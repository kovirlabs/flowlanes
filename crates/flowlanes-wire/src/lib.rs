//! Packet and record decoding for NetFlow v5, NetFlow v9 (RFC 3954) and
//! IPFIX (RFC 7011), with a template store and loss counters. No I/O.
//!
//! [`Collector::decode`] takes one export packet and the address it came
//! from and returns the records it could decode. Nothing is dropped
//! silently: every packet, set and record that is not turned into a
//! [`Record`] is counted in [`Counters`] by reason (R3).
#![forbid(unsafe_code)]

pub mod ie;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use ie::IeType;

/// Field length that marks a variable-length element in an IPFIX template.
pub const VARLEN: u16 = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    V5,
    V9,
    Ipfix,
}

impl Version {
    pub fn number(self) -> u16 {
        match self {
            Version::V5 => 5,
            Version::V9 => 9,
            Version::Ipfix => 10,
        }
    }
}

/// One field of a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldSpec {
    pub id: u16,
    /// Private enterprise number, for enterprise-specific IPFIX elements.
    pub enterprise: Option<u32>,
    /// Length in bytes, or [`VARLEN`].
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: u16,
    pub fields: Vec<FieldSpec>,
    /// Number of leading scope fields (options templates); 0 otherwise.
    pub scope_fields: usize,
    pub options: bool,
}

impl Template {
    /// Smallest possible encoded record (variable-length fields count 1).
    pub fn min_record_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| {
                if f.length == VARLEN {
                    1
                } else {
                    usize::from(f.length)
                }
            })
            .sum()
    }
}

/// Templates are kept per exporter, version, observation domain (IPFIX)
/// or source ID (v9), and template ID (R2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TemplateKey {
    pub exporter: IpAddr,
    pub version: Version,
    pub domain: u32,
    pub template_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    Str(String),
    /// Raw bytes: unknown and enterprise elements, octet arrays, and known
    /// elements whose length does not fit their type.
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub id: u16,
    pub enterprise: Option<u32>,
    /// IANA name when flowlanes knows the element.
    pub name: Option<&'static str>,
    /// True for the scope fields of an options record.
    pub scope: bool,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub exporter: IpAddr,
    pub version: Version,
    /// IPFIX observation domain, v9 source ID, v5 engine type and ID
    /// (`engine_type << 8 | engine_id`).
    pub domain: u32,
    /// `None` for v5.
    pub template_id: Option<u16>,
    /// True for options data records.
    pub options: bool,
    /// Export time in UNIX seconds from the packet header.
    pub export_time: u32,
    pub sequence: u32,
    pub fields: Vec<Field>,
}

impl Record {
    pub fn get(&self, id: u16) -> Option<&Value> {
        self.fields
            .iter()
            .find(|f| f.id == id && f.enterprise.is_none())
            .map(|f| &f.value)
    }
}

/// Why a packet was refused as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketError {
    TooShort,
    UnknownVersion,
    LengthMismatch,
    V5CountMismatch,
}

/// Loss and activity counters (R3). Data sets in equal decoded plus
/// rejected plus malformed plus still held; v5 records in equal v5 records
/// out (a v5 packet is all or nothing).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub packets: u64,
    pub packets_by_version: [u64; 3],
    pub packets_malformed: u64,
    pub packet_errors: HashMap<PacketError, u64>,
    /// Sets (any kind) whose header or length was invalid; parsing of the
    /// rest of that packet stops.
    pub sets_malformed: u64,
    pub sets_reserved_id: u64,
    pub templates_added: u64,
    pub templates_replaced: u64,
    pub templates_malformed: u64,
    /// Templates discarded because they were not refreshed within
    /// [`Config::template_timeout_secs`].
    pub templates_expired: u64,
    pub withdrawals_applied: u64,
    pub withdrawals_ignored: u64,
    pub data_sets: u64,
    pub data_sets_decoded: u64,
    pub data_sets_held: u64,
    pub data_sets_released: u64,
    pub data_sets_rejected_no_template: u64,
    /// Data sets that ended in a record that could not be decoded.
    pub data_sets_malformed: u64,
    pub records_out: u64,
    pub options_records_out: u64,
    /// Records within a decoded set that overran the set (counted once per
    /// set; the records before it are kept).
    pub records_malformed: u64,
    /// Sum over exporters of records (IPFIX, v5) or packets (v9) missing
    /// according to the header sequence numbers.
    pub sequence_missing: u64,
    pub sequence_out_of_order: u64,
}

impl Counters {
    /// Data sets currently held waiting for a template, by arithmetic.
    pub fn held_now(&self) -> u64 {
        self.data_sets_held - self.data_sets_released - self.held_rejected()
    }

    fn held_rejected(&self) -> u64 {
        self.data_sets_rejected_no_template
    }

    /// The R3 identity for data sets.
    pub fn sets_balance(&self) -> bool {
        self.data_sets
            == self.data_sets_decoded
                + self.data_sets_rejected_no_template
                + self.data_sets_malformed
                + self.held_now()
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Most data sets held per exporter while their template is missing;
    /// beyond it the oldest is rejected and counted.
    pub hold_max_sets: usize,
    /// Seconds a held data set waits for its template.
    pub hold_max_age_secs: u64,
    /// Apply IPFIX template withdrawals. RFC 7011 §8.4 says UDP collectors
    /// MUST ignore them, so the default is `false` (they are counted).
    pub honor_withdrawals: bool,
    /// Seconds a template lives without being re-sent; 0 keeps templates
    /// for ever. RFC 3954 §9 has unrefreshed templates expire, and RFC 7011
    /// §8.4 lets a UDP collector give each template a lifetime, which
    /// "SHOULD default to at least 3 times the observed retransmission
    /// rate". Neither gives a number; the default here is a placeholder.
    pub template_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hold_max_sets: 256,
            hold_max_age_secs: 60,
            honor_withdrawals: false,
            template_timeout_secs: 1800,
        }
    }
}

struct Held {
    key: TemplateKey,
    set: Vec<u8>,
    export_time: u32,
    sequence: u32,
    received: u64,
}

/// Decoder state: templates, held data sets, sequence tracking, counters.
pub struct Collector {
    pub config: Config,
    pub counters: Counters,
    templates: HashMap<TemplateKey, Template>,
    /// When each template was last received (`now` of that packet).
    refreshed: HashMap<TemplateKey, u64>,
    /// `now` of the packet being decoded.
    now: u64,
    held: VecDeque<Held>,
    /// Next expected sequence number per (exporter, version, domain).
    next_seq: HashMap<(IpAddr, Version, u32), u32>,
    /// Records decoded from held data when its template arrived.
    released: Vec<Record>,
}

impl Default for Collector {
    fn default() -> Self {
        Collector::new(Config::default())
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Decode one field value by its element type.
pub fn decode_value(id: u16, enterprise: Option<u32>, raw: &[u8]) -> (Option<&'static str>, Value) {
    if enterprise.is_some() {
        return (None, Value::Bytes(raw.to_vec()));
    }
    let Some((name, ty)) = ie::lookup(id) else {
        return (None, Value::Bytes(raw.to_vec()));
    };
    let v = match ty {
        IeType::Unsigned | IeType::DateTimeSeconds | IeType::DateTimeMillis
            if (1..=8).contains(&raw.len()) =>
        {
            // Reduced-size encoding (RFC 7011 §6.2): big-endian, any length.
            Value::Unsigned(raw.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)))
        }
        IeType::Ipv4 if raw.len() == 4 => {
            Value::Ipv4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
        }
        IeType::Ipv6 if raw.len() == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(raw);
            Value::Ipv6(Ipv6Addr::from(a))
        }
        IeType::Mac if raw.len() == 6 => {
            let mut a = [0u8; 6];
            a.copy_from_slice(raw);
            Value::Mac(a)
        }
        IeType::Str => match std::str::from_utf8(raw) {
            Ok(s) => Value::Str(s.to_string()),
            Err(_) => Value::Bytes(raw.to_vec()),
        },
        _ => Value::Bytes(raw.to_vec()),
    };
    (Some(name), v)
}

impl Collector {
    pub fn new(config: Config) -> Collector {
        Collector {
            config,
            counters: Counters::default(),
            templates: HashMap::new(),
            refreshed: HashMap::new(),
            now: 0,
            held: VecDeque::new(),
            next_seq: HashMap::new(),
            released: Vec::new(),
        }
    }

    pub fn template(&self, key: &TemplateKey) -> Option<&Template> {
        self.templates.get(key)
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Decode one export packet received from `exporter` at `now` (seconds,
    /// any monotonic clock; used only to age held data).
    pub fn decode(&mut self, exporter: IpAddr, packet: &[u8], now: u64) -> Vec<Record> {
        self.counters.packets += 1;
        self.now = now;
        self.expire_held(now);
        let mut out = Vec::new();
        if packet.len() < 2 {
            self.packet_error(PacketError::TooShort);
            return out;
        }
        match be16(packet, 0) {
            5 => {
                self.counters.packets_by_version[0] += 1;
                self.decode_v5(exporter, packet, &mut out);
            }
            9 => {
                self.counters.packets_by_version[1] += 1;
                self.decode_v9(exporter, packet, now, &mut out);
            }
            10 => {
                self.counters.packets_by_version[2] += 1;
                self.decode_ipfix(exporter, packet, now, &mut out);
            }
            _ => self.packet_error(PacketError::UnknownVersion),
        }
        // Records from earlier data sets whose template arrived in this
        // packet come after this packet's own records.
        out.append(&mut self.released);
        out
    }

    /// Reject everything still held (end of input).
    pub fn finish(&mut self) {
        let n = self.held.len() as u64;
        self.held.clear();
        self.counters.data_sets_rejected_no_template += n;
    }

    fn packet_error(&mut self, e: PacketError) {
        self.counters.packets_malformed += 1;
        *self.counters.packet_errors.entry(e).or_insert(0) += 1;
    }

    fn expire_held(&mut self, now: u64) {
        let max_age = self.config.hold_max_age_secs;
        let before = self.held.len();
        self.held
            .retain(|h| now.saturating_sub(h.received) <= max_age);
        self.counters.data_sets_rejected_no_template += (before - self.held.len()) as u64;
    }

    fn check_sequence(&mut self, key: (IpAddr, Version, u32), seq: u32, advance: Option<u32>) {
        if let Some(&expected) = self.next_seq.get(&key) {
            let gap = seq.wrapping_sub(expected);
            if gap != 0 {
                if gap < 0x8000_0000 {
                    self.counters.sequence_missing += u64::from(gap);
                } else {
                    self.counters.sequence_out_of_order += 1;
                }
            }
        }
        match advance {
            Some(n) => {
                self.next_seq.insert(key, seq.wrapping_add(n));
            }
            // The number of records cannot be known (a data set without
            // its template): stop tracking until the next packet.
            None => {
                self.next_seq.remove(&key);
            }
        }
    }

    // ------------------------------------------------------------- v5

    fn decode_v5(&mut self, exporter: IpAddr, p: &[u8], out: &mut Vec<Record>) {
        if p.len() < 24 {
            self.packet_error(PacketError::TooShort);
            return;
        }
        let count = usize::from(be16(p, 2));
        if count == 0 || count > 30 || p.len() != 24 + 48 * count {
            self.packet_error(PacketError::V5CountMismatch);
            return;
        }
        let export_time = be32(p, 8);
        let seq = be32(p, 16);
        let domain = u32::from(be16(p, 20));
        self.check_sequence((exporter, Version::V5, domain), seq, Some(count as u32));
        for i in 0..count {
            let r = &p[24 + 48 * i..24 + 48 * (i + 1)];
            // (IE id, offset, length) per the Cisco v5 record format.
            const LAYOUT: &[(u16, usize, usize)] = &[
                (8, 0, 4),
                (12, 4, 4),
                (15, 8, 4),
                (10, 12, 2),
                (14, 14, 2),
                (2, 16, 4),
                (1, 20, 4),
                (22, 24, 4),
                (21, 28, 4),
                (7, 32, 2),
                (11, 34, 2),
                (6, 37, 1),
                (4, 38, 1),
                (5, 39, 1),
                (16, 40, 2),
                (17, 42, 2),
                (9, 44, 1),
                (13, 45, 1),
            ];
            let fields = LAYOUT
                .iter()
                .map(|&(id, off, len)| {
                    let (name, value) = decode_value(id, None, &r[off..off + len]);
                    Field {
                        id,
                        enterprise: None,
                        name,
                        scope: false,
                        value,
                    }
                })
                .collect();
            out.push(Record {
                exporter,
                version: Version::V5,
                domain,
                template_id: None,
                options: false,
                export_time,
                sequence: seq,
                fields,
            });
            self.counters.records_out += 1;
        }
    }

    // ------------------------------------------------------------- v9

    fn decode_v9(&mut self, exporter: IpAddr, p: &[u8], now: u64, out: &mut Vec<Record>) {
        if p.len() < 20 {
            self.packet_error(PacketError::TooShort);
            return;
        }
        let export_time = be32(p, 8);
        let seq = be32(p, 12);
        let domain = be32(p, 16);
        let mut at = 20;
        while at < p.len() {
            if p.len() - at < 4 {
                // Trailing bytes too short for a FlowSet header.
                self.counters.sets_malformed += 1;
                break;
            }
            let set_id = be16(p, at);
            let len = usize::from(be16(p, at + 2));
            if len < 4 || at + len > p.len() {
                self.counters.sets_malformed += 1;
                break;
            }
            let body = &p[at + 4..at + len];
            match set_id {
                0 => self.v9_templates(exporter, domain, body),
                1 => self.v9_options_templates(exporter, domain, body),
                2..=255 => self.counters.sets_reserved_id += 1,
                id => {
                    let key = TemplateKey {
                        exporter,
                        version: Version::V9,
                        domain,
                        template_id: id,
                    };
                    self.data_set(key, body, export_time, seq, now, out);
                }
            }
            at += len;
        }
        // v9 sequence numbers count packets.
        self.check_sequence((exporter, Version::V9, domain), seq, Some(1));
    }

    fn v9_templates(&mut self, exporter: IpAddr, domain: u32, body: &[u8]) {
        let mut at = 0;
        while body.len() - at >= 4 {
            let id = be16(body, at);
            let count = usize::from(be16(body, at + 2));
            if id == 0 && count == 0 {
                // Padding.
                break;
            }
            if id < 256 || count == 0 || at + 4 + 4 * count > body.len() {
                self.counters.templates_malformed += 1;
                return;
            }
            let fields = (0..count)
                .map(|i| FieldSpec {
                    id: be16(body, at + 4 + 4 * i),
                    enterprise: None,
                    length: be16(body, at + 6 + 4 * i),
                })
                .collect();
            at += 4 + 4 * count;
            self.add_template(
                TemplateKey {
                    exporter,
                    version: Version::V9,
                    domain,
                    template_id: id,
                },
                Template {
                    id,
                    fields,
                    scope_fields: 0,
                    options: false,
                },
            );
        }
    }

    fn v9_options_templates(&mut self, exporter: IpAddr, domain: u32, body: &[u8]) {
        let mut at = 0;
        while body.len() - at >= 6 {
            let id = be16(body, at);
            let scope_len = usize::from(be16(body, at + 2));
            let opt_len = usize::from(be16(body, at + 4));
            if id == 0 && scope_len == 0 && opt_len == 0 {
                break;
            }
            if id < 256
                || scope_len % 4 != 0
                || opt_len % 4 != 0
                || scope_len + opt_len == 0
                || at + 6 + scope_len + opt_len > body.len()
            {
                self.counters.templates_malformed += 1;
                return;
            }
            let n = (scope_len + opt_len) / 4;
            let fields = (0..n)
                .map(|i| FieldSpec {
                    id: be16(body, at + 6 + 4 * i),
                    enterprise: None,
                    length: be16(body, at + 8 + 4 * i),
                })
                .collect();
            at += 6 + scope_len + opt_len;
            self.add_template(
                TemplateKey {
                    exporter,
                    version: Version::V9,
                    domain,
                    template_id: id,
                },
                Template {
                    id,
                    fields,
                    scope_fields: scope_len / 4,
                    options: true,
                },
            );
            // Remaining bytes shorter than a header are padding.
            if body.len() - at < 6 {
                break;
            }
        }
    }

    // ------------------------------------------------------------- IPFIX

    fn decode_ipfix(&mut self, exporter: IpAddr, p: &[u8], now: u64, out: &mut Vec<Record>) {
        if p.len() < 16 {
            self.packet_error(PacketError::TooShort);
            return;
        }
        if usize::from(be16(p, 2)) != p.len() {
            self.packet_error(PacketError::LengthMismatch);
            return;
        }
        let export_time = be32(p, 4);
        let seq = be32(p, 8);
        let domain = be32(p, 12);
        let records_before = out.len();
        let mut countable = true;
        let mut at = 16;
        while at < p.len() {
            if p.len() - at < 4 {
                self.counters.sets_malformed += 1;
                countable = false;
                break;
            }
            let set_id = be16(p, at);
            let len = usize::from(be16(p, at + 2));
            if len < 4 || at + len > p.len() {
                self.counters.sets_malformed += 1;
                countable = false;
                break;
            }
            let body = &p[at + 4..at + len];
            match set_id {
                2 => self.ipfix_templates(exporter, domain, body, false),
                3 => self.ipfix_templates(exporter, domain, body, true),
                0..=255 => self.counters.sets_reserved_id += 1,
                id => {
                    let key = TemplateKey {
                        exporter,
                        version: Version::Ipfix,
                        domain,
                        template_id: id,
                    };
                    if !self.data_set(key, body, export_time, seq, now, out) {
                        countable = false;
                    }
                }
            }
            at += len;
        }
        // IPFIX sequence numbers count data records.
        let n = (out.len() - records_before) as u32;
        self.check_sequence(
            (exporter, Version::Ipfix, domain),
            seq,
            countable.then_some(n),
        );
    }

    fn ipfix_templates(&mut self, exporter: IpAddr, domain: u32, body: &[u8], options: bool) {
        let mut at = 0;
        let hdr = if options { 6 } else { 4 };
        while body.len() - at >= 4 {
            let id = be16(body, at);
            let count = usize::from(be16(body, at + 2));
            if count == 0 {
                // Withdrawal (RFC 7011 §8.1), or padding when the ID is 0.
                if id == 0 {
                    break;
                }
                at += 4;
                if !self.config.honor_withdrawals {
                    self.counters.withdrawals_ignored += 1;
                    continue;
                }
                self.counters.withdrawals_applied += 1;
                let all = (id == 2 && !options) || (id == 3 && options);
                self.templates.retain(|k, t| {
                    !(k.exporter == exporter
                        && k.version == Version::Ipfix
                        && k.domain == domain
                        && t.options == options
                        && (all || k.template_id == id))
                });
                let templates = &self.templates;
                self.refreshed.retain(|k, _| templates.contains_key(k));
                continue;
            }
            if body.len() - at < hdr {
                self.counters.templates_malformed += 1;
                return;
            }
            let scope = if options {
                usize::from(be16(body, at + 4))
            } else {
                0
            };
            if id < 256 || (options && (scope == 0 || scope > count)) {
                self.counters.templates_malformed += 1;
                return;
            }
            let mut pos = at + hdr;
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                if body.len() - pos < 4 {
                    self.counters.templates_malformed += 1;
                    return;
                }
                let raw_id = be16(body, pos);
                let length = be16(body, pos + 2);
                pos += 4;
                let enterprise = if raw_id & 0x8000 != 0 {
                    if body.len() - pos < 4 {
                        self.counters.templates_malformed += 1;
                        return;
                    }
                    let e = be32(body, pos);
                    pos += 4;
                    Some(e)
                } else {
                    None
                };
                fields.push(FieldSpec {
                    id: raw_id & 0x7fff,
                    enterprise,
                    length,
                });
            }
            at = pos;
            self.add_template(
                TemplateKey {
                    exporter,
                    version: Version::Ipfix,
                    domain,
                    template_id: id,
                },
                Template {
                    id,
                    fields,
                    scope_fields: scope,
                    options,
                },
            );
        }
    }

    // ------------------------------------------------------------- common

    fn add_template(&mut self, key: TemplateKey, t: Template) {
        if t.fields.iter().any(|f| f.length == 0) {
            self.counters.templates_malformed += 1;
            return;
        }
        self.refreshed.insert(key, self.now);
        match self.templates.insert(key, t) {
            Some(_) => self.counters.templates_replaced += 1,
            None => self.counters.templates_added += 1,
        }
        // Release data held for this template, in arrival order.
        let mut i = 0;
        let mut ready = Vec::new();
        while i < self.held.len() {
            if self.held[i].key == key {
                ready.push(self.held.remove(i).expect("index in range"));
            } else {
                i += 1;
            }
        }
        for h in ready {
            self.counters.data_sets_released += 1;
            let mut out = Vec::new();
            self.decode_data(h.key, &h.set, h.export_time, h.sequence, &mut out);
            self.released.extend(out);
        }
    }

    /// Returns false when the set could not be decoded now (held, or
    /// malformed), so the record count of the packet is unknown.
    fn data_set(
        &mut self,
        key: TemplateKey,
        body: &[u8],
        export_time: u32,
        seq: u32,
        now: u64,
        out: &mut Vec<Record>,
    ) -> bool {
        self.counters.data_sets += 1;
        let timeout = self.config.template_timeout_secs;
        if timeout != 0
            && let Some(&at) = self.refreshed.get(&key)
            && now.saturating_sub(at) > timeout
        {
            // Not refreshed in time: the template is gone, and this data
            // waits for the next copy like any data without a template.
            self.templates.remove(&key);
            self.refreshed.remove(&key);
            self.counters.templates_expired += 1;
        }
        if !self.templates.contains_key(&key) {
            let from_exporter = self
                .held
                .iter()
                .filter(|h| h.key.exporter == key.exporter)
                .count();
            if from_exporter >= self.config.hold_max_sets
                && let Some(pos) = self
                    .held
                    .iter()
                    .position(|h| h.key.exporter == key.exporter)
            {
                self.held.remove(pos);
                self.counters.data_sets_rejected_no_template += 1;
            }
            self.counters.data_sets_held += 1;
            self.held.push_back(Held {
                key,
                set: body.to_vec(),
                export_time,
                sequence: seq,
                received: now,
            });
            return false;
        }
        self.decode_data(key, body, export_time, seq, out)
    }

    fn decode_data(
        &mut self,
        key: TemplateKey,
        body: &[u8],
        export_time: u32,
        seq: u32,
        out: &mut Vec<Record>,
    ) -> bool {
        let t = self.templates.get(&key).expect("caller checked").clone();
        let min = t.min_record_len().max(1);
        let mut at = 0;
        let mut ok = true;
        'records: while body.len() - at >= min {
            let mut fields = Vec::with_capacity(t.fields.len());
            let mut pos = at;
            for (i, f) in t.fields.iter().enumerate() {
                let len = if f.length == VARLEN {
                    if pos >= body.len() {
                        ok = false;
                        break 'records;
                    }
                    let first = usize::from(body[pos]);
                    pos += 1;
                    if first == 255 {
                        if body.len() - pos < 2 {
                            ok = false;
                            break 'records;
                        }
                        let l = usize::from(be16(body, pos));
                        pos += 2;
                        l
                    } else {
                        first
                    }
                } else {
                    usize::from(f.length)
                };
                if body.len() - pos < len {
                    ok = false;
                    break 'records;
                }
                let (name, value) = decode_value(f.id, f.enterprise, &body[pos..pos + len]);
                pos += len;
                fields.push(Field {
                    id: f.id,
                    enterprise: f.enterprise,
                    name,
                    scope: i < t.scope_fields,
                    value,
                });
            }
            at = pos;
            if t.options {
                self.counters.options_records_out += 1;
            } else {
                self.counters.records_out += 1;
            }
            out.push(Record {
                exporter: key.exporter,
                version: key.version,
                domain: key.domain,
                template_id: Some(key.template_id),
                options: t.options,
                export_time,
                sequence: seq,
                fields,
            });
        }
        if ok && body[at..].iter().any(|&b| b != 0) && key.version == Version::Ipfix {
            // Non-zero bytes after the last whole record: RFC 7011 §3.3.1
            // requires zero padding.
            ok = false;
        }
        if ok {
            self.counters.data_sets_decoded += 1;
        } else {
            self.counters.data_sets_malformed += 1;
            self.counters.records_malformed += 1;
        }
        ok
    }
}
