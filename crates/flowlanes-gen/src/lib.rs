//! Generated NetFlow v5, NetFlow v9 and IPFIX export packets for tests and
//! load: valid traffic, template edge cases and malformed packets.
//!
//! Everything is built from a seed; no packet comes from a real network.
//! Addresses are from the documentation ranges (192.0.2.0/24,
//! 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and RFC 1918 space.
//! Enterprise-specific elements use PEN 32473, the IANA example enterprise
//! number for documentation (RFC 5612).
#![forbid(unsafe_code)]

use flowlanes_wire::{FieldSpec, VARLEN, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// PEN reserved for documentation (RFC 5612).
pub const EXAMPLE_PEN: u32 = 32473;
/// An IANA element ID in the unassigned range (534-32767 on 2026-11-22).
pub const UNASSIGNED_IE: u16 = 30000;

/// Deterministic xorshift64* generator.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

/// A flow as the generator means it; packets encode these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub tos: u8,
    pub packets: u64,
    pub bytes: u64,
    pub in_if: u32,
    pub out_if: u32,
    /// UNIX milliseconds.
    pub start_ms: u64,
    pub end_ms: u64,
}

pub fn random_flow(r: &mut Rng, v6: bool, base_ms: u64) -> Flow {
    let (src, dst) = if v6 {
        (
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0,
                r.below(16) as u16,
                0,
                0,
                0,
                1 + r.below(200) as u16,
            )),
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                1,
                0,
                0,
                0,
                0,
                1 + r.below(200) as u16,
            )),
        )
    } else {
        let src = match r.below(3) {
            0 => Ipv4Addr::new(192, 168, r.below(4) as u8, 1 + r.below(250) as u8),
            1 => Ipv4Addr::new(10, 0, r.below(8) as u8, 1 + r.below(250) as u8),
            _ => Ipv4Addr::new(198, 51, 100, 1 + r.below(250) as u8),
        };
        let dst = match r.below(2) {
            0 => Ipv4Addr::new(203, 0, 113, 1 + r.below(250) as u8),
            _ => Ipv4Addr::new(192, 0, 2, 1 + r.below(250) as u8),
        };
        (IpAddr::V4(src), IpAddr::V4(dst))
    };
    let protocol = [6u8, 17, 1][r.below(3) as usize];
    let packets = 1 + r.below(5000);
    let start_ms = base_ms + r.below(60_000);
    Flow {
        src,
        dst,
        src_port: if protocol == 1 {
            0
        } else {
            1024 + r.below(60000) as u16
        },
        dst_port: if protocol == 1 {
            0
        } else {
            [22u16, 53, 80, 123, 443, 3389, 8080][r.below(7) as usize]
        },
        protocol,
        tcp_flags: if protocol == 6 { r.below(64) as u8 } else { 0 },
        tos: [0u8, 0, 0x10, 0xb8][r.below(4) as usize],
        packets,
        bytes: packets * (40 + r.below(1400)),
        in_if: 1 + r.below(8) as u32,
        out_if: 1 + r.below(8) as u32,
        start_ms,
        end_ms: start_ms + r.below(120_000),
    }
}

// ---------------------------------------------------------------- encoding

fn push16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}
fn push32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}

/// Encode one value in `length` bytes (`VARLEN` for the IPFIX variable
/// length encoding). Unsigned values use reduced-size encoding when
/// `length` is shorter than 8 (RFC 7011 §6.2).
pub fn encode_value(out: &mut Vec<u8>, v: &Value, length: u16) {
    let raw: Vec<u8> = match v {
        Value::Unsigned(n) => {
            let len = usize::from(length);
            n.to_be_bytes()[8 - len.min(8)..].to_vec()
        }
        Value::Ipv4(a) => a.octets().to_vec(),
        Value::Ipv6(a) => a.octets().to_vec(),
        Value::Mac(m) => m.to_vec(),
        Value::Str(s) => s.as_bytes().to_vec(),
        Value::Bytes(b) => b.clone(),
    };
    if length == VARLEN {
        if raw.len() < 255 {
            out.push(raw.len() as u8);
        } else {
            out.push(255);
            push16(out, raw.len() as u16);
        }
    }
    out.extend_from_slice(&raw);
}

/// Pad to a multiple of 4 with zeros.
fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// A set or FlowSet: id, length, body, zero padding to 4 bytes.
pub fn set(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 8);
    push16(&mut v, id);
    push16(&mut v, 0);
    v.extend_from_slice(body);
    pad4(&mut v);
    let len = v.len() as u16;
    v[2..4].copy_from_slice(&len.to_be_bytes());
    v
}

/// IPFIX template record (for set ID 2).
pub fn ipfix_template(id: u16, fields: &[FieldSpec]) -> Vec<u8> {
    let mut v = Vec::new();
    push16(&mut v, id);
    push16(&mut v, fields.len() as u16);
    for f in fields {
        match f.enterprise {
            Some(pen) => {
                push16(&mut v, f.id | 0x8000);
                push16(&mut v, f.length);
                push32(&mut v, pen);
            }
            None => {
                push16(&mut v, f.id);
                push16(&mut v, f.length);
            }
        }
    }
    v
}

/// IPFIX options template record (for set ID 3).
pub fn ipfix_options_template(id: u16, scope_count: u16, fields: &[FieldSpec]) -> Vec<u8> {
    let mut v = Vec::new();
    push16(&mut v, id);
    push16(&mut v, fields.len() as u16);
    push16(&mut v, scope_count);
    for f in fields {
        push16(&mut v, f.id);
        push16(&mut v, f.length);
    }
    v
}

/// A data record: the values in template order.
pub fn record(fields: &[FieldSpec], values: &[Value]) -> Vec<u8> {
    let mut v = Vec::new();
    for (f, val) in fields.iter().zip(values) {
        encode_value(&mut v, val, f.length);
    }
    v
}

/// An IPFIX message from its sets.
pub fn ipfix_message(domain: u32, sequence: u32, export_time: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let body: usize = sets.iter().map(Vec::len).sum();
    let mut v = Vec::with_capacity(16 + body);
    push16(&mut v, 10);
    push16(&mut v, (16 + body) as u16);
    push32(&mut v, export_time);
    push32(&mut v, sequence);
    push32(&mut v, domain);
    for s in sets {
        v.extend_from_slice(s);
    }
    v
}

/// NetFlow v9 template record (for FlowSet ID 0).
pub fn v9_template(id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut v = Vec::new();
    push16(&mut v, id);
    push16(&mut v, fields.len() as u16);
    for &(t, l) in fields {
        push16(&mut v, t);
        push16(&mut v, l);
    }
    v
}

/// NetFlow v9 options template (for FlowSet ID 1).
pub fn v9_options_template(id: u16, scope: &[(u16, u16)], options: &[(u16, u16)]) -> Vec<u8> {
    let mut v = Vec::new();
    push16(&mut v, id);
    push16(&mut v, (scope.len() * 4) as u16);
    push16(&mut v, (options.len() * 4) as u16);
    for &(t, l) in scope.iter().chain(options) {
        push16(&mut v, t);
        push16(&mut v, l);
    }
    v
}

/// A NetFlow v9 packet. `count` is the header record count.
pub fn v9_packet(
    source_id: u32,
    sequence: u32,
    uptime_ms: u32,
    secs: u32,
    count: u16,
    flowsets: &[Vec<u8>],
) -> Vec<u8> {
    let mut v = Vec::new();
    push16(&mut v, 9);
    push16(&mut v, count);
    push32(&mut v, uptime_ms);
    push32(&mut v, secs);
    push32(&mut v, sequence);
    push32(&mut v, source_id);
    for s in flowsets {
        v.extend_from_slice(s);
    }
    v
}

/// A NetFlow v5 packet for up to 30 IPv4 flows. Times are carried as
/// SysUptime milliseconds relative to `boot_ms`.
pub fn v5_packet(
    flows: &[Flow],
    sequence: u32,
    boot_ms: u64,
    now_ms: u64,
    engine: (u8, u8),
) -> Vec<u8> {
    assert!(
        !flows.is_empty() && flows.len() <= 30,
        "v5 carries 1-30 flows"
    );
    let mut v = Vec::with_capacity(24 + 48 * flows.len());
    push16(&mut v, 5);
    push16(&mut v, flows.len() as u16);
    push32(&mut v, (now_ms - boot_ms) as u32);
    push32(&mut v, (now_ms / 1000) as u32);
    push32(&mut v, ((now_ms % 1000) * 1_000_000) as u32);
    push32(&mut v, sequence);
    v.push(engine.0);
    v.push(engine.1);
    push16(&mut v, 0);
    for f in flows {
        let (IpAddr::V4(s), IpAddr::V4(d)) = (f.src, f.dst) else {
            panic!("v5 is IPv4 only");
        };
        v.extend_from_slice(&s.octets());
        v.extend_from_slice(&d.octets());
        v.extend_from_slice(&[0, 0, 0, 0]);
        push16(&mut v, f.in_if as u16);
        push16(&mut v, f.out_if as u16);
        push32(&mut v, f.packets as u32);
        push32(&mut v, f.bytes as u32);
        push32(&mut v, (f.start_ms - boot_ms) as u32);
        push32(&mut v, (f.end_ms - boot_ms) as u32);
        push16(&mut v, f.src_port);
        push16(&mut v, f.dst_port);
        v.push(0);
        v.push(f.tcp_flags);
        v.push(f.protocol);
        v.push(f.tos);
        push16(&mut v, 0);
        push16(&mut v, 0);
        v.push(24);
        v.push(24);
        push16(&mut v, 0);
    }
    v
}

// ---------------------------------------------------------------- templates

fn spec(id: u16, length: u16) -> FieldSpec {
    FieldSpec {
        id,
        enterprise: None,
        length,
    }
}

/// IPFIX template 256: IPv4 flow with the common UniFi-style fields.
pub fn ipfix_v4_fields() -> Vec<FieldSpec> {
    vec![
        spec(8, 4),
        spec(12, 4),
        spec(7, 2),
        spec(11, 2),
        spec(4, 1),
        spec(6, 2),
        spec(5, 1),
        spec(1, 8),
        spec(2, 8),
        spec(10, 4),
        spec(14, 4),
        spec(152, 8),
        spec(153, 8),
    ]
}

/// IPFIX template 257: the IPv6 version.
pub fn ipfix_v6_fields() -> Vec<FieldSpec> {
    let mut f = ipfix_v4_fields();
    f[0] = spec(27, 16);
    f[1] = spec(28, 16);
    f
}

/// IPFIX template 258: IPv4 with reduced-size counters, an
/// enterprise-specific element, an unassigned IANA element, a
/// variable-length string and NAT elements.
pub fn ipfix_extended_fields() -> Vec<FieldSpec> {
    let mut f = ipfix_v4_fields();
    f[7] = spec(1, 4);
    f[8] = spec(2, 4);
    f.push(FieldSpec {
        id: 1,
        enterprise: Some(EXAMPLE_PEN),
        length: 4,
    });
    f.push(spec(UNASSIGNED_IE, 2));
    f.push(spec(96, VARLEN));
    f.push(spec(225, 4));
    f.push(spec(227, 2));
    f
}

/// Options template 300: scope observationDomainId; options
/// samplingInterval and samplingAlgorithm.
pub fn ipfix_options_fields() -> Vec<FieldSpec> {
    vec![spec(149, 4), spec(34, 4), spec(35, 1)]
}

/// Values for a flow in the order of `fields` (only elements the
/// generator knows).
pub fn values(fields: &[FieldSpec], f: &Flow, extra: &str) -> Vec<Value> {
    fields
        .iter()
        .map(|s| match (s.enterprise, s.id) {
            (Some(_), _) => Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            (None, 8) | (None, 27) => ip_value(f.src),
            (None, 12) | (None, 28) => ip_value(f.dst),
            (None, 7) => Value::Unsigned(f.src_port.into()),
            (None, 11) => Value::Unsigned(f.dst_port.into()),
            (None, 4) => Value::Unsigned(f.protocol.into()),
            (None, 6) => Value::Unsigned(f.tcp_flags.into()),
            (None, 5) => Value::Unsigned(f.tos.into()),
            (None, 1) => Value::Unsigned(trim(f.bytes, s.length)),
            (None, 2) => Value::Unsigned(trim(f.packets, s.length)),
            (None, 10) => Value::Unsigned(f.in_if.into()),
            (None, 14) => Value::Unsigned(f.out_if.into()),
            (None, 152) => Value::Unsigned(f.start_ms),
            (None, 153) => Value::Unsigned(f.end_ms),
            (None, 21) => Value::Unsigned(f.end_ms & 0xffff_ffff),
            (None, 22) => Value::Unsigned(f.start_ms & 0xffff_ffff),
            (None, UNASSIGNED_IE) => Value::Bytes(vec![0x12, 0x34]),
            (None, 96) => Value::Str(extra.to_string()),
            (None, 225) => Value::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
            (None, 227) => Value::Unsigned(40000),
            (None, 149) => Value::Unsigned(1),
            (None, 34) => Value::Unsigned(1),
            (None, 35) => Value::Unsigned(0),
            _ => Value::Unsigned(0),
        })
        .collect()
}

fn trim(n: u64, len: u16) -> u64 {
    if len >= 8 {
        n
    } else {
        n & ((1u64 << (8 * u32::from(len))) - 1)
    }
}

fn ip_value(a: IpAddr) -> Value {
    match a {
        IpAddr::V4(a) => Value::Ipv4(a),
        IpAddr::V6(a) => Value::Ipv6(a),
    }
}

/// NetFlow v9 template 256 (IPv4).
pub fn v9_fields() -> Vec<(u16, u16)> {
    vec![
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (6, 1),
        (5, 1),
        (1, 4),
        (2, 4),
        (10, 2),
        (14, 2),
        (22, 4),
        (21, 4),
    ]
}

pub fn v9_specs() -> Vec<FieldSpec> {
    v9_fields().into_iter().map(|(t, l)| spec(t, l)).collect()
}

// ---------------------------------------------------------------- packets

/// One generated packet, with what it is for.
#[derive(Debug, Clone)]
pub struct Packet {
    pub exporter: IpAddr,
    pub label: String,
    pub bytes: Vec<u8>,
}

/// Exporters used by the generator (documentation addresses).
pub fn exporter(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

/// Base time for generated packets: 2026-11-22T00:00:00Z.
pub const BASE_SECS: u32 = 1_795_305_600;

/// Valid traffic of one protocol version: `packets` packets of up to
/// `per_packet` flows each. Returns the packets and the flows in order.
pub fn traffic(
    version: u16,
    seed: u64,
    packets: usize,
    per_packet: usize,
) -> (Vec<Packet>, Vec<Flow>) {
    let mut r = Rng::new(seed);
    let mut out = Vec::new();
    let mut flows = Vec::new();
    let exp = exporter(10);
    let mut seq: u32 = 0;
    for p in 0..packets {
        let n = 1 + r.below(per_packet as u64) as usize;
        let secs = BASE_SECS + p as u32;
        let base_ms = u64::from(secs) * 1000 - 120_000;
        let batch: Vec<Flow> = (0..n)
            .map(|_| {
                let v6 = version == 10 && r.below(4) == 0;
                random_flow(&mut r, v6, base_ms)
            })
            .collect();
        let bytes = match version {
            5 => {
                let pkt = v5_packet(
                    &batch,
                    seq,
                    base_ms - 3_600_000,
                    u64::from(secs) * 1000,
                    (0, 1),
                );
                seq = seq.wrapping_add(n as u32);
                pkt
            }
            9 => {
                let fields = v9_fields();
                let specs = v9_specs();
                let mut data = Vec::new();
                for f in &batch {
                    data.extend(record(&specs, &values(&specs, f, "")));
                }
                // Template in every packet (a refresh), as exporters do.
                let pkt = v9_packet(
                    1,
                    seq,
                    3_600_000,
                    secs,
                    (1 + n) as u16,
                    &[set(0, &v9_template(256, &fields)), set(256, &data)],
                );
                seq = seq.wrapping_add(1);
                pkt
            }
            _ => {
                let mut sets = Vec::new();
                if p % 4 == 0 {
                    let mut t = ipfix_template(256, &ipfix_v4_fields());
                    t.extend(ipfix_template(257, &ipfix_v6_fields()));
                    t.extend(ipfix_template(258, &ipfix_extended_fields()));
                    sets.push(set(2, &t));
                    sets.push(set(
                        3,
                        &ipfix_options_template(300, 1, &ipfix_options_fields()),
                    ));
                    let o = ipfix_options_fields();
                    sets.push(set(300, &record(&o, &values(&o, &batch[0], ""))));
                }
                for f in &batch {
                    let (id, fields) = if f.src.is_ipv6() {
                        (257, ipfix_v6_fields())
                    } else if r.below(3) == 0 {
                        (258, ipfix_extended_fields())
                    } else {
                        (256, ipfix_v4_fields())
                    };
                    let name = ["dns", "https", "ssh", "a-much-longer-application-name"]
                        [r.below(4) as usize];
                    sets.push(set(id, &record(&fields, &values(&fields, f, name))));
                }
                let options = usize::from(p % 4 == 0);
                let pkt = ipfix_message(1, seq, secs, &sets);
                seq = seq.wrapping_add((n + options) as u32);
                pkt
            }
        };
        out.push(Packet {
            exporter: exp,
            label: format!("v{version}-traffic-{p}"),
            bytes,
        });
        flows.extend(batch);
    }
    (out, flows)
}

/// Malformed packets, one per kind. Each must be counted, never decoded
/// into a wrong record.
pub fn malformed(seed: u64) -> Vec<Packet> {
    let mut r = Rng::new(seed);
    let f = random_flow(&mut r, false, u64::from(BASE_SECS) * 1000);
    let fields = ipfix_v4_fields();
    let good_template = set(2, &ipfix_template(256, &fields));
    let good_data = set(256, &record(&fields, &values(&fields, &f, "")));
    let exp = exporter(66);
    let mut v = Vec::new();
    let mut add = |label: &str, bytes: Vec<u8>| {
        v.push(Packet {
            exporter: exp,
            label: label.to_string(),
            bytes,
        })
    };
    add("one-byte", vec![0]);
    add("unknown-version", {
        let mut p = ipfix_message(9, 0, BASE_SECS, std::slice::from_ref(&good_template));
        p[1] = 7;
        p
    });
    add(
        "ipfix-short-header",
        ipfix_message(9, 0, BASE_SECS, &[])[..12].to_vec(),
    );
    add("ipfix-length-mismatch", {
        let mut p = ipfix_message(9, 0, BASE_SECS, std::slice::from_ref(&good_template));
        let l = (p.len() + 8) as u16;
        p[2..4].copy_from_slice(&l.to_be_bytes());
        p
    });
    add("ipfix-set-overrun", {
        let mut s = good_template.clone();
        s[2..4].copy_from_slice(&200u16.to_be_bytes());
        ipfix_message(9, 0, BASE_SECS, &[s])
    });
    add("ipfix-set-length-below-header", {
        let mut s = good_template.clone();
        s[2..4].copy_from_slice(&2u16.to_be_bytes());
        ipfix_message(9, 0, BASE_SECS, &[s])
    });
    add("ipfix-template-truncated", {
        let mut t = ipfix_template(256, &fields);
        t[2..4].copy_from_slice(&40u16.to_be_bytes());
        ipfix_message(9, 0, BASE_SECS, &[set(2, &t)])
    });
    add(
        "ipfix-options-scope-zero",
        ipfix_message(
            9,
            0,
            BASE_SECS,
            &[set(
                3,
                &ipfix_options_template(300, 0, &ipfix_options_fields()),
            )],
        ),
    );
    add(
        "ipfix-template-id-below-256",
        ipfix_message(9, 0, BASE_SECS, &[set(2, &ipfix_template(200, &fields))]),
    );
    add("ipfix-template-zero-length-field", {
        let mut bad = fields.clone();
        bad[2].length = 0;
        ipfix_message(9, 0, BASE_SECS, &[set(2, &ipfix_template(259, &bad))])
    });
    add("ipfix-data-varlen-overrun", {
        let vf = vec![spec(8, 4), spec(96, VARLEN)];
        let mut data = Ipv4Addr::new(192, 0, 2, 1).octets().to_vec();
        data.push(200);
        data.extend_from_slice(b"short");
        ipfix_message(
            9,
            0,
            BASE_SECS,
            &[set(2, &ipfix_template(260, &vf)), set(260, &data)],
        )
    });
    add("ipfix-data-nonzero-trailer", {
        let mut d = record(&fields, &values(&fields, &f, ""));
        d.extend_from_slice(&[1, 2, 3]);
        let mut s = set(256, &d);
        // set() padded with zeros; make the trailer non-zero.
        let n = s.len();
        s[n - 1] = 9;
        ipfix_message(9, 0, BASE_SECS, &[good_template.clone(), s])
    });
    add("v5-count-mismatch", {
        let mut p = v5_packet(
            &[f.clone(), f.clone()],
            0,
            0,
            u64::from(BASE_SECS) * 1000,
            (0, 0),
        );
        p[3] = 3;
        p
    });
    add(
        "v5-short-header",
        v5_packet(
            std::slice::from_ref(&f),
            0,
            0,
            u64::from(BASE_SECS) * 1000,
            (0, 0),
        )[..20]
            .to_vec(),
    );
    add(
        "v9-short-header",
        v9_packet(9, 0, 0, BASE_SECS, 0, &[])[..16].to_vec(),
    );
    add("v9-flowset-overrun", {
        let mut s = set(0, &v9_template(256, &v9_fields()));
        s[2..4].copy_from_slice(&300u16.to_be_bytes());
        v9_packet(9, 0, 0, BASE_SECS, 1, &[s])
    });
    add("v9-template-truncated", {
        let mut t = v9_template(256, &v9_fields());
        t[2..4].copy_from_slice(&50u16.to_be_bytes());
        v9_packet(9, 0, 0, BASE_SECS, 1, &[set(0, &t)])
    });
    add(
        "good-after-malformed",
        ipfix_message(9, 1, BASE_SECS, &[good_template, good_data]),
    );
    v
}

/// Every generated kind together: v5, v9 and IPFIX traffic plus the
/// malformed packets.
pub fn mix(seed: u64) -> Vec<Packet> {
    let mut v = traffic(5, seed, 5, 30).0;
    v.extend(traffic(9, seed + 1, 5, 20).0);
    v.extend(traffic(10, seed + 2, 8, 20).0);
    v.extend(malformed(seed + 3));
    v
}

// ---------------------------------------------------------------- file format

/// Magic at the start of a flowlanes packet file.
pub const FILE_MAGIC: &[u8; 8] = b"FLPKT1\n\0";

/// Write packets as a flowlanes packet file: the magic, then per packet a
/// one-byte address family (4 or 6), the exporter address, a big-endian
/// u32 length and the packet bytes.
pub fn write_packets(packets: &[Packet]) -> Vec<u8> {
    let mut v = FILE_MAGIC.to_vec();
    for p in packets {
        match p.exporter {
            IpAddr::V4(a) => {
                v.push(4);
                v.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                v.push(6);
                v.extend_from_slice(&a.octets());
            }
        }
        v.extend_from_slice(&(p.bytes.len() as u32).to_be_bytes());
        v.extend_from_slice(&p.bytes);
    }
    v
}

/// Read a flowlanes packet file.
pub fn read_packets(data: &[u8]) -> Result<Vec<(IpAddr, Vec<u8>)>, String> {
    let rest = data
        .strip_prefix(FILE_MAGIC.as_slice())
        .ok_or("not a flowlanes packet file (bad magic)")?;
    let mut out = Vec::new();
    let mut at = 0;
    while at < rest.len() {
        let fam = rest[at];
        let alen = match fam {
            4 => 4,
            6 => 16,
            _ => return Err(format!("bad address family {fam} at offset {at}")),
        };
        if rest.len() < at + 1 + alen + 4 {
            return Err("truncated packet entry".into());
        }
        let a = &rest[at + 1..at + 1 + alen];
        let addr = if fam == 4 {
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        } else {
            let mut b = [0u8; 16];
            b.copy_from_slice(a);
            IpAddr::V6(Ipv6Addr::from(b))
        };
        let lp = at + 1 + alen;
        let len = u32::from_be_bytes([rest[lp], rest[lp + 1], rest[lp + 2], rest[lp + 3]]) as usize;
        let start = lp + 4;
        if rest.len() < start + len {
            return Err("truncated packet".into());
        }
        out.push((addr, rest[start..start + len].to_vec()));
        at = start + len;
    }
    Ok(out)
}
