//! Packets shaped like the IPFIX export of a UniFi gateway, as one was seen
//! sending on 2026-11-23 (`docs/unifi.md`): the same template IDs, element
//! IDs, lengths and order, with generated values only.
//!
//! The gateway's template set depends on its sampling setting:
//!
//! - **Sampling on** (`t256` to `t261`): options templates 256 (domain
//!   name and times), 257 (sampling configuration), 258 (interface table),
//!   259 (export counters), all scoped by observationDomainId, and 260
//!   (selector counters, scoped by selectorId); 261 is the one flow
//!   template and carries selectorId.
//! - **Sampling off** (`off_*`): 256 as before, 257 the interface table,
//!   258 TCP flows (with tcpOptions), 259 other TCP and UDP flows, 260 ICMP
//!   flows, 261 the export counters. No selector elements.

use crate::{
    BASE_SECS, Packet, Rng, exporter, ipfix_message, ipfix_options_template, ipfix_template,
    random_flow, record, set,
};
use flowlanes_wire::{FieldSpec, Value};
use std::net::IpAddr;

pub fn f(id: u16, length: u16) -> FieldSpec {
    FieldSpec {
        id,
        enterprise: None,
        length,
    }
}

/// Text in a fixed-length field, padded with NUL bytes as the gateway does.
pub fn padded(s: &str, len: usize) -> Value {
    let mut b = s.as_bytes().to_vec();
    b.resize(len, 0);
    Value::Bytes(b)
}

pub fn t256() -> Vec<FieldSpec> {
    vec![f(149, 4), f(160, 8), f(300, 29), f(152, 8), f(153, 8)]
}
pub fn t257() -> Vec<FieldSpec> {
    vec![f(149, 4), f(302, 1), f(390, 1), f(309, 1), f(310, 2)]
}
pub fn t258() -> Vec<FieldSpec> {
    vec![f(149, 4), f(10, 2), f(82, 16), f(83, 32)]
}
pub fn t259() -> Vec<FieldSpec> {
    vec![f(149, 4), f(41, 8), f(42, 8), f(40, 8), f(163, 8)]
}
/// Scope selectorId.
pub fn t260() -> Vec<FieldSpec> {
    vec![
        f(302, 1),
        f(395, 8),
        f(318, 8),
        f(319, 8),
        f(152, 8),
        f(153, 8),
    ]
}

/// The flow template: IPv4 only, counters and interfaces in reduced size.
pub fn t261() -> Vec<FieldSpec> {
    [
        (8, 4),
        (12, 4),
        (15, 4),
        (60, 1),
        (7, 2),
        (11, 2),
        (6, 1),
        (10, 2),
        (14, 2),
        (2, 4),
        (1, 4),
        (152, 8),
        (153, 8),
        (4, 1),
        (5, 1),
        (136, 1),
        (209, 4),
        (80, 6),
        (56, 6),
        (256, 2),
        (61, 1),
        (302, 1),
    ]
    .iter()
    .map(|&(id, len)| f(id, len))
    .collect()
}

pub fn unpadded_set(id: u16, fields: &[FieldSpec], rows: &[Vec<Value>]) -> Vec<u8> {
    let body: Vec<u8> = rows.iter().flat_map(|v| record(fields, v)).collect();
    // The gateway does not pad its sets to 4 bytes; neither does this.
    let mut s = id.to_be_bytes().to_vec();
    s.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    s.extend_from_slice(&body);
    s
}

fn flow_template(ids: &[(u16, u16)]) -> Vec<FieldSpec> {
    ids.iter().map(|&(id, len)| f(id, len)).collect()
}

/// Sampling off: TCP flows.
pub fn off_t258() -> Vec<FieldSpec> {
    flow_template(&[
        (8, 4),
        (12, 4),
        (15, 4),
        (60, 1),
        (7, 2),
        (11, 2),
        (6, 1),
        (10, 2),
        (14, 2),
        (2, 4),
        (1, 4),
        (152, 8),
        (153, 8),
        (4, 1),
        (5, 1),
        (136, 1),
        (209, 4),
        (80, 6),
        (56, 6),
        (256, 2),
        (61, 1),
    ])
}

/// Sampling off: TCP and UDP flows without tcpOptions.
pub fn off_t259() -> Vec<FieldSpec> {
    off_t258().into_iter().filter(|x| x.id != 209).collect()
}

/// Sampling off: ICMP flows (icmpTypeCodeIPv4 instead of ports and flags).
pub fn off_t260() -> Vec<FieldSpec> {
    flow_template(&[
        (8, 4),
        (12, 4),
        (15, 4),
        (60, 1),
        (32, 2),
        (10, 2),
        (14, 2),
        (2, 4),
        (1, 4),
        (152, 8),
        (153, 8),
        (4, 1),
        (5, 1),
        (136, 1),
        (80, 6),
        (56, 6),
        (256, 2),
        (61, 1),
    ])
}

/// The value of element `id` for a generated flow, cut to `length` bytes.
fn flow_value(id: u16, length: u16, fl: &crate::Flow) -> Value {
    let u = Value::Unsigned;
    let mask = |n: u64| {
        if length >= 8 {
            n
        } else {
            n & ((1u64 << (8 * length)) - 1)
        }
    };
    let ip = |a: IpAddr| match a {
        IpAddr::V4(x) => Value::Ipv4(x),
        IpAddr::V6(_) => unreachable!("IPv4 flows"),
    };
    match id {
        8 => ip(fl.src),
        12 => ip(fl.dst),
        15 => Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
        60 => u(4),
        7 => u(fl.src_port.into()),
        11 => u(fl.dst_port.into()),
        32 => u(mask(u64::from(fl.dst_port))),
        6 => u(fl.tcp_flags.into()),
        10 => u(mask(fl.in_if.into())),
        14 => u(mask(fl.out_if.into())),
        2 => u(mask(fl.packets)),
        1 => u(mask(fl.bytes)),
        152 => u(fl.start_ms),
        153 => u(fl.end_ms),
        4 => u(fl.protocol.into()),
        5 => u(fl.tos.into()),
        136 => u(1),
        80 => Value::Mac([0x02, 0, 0, 0, 0, 1]),
        56 => Value::Mac([0x02, 0, 0, 0, 0, 2]),
        256 => u(0x0800),
        61 => u(255),
        302 => u(3),
        _ => u(0),
    }
}

fn flow_row(fields: &[FieldSpec], fl: &crate::Flow) -> Vec<Value> {
    fields
        .iter()
        .map(|x| flow_value(x.id, x.length, fl))
        .collect()
}

/// Gateway-shaped traffic with sampling on: one packet with the options
/// templates 256-260 and their data, then `packets` packets of up to
/// `per_packet` flows each on template 261, the template sent with the
/// first. Flow values are generated and cut to the field lengths.
pub fn traffic_sampled(seed: u64, packets: usize, per_packet: usize) -> Vec<Packet> {
    let mut r = Rng::new(seed);
    let base_ms = u64::from(BASE_SECS) * 1000;
    let u = Value::Unsigned;
    let mut seq = 0u32;
    let mut out = Vec::new();
    let opts = vec![
        set(3, &ipfix_options_template(256, 1, &t256())),
        set(3, &ipfix_options_template(257, 1, &t257())),
        set(3, &ipfix_options_template(258, 1, &t258())),
        set(3, &ipfix_options_template(259, 1, &t259())),
        set(3, &ipfix_options_template(260, 1, &t260())),
        unpadded_set(256, &t256(), &[domain_row(base_ms)]),
        unpadded_set(257, &t257(), &[vec![u(0), u(3), u(3), u(1), u(512)]]),
        unpadded_set(258, &t258(), &[iface_row(1)]),
        unpadded_set(259, &t259(), &[vec![u(0), u(1), u(2), u(3), u(4)]]),
        unpadded_set(
            260,
            &t260(),
            &[vec![u(3), u(1), u(512), u(1), u(base_ms), u(base_ms)]],
        ),
    ];
    out.push(Packet {
        exporter: exporter(1),
        label: "unifi sampled options".into(),
        bytes: ipfix_message(0, seq, BASE_SECS, &opts),
    });
    seq += 5;
    for i in 0..packets {
        let n = 1 + r.below(per_packet as u64) as usize;
        let rows: Vec<Vec<Value>> = (0..n)
            .map(|_| flow_row(&t261(), &random_flow(&mut r, false, base_ms)))
            .collect();
        let mut sets = Vec::new();
        if i == 0 {
            sets.push(set(2, &ipfix_template(261, &t261())));
        }
        sets.push(unpadded_set(261, &t261(), &rows));
        out.push(Packet {
            exporter: exporter(1),
            label: "unifi sampled flows".into(),
            bytes: ipfix_message(0, seq, BASE_SECS + i as u32, &sets),
        });
        seq += n as u32;
    }
    out
}

fn domain_row(base_ms: u64) -> Vec<Value> {
    let u = Value::Unsigned;
    vec![
        u(0),
        u(base_ms - 86_400_000),
        padded("gw", 29),
        u(base_ms),
        u(base_ms),
    ]
}

fn iface_row(i: u64) -> Vec<Value> {
    vec![
        Value::Unsigned(0),
        Value::Unsigned(i),
        padded(&format!("eth{i}"), 16),
        padded(&format!("port {i}"), 32),
    ]
}

/// Gateway-shaped traffic with sampling off: the options templates (256,
/// 257 the interface table, 261 the export counters) and the three flow
/// templates in the first packet, then `packets` packets of up to
/// `per_packet` flows each, split by protocol as the gateway does: TCP on
/// 258 or 259, UDP and others on 259, ICMP on 260.
pub fn traffic(seed: u64, packets: usize, per_packet: usize) -> Vec<Packet> {
    let mut r = Rng::new(seed);
    let base_ms = u64::from(BASE_SECS) * 1000;
    let u = Value::Unsigned;
    let mut seq = 0u32;
    let mut out = Vec::new();
    let first = vec![
        set(3, &ipfix_options_template(256, 1, &t256())),
        set(3, &ipfix_options_template(257, 1, &t258())),
        set(3, &ipfix_options_template(261, 1, &t259())),
        set(
            2,
            &[
                ipfix_template(258, &off_t258()),
                ipfix_template(259, &off_t259()),
                ipfix_template(260, &off_t260()),
            ]
            .concat(),
        ),
        unpadded_set(256, &t256(), &[domain_row(base_ms)]),
        unpadded_set(257, &t258(), &[iface_row(1), iface_row(2)]),
        unpadded_set(261, &t259(), &[vec![u(0), u(1), u(2), u(3), u(4)]]),
    ];
    out.push(Packet {
        exporter: exporter(1),
        label: "unifi options".into(),
        bytes: ipfix_message(0, seq, BASE_SECS, &first),
    });
    seq += 4;
    for i in 0..packets {
        let n = 1 + r.below(per_packet as u64) as usize;
        let mut by_tmpl: Vec<(u16, Vec<FieldSpec>, Vec<Vec<Value>>)> = vec![
            (258, off_t258(), Vec::new()),
            (259, off_t259(), Vec::new()),
            (260, off_t260(), Vec::new()),
        ];
        for k in 0..n {
            let fl = random_flow(&mut r, false, base_ms);
            let slot = match fl.protocol {
                1 => 2,
                6 if k % 2 == 0 => 0,
                _ => 1,
            };
            let row = flow_row(&by_tmpl[slot].1, &fl);
            by_tmpl[slot].2.push(row);
        }
        let sets: Vec<Vec<u8>> = by_tmpl
            .iter()
            .filter(|(_, _, rows)| !rows.is_empty())
            .map(|(id, fields, rows)| unpadded_set(*id, fields, rows))
            .collect();
        out.push(Packet {
            exporter: exporter(1),
            label: "unifi flows".into(),
            bytes: ipfix_message(0, seq, BASE_SECS + i as u32, &sets),
        });
        seq += n as u32;
    }
    out
}
