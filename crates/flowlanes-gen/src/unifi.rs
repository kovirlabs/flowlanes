//! Packets shaped like the IPFIX export of a UniFi gateway, as one was seen
//! sending on 2026-11-23 (`docs/unifi.md`): the same template IDs, element
//! IDs, lengths and order, with generated values only. Options templates
//! 256-259 are scoped by observationDomainId, 260 by selectorId; 261 is the
//! flow template.

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

/// Gateway-shaped traffic: one packet with the options templates 256-260
/// and their data, then `packets` packets of up to `per_packet` flows each
/// on template 261, the template sent with the first. Flow values are
/// generated and cut to the template's field lengths.
pub fn traffic(seed: u64, packets: usize, per_packet: usize) -> Vec<Packet> {
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
        unpadded_set(
            256,
            &t256(),
            &[vec![
                u(0),
                u(base_ms - 86_400_000),
                padded("gw", 29),
                u(base_ms),
                u(base_ms),
            ]],
        ),
        unpadded_set(257, &t257(), &[vec![u(0), u(3), u(3), u(1), u(512)]]),
        unpadded_set(
            258,
            &t258(),
            &[vec![u(0), u(1), padded("eth1", 16), padded("port 1", 32)]],
        ),
        unpadded_set(259, &t259(), &[vec![u(0), u(1), u(2), u(3), u(4)]]),
        unpadded_set(
            260,
            &t260(),
            &[vec![u(3), u(1), u(512), u(1), u(base_ms), u(base_ms)]],
        ),
    ];
    out.push(Packet {
        exporter: exporter(1),
        label: "unifi options".into(),
        bytes: ipfix_message(0, seq, BASE_SECS, &opts),
    });
    seq += 5;
    for i in 0..packets {
        let n = 1 + r.below(per_packet as u64) as usize;
        let rows: Vec<Vec<Value>> = (0..n)
            .map(|_| {
                let f = random_flow(&mut r, false, base_ms);
                let ip = |a: IpAddr| match a {
                    IpAddr::V4(x) => Value::Ipv4(x),
                    IpAddr::V6(_) => unreachable!("IPv4 flows"),
                };
                vec![
                    ip(f.src),
                    ip(f.dst),
                    Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
                    u(4),
                    u(f.src_port.into()),
                    u(f.dst_port.into()),
                    u(f.tcp_flags.into()),
                    u(u64::from(f.in_if) & 0xffff),
                    u(u64::from(f.out_if) & 0xffff),
                    u(f.packets & 0xffff_ffff),
                    u(f.bytes & 0xffff_ffff),
                    u(f.start_ms),
                    u(f.end_ms),
                    u(f.protocol.into()),
                    u(f.tos.into()),
                    u(3),
                    u(0),
                    Value::Mac([0x02, 0, 0, 0, 0, 1]),
                    Value::Mac([0x02, 0, 0, 0, 0, 2]),
                    u(0x0800),
                    u(0),
                    u(3),
                ]
            })
            .collect();
        let mut sets = Vec::new();
        if i == 0 {
            sets.push(set(2, &ipfix_template(261, &t261())));
        }
        sets.push(unpadded_set(261, &t261(), &rows));
        out.push(Packet {
            exporter: exporter(1),
            label: "unifi flows".into(),
            bytes: ipfix_message(0, seq, BASE_SECS + i as u32, &sets),
        });
        seq += n as u32;
    }
    out
}
