//! M1 gates for `flowlanes-wire`, using `flowlanes-gen` packets and
//! hand-written golden vectors.

use flowlanes_gen::*;
use flowlanes_wire::{Collector, Config, FieldSpec, Record, Value, Version};
use std::net::{IpAddr, Ipv4Addr};

fn ip4(a: u8, b: u8, c: u8, d: u8) -> Value {
    Value::Ipv4(Ipv4Addr::new(a, b, c, d))
}

fn hexbytes(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn exp() -> IpAddr {
    exporter(1)
}

// ------------------------------------------------------------ R1 golden

/// NetFlow v5, one record, written byte by byte from the Cisco v5 header
/// and record tables.
#[test]
fn r1_golden_v5() {
    let p = hexbytes(
        "0005 0001 00000064 6a5f0000 00000000 00000007 01 02 0000
         c0000201 cb007105 00000000 0003 0004 0000000a 000003e8
         00000010 00000020 d431 01bb 00 12 06 00 0000 0000 18 18 0000",
    );
    let mut c = Collector::default();
    let r = c.decode(exp(), &p, 0);
    assert_eq!(r.len(), 1);
    let r = &r[0];
    assert_eq!(r.version, Version::V5);
    assert_eq!(r.sequence, 7);
    assert_eq!(r.domain, 0x0102);
    assert_eq!(r.export_time, 0x6a5f0000);
    assert_eq!(r.get(8), Some(&ip4(192, 0, 2, 1)));
    assert_eq!(r.get(12), Some(&ip4(203, 0, 113, 5)));
    assert_eq!(r.get(10), Some(&Value::Unsigned(3)));
    assert_eq!(r.get(14), Some(&Value::Unsigned(4)));
    assert_eq!(r.get(2), Some(&Value::Unsigned(10)));
    assert_eq!(r.get(1), Some(&Value::Unsigned(1000)));
    assert_eq!(r.get(22), Some(&Value::Unsigned(16)));
    assert_eq!(r.get(21), Some(&Value::Unsigned(32)));
    assert_eq!(r.get(7), Some(&Value::Unsigned(54321)));
    assert_eq!(r.get(11), Some(&Value::Unsigned(443)));
    assert_eq!(r.get(6), Some(&Value::Unsigned(0x12)));
    assert_eq!(r.get(4), Some(&Value::Unsigned(6)));
    assert_eq!(r.get(9), Some(&Value::Unsigned(24)));
}

/// NetFlow v9: a template FlowSet and a data FlowSet with padding, per
/// RFC 3954 §5.
#[test]
fn r1_golden_v9() {
    let p = hexbytes(
        "0009 0002 00001000 6a5f0000 00000005 00000011
         0000 0014 0100 0003 0008 0004 000c 0004 0001 0004
         0100 0010 c6336401 c0000202 00000bb8 00000000",
    );
    let mut c = Collector::default();
    let r = c.decode(exp(), &p, 0);
    assert_eq!(r.len(), 1, "{:?}", c.counters);
    assert_eq!(r[0].version, Version::V9);
    assert_eq!(r[0].domain, 0x11);
    assert_eq!(r[0].template_id, Some(256));
    assert_eq!(r[0].get(8), Some(&ip4(198, 51, 100, 1)));
    assert_eq!(r[0].get(12), Some(&ip4(192, 0, 2, 2)));
    assert_eq!(r[0].get(1), Some(&Value::Unsigned(3000)));
    assert!(c.counters.sets_balance());
}

/// IPFIX: template set with an enterprise element and a variable-length
/// string, then a data set, per RFC 7011 §3.
#[test]
fn r1_golden_ipfix() {
    let p = hexbytes(
        "000a 0038 6a5f0000 00000000 00000001
         0002 0018 0101 0003 0008 0004 8001 0002 00007ed9 0060 ffff
         0101 0010 c0000203 abcd 03 646e73 00 00",
    );
    // Message length: 16 + 24 + 16 = 56 = 0x38.
    let mut c = Collector::default();
    let r = c.decode(exp(), &p, 0);
    assert_eq!(r.len(), 1, "{:?}", c.counters);
    let f = &r[0].fields;
    assert_eq!(f[0].value, ip4(192, 0, 2, 3));
    assert_eq!(f[1].enterprise, Some(32473));
    assert_eq!(f[1].id, 1);
    assert_eq!(f[1].value, Value::Bytes(vec![0xab, 0xcd]));
    assert_eq!(f[2].name, Some("applicationName"));
    assert_eq!(f[2].value, Value::Str("dns".into()));
    assert!(c.counters.sets_balance());
}

// ------------------------------------------------------------ R1 round trip

fn flow_matches(r: &Record, f: &Flow, v5: bool) {
    let ip = |a: IpAddr| match a {
        IpAddr::V4(a) => Value::Ipv4(a),
        IpAddr::V6(a) => Value::Ipv6(a),
    };
    let src = r.get(8).or(r.get(27)).unwrap();
    let dst = r.get(12).or(r.get(28)).unwrap();
    assert_eq!(src, &ip(f.src));
    assert_eq!(dst, &ip(f.dst));
    assert_eq!(r.get(7), Some(&Value::Unsigned(f.src_port.into())));
    assert_eq!(r.get(11), Some(&Value::Unsigned(f.dst_port.into())));
    assert_eq!(r.get(4), Some(&Value::Unsigned(f.protocol.into())));
    assert_eq!(r.get(6), Some(&Value::Unsigned(f.tcp_flags.into())));
    assert_eq!(r.get(5), Some(&Value::Unsigned(f.tos.into())));
    assert_eq!(r.get(10), Some(&Value::Unsigned(f.in_if.into())));
    assert_eq!(r.get(14), Some(&Value::Unsigned(f.out_if.into())));
    let mask = |n: u64| if v5 { n & 0xffff_ffff } else { n };
    match r.get(1) {
        Some(Value::Unsigned(b)) => assert_eq!(*b, mask(f.bytes) & bytes_mask(r)),
        other => panic!("octetDeltaCount {other:?}"),
    }
    match r.get(2) {
        Some(Value::Unsigned(p)) => assert_eq!(*p, mask(f.packets) & bytes_mask(r)),
        other => panic!("packetDeltaCount {other:?}"),
    }
}

fn bytes_mask(r: &Record) -> u64 {
    if r.template_id == Some(258) || r.version != Version::Ipfix {
        0xffff_ffff
    } else {
        u64::MAX
    }
}

#[test]
fn r1_round_trip_every_version() {
    for version in [5u16, 9, 10] {
        let (packets, flows) = traffic(version, 42 + u64::from(version), 40, 20);
        let mut c = Collector::default();
        let mut recs = Vec::new();
        for (i, p) in packets.iter().enumerate() {
            recs.extend(c.decode(p.exporter, &p.bytes, i as u64));
        }
        let flow_recs: Vec<_> = recs.iter().filter(|r| !r.options).collect();
        assert_eq!(flow_recs.len(), flows.len(), "v{version}: {:?}", c.counters);
        for (r, f) in flow_recs.iter().zip(&flows) {
            flow_matches(r, f, version == 5);
        }
        assert_eq!(c.counters.records_out as usize, flows.len());
        assert_eq!(c.counters.packets_malformed, 0);
        assert_eq!(c.counters.sequence_missing, 0, "v{version}");
        assert!(c.counters.sets_balance());
    }
}

// ------------------------------------------------------------ R2 templates

fn fields_a() -> Vec<FieldSpec> {
    vec![
        FieldSpec {
            id: 8,
            enterprise: None,
            length: 4,
        },
        FieldSpec {
            id: 1,
            enterprise: None,
            length: 4,
        },
    ]
}
fn fields_b() -> Vec<FieldSpec> {
    vec![
        FieldSpec {
            id: 1,
            enterprise: None,
            length: 8,
        },
        FieldSpec {
            id: 12,
            enterprise: None,
            length: 4,
        },
    ]
}

fn tmpl(id: u16, f: &[FieldSpec]) -> Vec<u8> {
    set(2, &ipfix_template(id, f))
}

fn data(id: u16, f: &[FieldSpec], v: &[Value]) -> Vec<u8> {
    set(id, &record(f, v))
}

#[test]
fn r2_templates_are_scoped_by_exporter_and_domain() {
    let mut c = Collector::default();
    let (e1, e2) = (exporter(1), exporter(2));
    // Same template ID 256, three different definitions.
    c.decode(
        e1,
        &ipfix_message(1, 0, BASE_SECS, &[tmpl(256, &fields_a())]),
        0,
    );
    c.decode(
        e1,
        &ipfix_message(2, 0, BASE_SECS, &[tmpl(256, &fields_b())]),
        0,
    );
    c.decode(
        e2,
        &ipfix_message(1, 0, BASE_SECS, &[tmpl(256, &fields_b())]),
        0,
    );
    assert_eq!(c.counters.templates_added, 3);
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(77)];
    let vb = [Value::Unsigned(88), ip4(203, 0, 113, 9)];
    let r1 = c.decode(
        e1,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_a(), &va)]),
        0,
    );
    let r2 = c.decode(
        e1,
        &ipfix_message(2, 0, BASE_SECS, &[data(256, &fields_b(), &vb)]),
        0,
    );
    let r3 = c.decode(
        e2,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_b(), &vb)]),
        0,
    );
    assert_eq!(r1[0].get(8), Some(&va[0]));
    assert_eq!(r2[0].get(12), Some(&vb[1]));
    assert_eq!(r3[0].get(1), Some(&Value::Unsigned(88)));
}

#[test]
fn r2_template_replaced() {
    let mut c = Collector::default();
    let e = exp();
    c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[tmpl(256, &fields_a())]),
        0,
    );
    c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[tmpl(256, &fields_b())]),
        0,
    );
    assert_eq!(c.counters.templates_replaced, 1);
    let vb = [Value::Unsigned(5), ip4(203, 0, 113, 1)];
    let r = c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_b(), &vb)]),
        0,
    );
    assert_eq!(r[0].get(12), Some(&vb[1]));
}

fn withdrawal(id: u16) -> Vec<u8> {
    let mut b = id.to_be_bytes().to_vec();
    b.extend_from_slice(&[0, 0]);
    set(2, &b)
}

#[test]
fn r2_withdrawal_ignored_over_udp_by_default() {
    let mut c = Collector::default();
    let e = exp();
    c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[tmpl(256, &fields_a())]),
        0,
    );
    c.decode(e, &ipfix_message(1, 0, BASE_SECS, &[withdrawal(256)]), 0);
    assert_eq!(c.counters.withdrawals_ignored, 1);
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(1)];
    let r = c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_a(), &va)]),
        0,
    );
    assert_eq!(r.len(), 1);
}

#[test]
fn r2_withdrawal_honoured_when_configured() {
    let mut c = Collector::new(Config {
        honor_withdrawals: true,
        ..Config::default()
    });
    let e = exp();
    c.decode(
        e,
        &ipfix_message(
            1,
            0,
            BASE_SECS,
            &[tmpl(256, &fields_a()), tmpl(257, &fields_b())],
        ),
        0,
    );
    c.decode(e, &ipfix_message(1, 0, BASE_SECS, &[withdrawal(256)]), 0);
    assert_eq!(c.counters.withdrawals_applied, 1);
    assert_eq!(c.template_count(), 1);
    // "Withdraw all": template ID 2 in a template set.
    c.decode(e, &ipfix_message(1, 0, BASE_SECS, &[withdrawal(2)]), 0);
    assert_eq!(c.template_count(), 0);
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(1)];
    let r = c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_a(), &va)]),
        0,
    );
    assert!(r.is_empty());
    assert_eq!(c.counters.data_sets_held, 1);
}

#[test]
fn r2_data_before_template_is_held_then_decoded() {
    let mut c = Collector::default();
    let e = exp();
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(1)];
    let r = c.decode(
        e,
        &ipfix_message(1, 0, BASE_SECS, &[data(256, &fields_a(), &va)]),
        0,
    );
    assert!(r.is_empty());
    assert_eq!(c.counters.held_now(), 1);
    let r = c.decode(
        e,
        &ipfix_message(1, 1, BASE_SECS, &[tmpl(256, &fields_a())]),
        1,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].get(8), Some(&va[0]));
    assert_eq!(c.counters.data_sets_released, 1);
    assert_eq!(c.counters.held_now(), 0);
    assert!(c.counters.sets_balance());
}

#[test]
fn r2_held_data_is_rejected_at_the_limit_and_by_age() {
    let mut c = Collector::new(Config {
        hold_max_sets: 2,
        hold_max_age_secs: 10,
        ..Config::default()
    });
    let e = exp();
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(1)];
    for i in 0..3 {
        c.decode(
            e,
            &ipfix_message(1, i, BASE_SECS, &[data(256, &fields_a(), &va)]),
            0,
        );
    }
    assert_eq!(
        c.counters.data_sets_rejected_no_template, 1,
        "over the limit"
    );
    assert_eq!(c.counters.held_now(), 2);
    // A packet 11 seconds later ages the two out.
    c.decode(
        e,
        &ipfix_message(1, 9, BASE_SECS, &[tmpl(300, &fields_b())]),
        11,
    );
    assert_eq!(c.counters.data_sets_rejected_no_template, 3);
    assert_eq!(c.counters.held_now(), 0);
    assert!(c.counters.sets_balance());
}

#[test]
fn r2_options_templates_are_decoded() {
    // IPFIX
    let mut c = Collector::default();
    let o = ipfix_options_fields();
    let vals = [Value::Unsigned(7), Value::Unsigned(512), Value::Unsigned(2)];
    let r = c.decode(
        exp(),
        &ipfix_message(
            1,
            0,
            BASE_SECS,
            &[
                set(3, &ipfix_options_template(300, 1, &o)),
                set(300, &record(&o, &vals)),
            ],
        ),
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].options);
    assert!(r[0].fields[0].scope && !r[0].fields[1].scope);
    assert_eq!(r[0].get(34), Some(&Value::Unsigned(512)));
    assert_eq!(c.counters.options_records_out, 1);
    // NetFlow v9: scope "System" (type 1) then samplingInterval.
    let mut c = Collector::default();
    let tpl = v9_options_template(400, &[(1, 4)], &[(34, 4)]);
    let mut d = 9u32.to_be_bytes().to_vec();
    d.extend_from_slice(&100u32.to_be_bytes());
    let p = v9_packet(3, 0, 0, BASE_SECS, 2, &[set(1, &tpl), set(400, &d)]);
    let r = c.decode(exp(), &p, 0);
    assert_eq!(r.len(), 1, "{:?}", c.counters);
    assert!(r[0].options && r[0].fields[0].scope);
    assert_eq!(r[0].get(34), Some(&Value::Unsigned(100)));
}

// ------------------------------------------------------------ R3 counts

#[test]
fn r3_malformed_packets_are_counted_not_decoded_wrongly() {
    let mut c = Collector::default();
    let mut out = Vec::new();
    let pk = malformed(5);
    for (i, p) in pk.iter().enumerate() {
        let r = c.decode(p.exporter, &p.bytes, i as u64);
        if p.label != "good-after-malformed" && p.label != "ipfix-data-nonzero-trailer" {
            assert!(r.is_empty(), "{} produced records", p.label);
        }
        out.extend(r);
    }
    let k = &c.counters;
    // one-byte, unknown-version, ipfix-short-header, ipfix-length-mismatch,
    // v5-count-mismatch, v5-short-header, v9-short-header
    assert_eq!(k.packets_malformed, 7, "{k:?}");
    // ipfix-set-overrun, ipfix-set-length-below-header, v9-flowset-overrun
    assert_eq!(k.sets_malformed, 3, "{k:?}");
    // truncated (ipfix, v9), options scope 0, id below 256, zero-length field
    assert_eq!(k.templates_malformed, 5, "{k:?}");
    // varlen overrun, non-zero trailer
    assert_eq!(k.data_sets_malformed, 2, "{k:?}");
    // The record before the bad trailer, and the good packet's record.
    assert_eq!(out.len(), 2);
    assert!(k.sets_balance());
    assert_eq!(k.packets as usize, pk.len());
}

#[test]
fn r3_sequence_gaps_are_counted() {
    for (version, expect) in [(5u16, None), (9, Some(1u64)), (10, None)] {
        let (packets, _) = traffic(version, 9, 6, 10);
        let mut c = Collector::default();
        // Drop packet 2 (for IPFIX, one without a template refresh).
        let dropped = &packets[2];
        let lost_records = {
            let mut probe = Collector::default();
            for p in &packets[..2] {
                probe.decode(p.exporter, &p.bytes, 0);
            }
            let before = probe.counters.records_out + probe.counters.options_records_out;
            probe.decode(dropped.exporter, &dropped.bytes, 0);
            probe.counters.records_out + probe.counters.options_records_out - before
        };
        for (i, p) in packets.iter().enumerate() {
            if i != 2 {
                c.decode(p.exporter, &p.bytes, 0);
            }
        }
        let want = expect.unwrap_or(lost_records);
        assert_eq!(c.counters.sequence_missing, want, "v{version}");
    }
}

#[test]
fn r3_records_in_equal_records_out_plus_rejects() {
    let pk = mix(11);
    let mut c = Collector::default();
    for (i, p) in pk.iter().enumerate() {
        c.decode(p.exporter, &p.bytes, i as u64);
    }
    // A data set for a template that never comes.
    let va = [ip4(192, 0, 2, 9), Value::Unsigned(1)];
    c.decode(
        exporter(99),
        &ipfix_message(1, 0, BASE_SECS, &[data(999, &fields_a(), &va)]),
        99,
    );
    c.finish();
    let k = &c.counters;
    assert!(k.sets_balance(), "{k:?}");
    assert_eq!(k.data_sets_rejected_no_template, 1);
    assert_eq!(k.held_now(), 0);
}

// ------------------------------------------------------------ R4 unknown fields

#[test]
fn r4_unknown_and_enterprise_elements_are_kept() {
    let f = ipfix_extended_fields();
    let mut r = Rng::new(3);
    let flow = random_flow(&mut r, false, u64::from(BASE_SECS) * 1000);
    let vals = values(&f, &flow, "a-much-longer-application-name");
    let mut c = Collector::default();
    let recs = c.decode(
        exp(),
        &ipfix_message(
            1,
            0,
            BASE_SECS,
            &[
                set(2, &ipfix_template(258, &f)),
                set(258, &record(&f, &vals)),
            ],
        ),
        0,
    );
    assert_eq!(recs.len(), 1);
    let ent = recs[0]
        .fields
        .iter()
        .find(|x| x.enterprise == Some(EXAMPLE_PEN))
        .unwrap();
    assert_eq!(ent.id, 1);
    assert_eq!(ent.name, None);
    assert_eq!(ent.value, Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
    let un = recs[0]
        .fields
        .iter()
        .find(|x| x.id == UNASSIGNED_IE)
        .unwrap();
    assert_eq!(un.name, None);
    assert_eq!(un.value, Value::Bytes(vec![0x12, 0x34]));
    assert_eq!(
        recs[0].get(96),
        Some(&Value::Str("a-much-longer-application-name".into()))
    );
}

#[test]
fn r4_long_variable_length_form() {
    let f = vec![FieldSpec {
        id: 96,
        enterprise: None,
        length: flowlanes_wire::VARLEN,
    }];
    let long = "x".repeat(300);
    let mut c = Collector::default();
    let recs = c.decode(
        exp(),
        &ipfix_message(
            1,
            0,
            BASE_SECS,
            &[
                tmpl(256, &f),
                set(256, &record(&f, &[Value::Str(long.clone())])),
            ],
        ),
        0,
    );
    assert_eq!(recs[0].get(96), Some(&Value::Str(long)));
}

#[test]
fn packet_file_round_trip() {
    let pk = mix(2);
    let back = read_packets(&write_packets(&pk)).unwrap();
    assert_eq!(back.len(), pk.len());
    for (a, b) in pk.iter().zip(&back) {
        assert_eq!(a.exporter, b.0);
        assert_eq!(a.bytes, b.1);
    }
}
