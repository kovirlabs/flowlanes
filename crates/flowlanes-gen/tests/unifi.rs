//! Packets shaped like the IPFIX export of Evan's UniFi gateway, as seen
//! on 2026-11-23 (`docs/unifi.md`): the same template IDs, element IDs,
//! lengths and order, with generated values only. Addresses are from the
//! documentation ranges and MAC addresses are locally administered.

use flowlanes_gen::unifi::*;
use flowlanes_gen::{exporter, ipfix_message, ipfix_options_template, ipfix_template, set};
use flowlanes_wire::{Collector, Config, FieldSpec, Value, ie};
use std::net::Ipv4Addr;

const T0: u32 = 1_700_000_000;
const MS: u64 = T0 as u64 * 1000;

fn u(n: u64) -> Value {
    Value::Unsigned(n)
}

fn row259(n: u64) -> Vec<Value> {
    vec![u(0), u(n), u(n * 2), u(n * 300), u(n * 5)]
}

fn row260(n: u64) -> Vec<Value> {
    vec![u(3), u(n), u(n * 512), u(n), u(MS), u(MS + 60_000)]
}

fn flow(n: u8) -> Vec<Value> {
    vec![
        Value::Ipv4(Ipv4Addr::new(192, 0, 2, n)),
        Value::Ipv4(Ipv4Addr::new(198, 51, 100, n)),
        Value::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
        u(4),
        u(50_000 + u64::from(n)),
        u(443),
        u(0x18),
        u(2),
        u(3),
        u(10),
        u(4_000),
        u(MS),
        u(MS + 1_500),
        u(6),
        u(0),
        u(3),
        u(0),
        Value::Mac([0x02, 0, 0, 0, 0, n]),
        Value::Mac([0x02, 0, 0, 0, 1, n]),
        u(0x0800),
        u(0),
        u(3),
    ]
}

/// The export as seen after a collector start: the 60-second options data
/// (259, 260) arrives first, the options templates some minutes later, the
/// flow template with the first flow. With the default hold limits nothing
/// is lost, every element is named, and the sequence numbers (which count
/// options records too) show no gap.
#[test]
fn gateway_shaped_export_after_a_collector_start_decodes_fully() {
    let mut c = Collector::default();
    let e = exporter(1);
    let mut seq = 0u32;
    let mut out = Vec::new();
    let mut send = |c: &mut Collector, at: u64, sets: Vec<Vec<u8>>, records: u32| {
        let m = ipfix_message(0, seq, T0 + at as u32, &sets);
        seq += records;
        c.decode(e, &m, at)
    };
    // Every 60 s: one 259 and one 260 record, before their templates.
    for (i, at) in [60u64, 120, 180].into_iter().enumerate() {
        let n = i as u64 + 1;
        out.extend(send(
            &mut c,
            at,
            vec![
                unpadded_set(259, &t259(), &[row259(n)]),
                unpadded_set(260, &t260(), &[row260(n)]),
            ],
            2,
        ));
    }
    assert!(out.is_empty());
    assert_eq!(c.counters.held_now(), 6);
    // At 230 s the options templates 256-258 with their data (an interface
    // table of 3 rows here), at 291 s templates 259 and 260 with new data.
    let iface = |i: u64| {
        vec![
            u(0),
            u(i),
            padded(&format!("eth{i}"), 16),
            padded(&format!("port {i}"), 32),
        ]
    };
    out.extend(send(
        &mut c,
        230,
        vec![
            set(3, &ipfix_options_template(256, 1, &t256())),
            set(3, &ipfix_options_template(257, 1, &t257())),
            set(3, &ipfix_options_template(258, 1, &t258())),
            unpadded_set(
                256,
                &t256(),
                &[vec![
                    u(0),
                    u(MS - 86_400_000),
                    padded("gateway", 29),
                    u(MS),
                    u(MS),
                ]],
            ),
            unpadded_set(257, &t257(), &[vec![u(0), u(3), u(3), u(1), u(512)]]),
            unpadded_set(258, &t258(), &[iface(1), iface(2), iface(3)]),
        ],
        5,
    ));
    out.extend(send(
        &mut c,
        291,
        vec![
            set(3, &ipfix_options_template(259, 1, &t259())),
            set(3, &ipfix_options_template(260, 1, &t260())),
            unpadded_set(259, &t259(), &[row259(5)]),
            unpadded_set(260, &t260(), &[row260(5)]),
        ],
        2,
    ));
    out.extend(send(
        &mut c,
        381,
        vec![
            set(2, &ipfix_template(261, &t261())),
            unpadded_set(261, &t261(), &[flow(1), flow(2)]),
        ],
        2,
    ));

    let k = &c.counters;
    assert_eq!(k.data_sets_rejected_no_template, 0, "{k:?}");
    assert_eq!(k.data_sets_released, 6);
    assert_eq!(k.held_now(), 0);
    assert!(k.sets_balance());
    assert_eq!(k.sequence_missing, 0);
    assert_eq!(k.options_records_out, 13);
    assert_eq!(k.records_out, 2);
    assert_eq!(out.len(), 15);
    // Every field of every record has its IANA name.
    for r in &out {
        for fld in &r.fields {
            assert!(fld.name.is_some(), "element {} unnamed", fld.id);
        }
    }
    // Scope fields are marked.
    let r260 = out.iter().find(|r| r.template_id == Some(260)).unwrap();
    assert!(r260.fields[0].scope && r260.fields[0].name == Some("selectorId"));
    // Fixed-length strings come out without their padding.
    let r258 = out.iter().find(|r| r.template_id == Some(258)).unwrap();
    assert_eq!(r258.get(82), Some(&Value::Str("eth1".into())));
    assert_eq!(r258.get(83), Some(&Value::Str("port 1".into())));
    // The sampling configuration (random 1-out-of-512) is readable.
    let r257 = out.iter().find(|r| r.template_id == Some(257)).unwrap();
    assert_eq!(r257.get(390), Some(&u(3)));
    assert_eq!(r257.get(309), Some(&u(1)));
    assert_eq!(r257.get(310), Some(&u(512)));
    // Flow records: reduced-size counters and 2-byte interfaces decode.
    let fl = out.iter().find(|r| r.template_id == Some(261)).unwrap();
    assert_eq!(fl.get(8), Some(&Value::Ipv4(Ipv4Addr::new(192, 0, 2, 1))));
    assert_eq!(fl.get(1), Some(&u(4_000)));
    assert_eq!(fl.get(2), Some(&u(10)));
    assert_eq!(fl.get(10), Some(&u(2)));
    assert_eq!(fl.get(56), Some(&Value::Mac([0x02, 0, 0, 0, 1, 1])));
    assert_eq!(fl.get(302), Some(&u(3)));

    // The old 60 s hold limit would have rejected the data that came
    // more than 60 s before its template.
    let mut old = Collector::new(Config {
        hold_max_age_secs: 60,
        ..Config::default()
    });
    for (at, n) in [(60u64, 1), (120, 2), (180, 3)] {
        old.decode(
            e,
            &ipfix_message(
                0,
                0,
                T0,
                &[
                    unpadded_set(259, &t259(), &[row259(n)]),
                    unpadded_set(260, &t260(), &[row260(n)]),
                ],
            ),
            at,
        );
    }
    old.decode(
        e,
        &ipfix_message(
            0,
            0,
            T0,
            &[set(3, &ipfix_options_template(259, 1, &t259()))],
        ),
        291,
    );
    assert!(old.counters.data_sets_rejected_no_template >= 4);
}

#[test]
fn every_element_the_gateway_sends_has_its_iana_name() {
    // Names and types checked against the IANA registry copy of 2026-11-23.
    for (id, name) in [
        (40, "exportedOctetTotalCount"),
        (41, "exportedMessageTotalCount"),
        (42, "exportedFlowRecordTotalCount"),
        (82, "interfaceName"),
        (83, "interfaceDescription"),
        (163, "observedFlowTotalCount"),
        (209, "tcpOptions"),
        (256, "ethernetType"),
        (300, "observationDomainName"),
        (302, "selectorId"),
        (309, "samplingSize"),
        (310, "samplingPopulation"),
        (318, "selectorIdTotalPktsObserved"),
        (319, "selectorIdTotalPktsSelected"),
        (390, "flowSelectorAlgorithm"),
        (395, "selectorIDTotalFlowsSelected"),
    ] {
        assert_eq!(ie::lookup(id).map(|(n, _)| n), Some(name), "element {id}");
        assert_eq!(ie::id_of(name), Some(id));
    }
    // The table stays sorted and free of duplicates.
    assert!(ie::KNOWN.windows(2).all(|w| w[0].0 < w[1].0));
}

#[test]
fn nul_padding_is_cut_from_fixed_length_strings() {
    let (name, v) = flowlanes_wire::decode_value(82, None, b"eth9\0\0\0\0\0\0\0\0\0\0\0\0");
    assert_eq!(name, Some("interfaceName"));
    assert_eq!(v, Value::Str("eth9".into()));
    // All padding: the empty string.
    let (_, v) = flowlanes_wire::decode_value(83, None, &[0; 32]);
    assert_eq!(v, Value::Str(String::new()));
    // A NUL inside the text is kept; only trailing padding is cut.
    let (_, v) = flowlanes_wire::decode_value(83, None, b"a\0b\0\0");
    assert_eq!(v, Value::Str("a\0b".into()));
    // Not UTF-8: raw bytes, padding included.
    let (_, v) = flowlanes_wire::decode_value(83, None, &[0xff, 0xfe, 0]);
    assert_eq!(v, Value::Bytes(vec![0xff, 0xfe, 0]));
}

#[test]
fn template_changes_are_reported_once_per_layout() {
    let fields = [f(8, 4), f(12, 4)];
    let t = |layout: &[FieldSpec]| {
        ipfix_message(0, 0, 1_700_000_000, &[set(2, &ipfix_template(261, layout))])
    };
    let mut quiet = Collector::default();
    quiet.decode(exporter(1), &t(&fields), 0);
    assert!(quiet.take_template_changes().is_empty(), "off by default");

    let mut c = Collector::new(Config {
        report_templates: true,
        ..Config::default()
    });
    c.decode(exporter(1), &t(&fields), 0);
    let got = c.take_template_changes();
    assert_eq!(got.len(), 1);
    assert!(!got[0].changed);
    assert_eq!(got[0].template.fields, fields);
    // The same layout re-sent: counted as replaced, not reported again.
    c.decode(exporter(1), &t(&fields), 600);
    assert!(c.take_template_changes().is_empty());
    assert_eq!(c.counters.templates_replaced, 1);
    // A different layout under the same ID is reported as a change.
    c.decode(exporter(1), &t(&[f(8, 4)]), 1200);
    let got = c.take_template_changes();
    assert_eq!(got.len(), 1);
    assert!(got[0].changed);
}

/// Sampling off: three flow templates split by protocol, the interface
/// table on 257 and the export counters on 261. Everything decodes, every
/// element is named, and the sequence numbers show no gap.
#[test]
fn gateway_shaped_export_without_sampling_decodes_fully() {
    let mut c = Collector::default();
    let mut out = Vec::new();
    for (i, p) in traffic(5, 40, 20).iter().enumerate() {
        out.extend(c.decode(p.exporter, &p.bytes, i as u64));
    }
    let k = &c.counters;
    assert!(k.sets_balance());
    assert_eq!(k.data_sets_malformed + k.data_sets_rejected_no_template, 0);
    assert_eq!(k.sequence_missing + k.sequence_out_of_order, 0);
    assert_eq!(k.options_records_out, 4);
    assert!(k.records_out > 100);
    for r in &out {
        for fld in &r.fields {
            assert!(fld.name.is_some(), "element {} unnamed", fld.id);
        }
    }
    for t in [258, 259, 260] {
        assert!(out.iter().any(|r| r.template_id == Some(t)), "template {t}");
    }
    let icmp = out.iter().find(|r| r.template_id == Some(260)).unwrap();
    assert_eq!(icmp.get(4), Some(&u(1)));
    assert!(icmp.get(32).is_some());
    assert!(out.iter().all(|r| r.options || r.get(302).is_none()));
}

/// When sampling is switched off the gateway starts a new export: the
/// sequence numbers start again and template IDs 257 to 261 come back with
/// other layouts. Each new layout replaces the old one, is reported as a
/// change, and the data after it decodes with the new layout.
#[test]
fn switching_sampling_off_reuses_template_ids_cleanly() {
    let mut c = Collector::new(Config {
        report_templates: true,
        ..Config::default()
    });
    let e = exporter(1);
    for (i, p) in traffic_sampled(3, 5, 10).iter().enumerate() {
        c.decode(e, &p.bytes, i as u64);
    }
    let before = c.take_template_changes().len();
    assert_eq!(before, 6);
    let mut out = Vec::new();
    for (i, p) in traffic(4, 5, 10).iter().enumerate() {
        out.extend(c.decode(e, &p.bytes, 100 + i as u64));
    }
    let changes = c.take_template_changes();
    // 256 is unchanged; 257 to 261 change layout.
    assert_eq!(changes.len(), 5);
    assert!(changes.iter().all(|t| t.changed));
    let k = &c.counters;
    assert_eq!(
        k.sequence_out_of_order, 1,
        "the new export starts again at 0"
    );
    assert_eq!(k.data_sets_malformed, 0);
    assert!(k.sets_balance());
    assert!(out.iter().all(|r| r.template_id != Some(258) || !r.options));
    // Sampled data for a reused ID arriving after the switch but before
    // the new template would be read with the old layout: the decoder has
    // no way to tell. The gateway was seen sending the new templates first.
}
