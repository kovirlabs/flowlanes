//! Records and counters as JSON. One `flow` event per line is the
//! collector's output format.

use flowlanes_wire::{Counters, Record, Value};
use serde_json::{Map, Value as J, json};
use std::io::Write;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn value_json(v: &Value) -> J {
    match v {
        Value::Unsigned(n) => json!(n),
        Value::Ipv4(a) => json!(a.to_string()),
        Value::Ipv6(a) => json!(a.to_string()),
        Value::Mac(m) => json!(
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        ),
        Value::Str(s) => json!(s),
        Value::Bytes(b) => json!(hex(b)),
    }
}

/// One record as JSON. Known elements by IANA name; unknown and
/// enterprise elements listed with their ID and raw bytes (R4).
pub fn record_json(r: &Record) -> J {
    let mut fields = Map::new();
    let mut unknown = Vec::new();
    let mut scope = Vec::new();
    for f in &r.fields {
        match f.name {
            Some(n) => {
                fields.insert(n.to_string(), value_json(&f.value));
                if f.scope {
                    scope.push(n);
                }
            }
            None => {
                let raw = match &f.value {
                    Value::Bytes(b) => hex(b),
                    other => value_json(other).to_string(),
                };
                unknown.push(json!({ "id": f.id, "enterprise": f.enterprise, "hex": raw }));
            }
        }
    }
    let mut o = json!({
        "event": "flow",
        "exporter": r.exporter.to_string(),
        "version": r.version.number(),
        "domain": r.domain,
        "template_id": r.template_id,
        "options": r.options,
        "export_time": r.export_time,
        "sequence": r.sequence,
        "fields": fields,
    });
    if !unknown.is_empty() {
        o["unknown"] = J::Array(unknown);
    }
    if !scope.is_empty() {
        o["scope"] = json!(scope);
    }
    o
}

fn write_hex(out: &mut Vec<u8>, b: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &x in b {
        out.push(DIGITS[usize::from(x >> 4)]);
        out.push(DIGITS[usize::from(x & 15)]);
    }
}

fn write_value(out: &mut Vec<u8>, v: &Value) {
    // Writing to a `Vec` cannot fail.
    match v {
        Value::Unsigned(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Ipv4(a) => {
            let _ = write!(out, "\"{a}\"");
        }
        Value::Ipv6(a) => {
            let _ = write!(out, "\"{a}\"");
        }
        Value::Mac(m) => {
            out.push(b'"');
            for (i, b) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b':');
                }
                write_hex(out, &[*b]);
            }
            out.push(b'"');
        }
        Value::Str(s) => {
            // serde_json does the escaping.
            let _ = serde_json::to_writer(&mut *out, s);
        }
        Value::Bytes(b) => {
            out.push(b'"');
            write_hex(out, b);
            out.push(b'"');
        }
    }
}

/// Appends one record as a JSON line (with its newline) to `out`: the same
/// bytes as [`record_json`] printed, without building the tree. This is
/// what the encode stage runs per record.
pub fn write_record(out: &mut Vec<u8>, r: &Record) {
    // A nameless field always carries raw bytes; anything else takes the
    // slow path so the two can never differ.
    if r.fields
        .iter()
        .any(|f| f.name.is_none() && !matches!(f.value, Value::Bytes(_)))
    {
        let _ = serde_json::to_writer(&mut *out, &record_json(r));
        out.push(b'\n');
        return;
    }
    let _ = write!(
        out,
        "{{\"event\":\"flow\",\"exporter\":\"{}\",\"version\":{},\"domain\":{},\"template_id\":",
        r.exporter,
        r.version.number(),
        r.domain
    );
    let _ = match r.template_id {
        Some(id) => write!(out, "{id}"),
        None => write!(out, "null"),
    };
    let _ = write!(
        out,
        ",\"options\":{},\"export_time\":{},\"sequence\":{},\"fields\":{{",
        r.options, r.export_time, r.sequence
    );
    // A name that occurs twice keeps its first place and its last value,
    // as inserting into a map does.
    let mut first = true;
    for (i, f) in r.fields.iter().enumerate() {
        let Some(name) = f.name else { continue };
        if r.fields[..i].iter().any(|g| g.name == Some(name)) {
            continue;
        }
        let last = r.fields[i..]
            .iter()
            .rfind(|g| g.name == Some(name))
            .unwrap_or(f);
        if !first {
            out.push(b',');
        }
        first = false;
        let _ = write!(out, "\"{name}\":");
        write_value(out, &last.value);
    }
    out.push(b'}');
    let mut first = true;
    for f in r.fields.iter().filter(|f| f.name.is_none()) {
        out.extend_from_slice(if first { b",\"unknown\":[" } else { b"," });
        first = false;
        let _ = write!(out, "{{\"id\":{},\"enterprise\":", f.id);
        let _ = match f.enterprise {
            Some(e) => write!(out, "{e}"),
            None => write!(out, "null"),
        };
        out.extend_from_slice(b",\"hex\":");
        write_value(out, &f.value);
        out.push(b'}');
    }
    if !first {
        out.push(b']');
    }
    let mut first = true;
    for f in r.fields.iter().filter(|f| f.scope) {
        let Some(name) = f.name else { continue };
        out.extend_from_slice(if first { b",\"scope\":[" } else { b"," });
        first = false;
        let _ = write!(out, "\"{name}\"");
    }
    if !first {
        out.push(b']');
    }
    out.extend_from_slice(b"}\n");
}

pub fn counters_json(c: &Counters) -> J {
    let mut errors = Map::new();
    let mut e: Vec<_> = c.packet_errors.iter().collect();
    e.sort();
    for (k, v) in e {
        errors.insert(format!("{k:?}"), json!(v));
    }
    json!({
        "packets": c.packets,
        "packets_v5": c.packets_by_version[0],
        "packets_v9": c.packets_by_version[1],
        "packets_ipfix": c.packets_by_version[2],
        "packets_malformed": c.packets_malformed,
        "packet_errors": errors,
        "sets_malformed": c.sets_malformed,
        "sets_reserved_id": c.sets_reserved_id,
        "templates_added": c.templates_added,
        "templates_replaced": c.templates_replaced,
        "templates_malformed": c.templates_malformed,
        "templates_expired": c.templates_expired,
        "withdrawals_applied": c.withdrawals_applied,
        "withdrawals_ignored": c.withdrawals_ignored,
        "data_sets": c.data_sets,
        "data_sets_decoded": c.data_sets_decoded,
        "data_sets_held": c.data_sets_held,
        "data_sets_released": c.data_sets_released,
        "data_sets_rejected_no_template": c.data_sets_rejected_no_template,
        "data_sets_malformed": c.data_sets_malformed,
        "data_sets_held_now": c.held_now(),
        "records_out": c.records_out,
        "options_records_out": c.options_records_out,
        "records_malformed": c.records_malformed,
        "sequence_missing": c.sequence_missing,
        "sequence_out_of_order": c.sequence_out_of_order,
        "sets_balance": c.sets_balance(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlanes_gen::{mix, traffic};
    use flowlanes_wire::{Collector, Field};
    use std::net::{IpAddr, Ipv4Addr};

    fn same(r: &Record) {
        let mut fast = Vec::new();
        write_record(&mut fast, r);
        let slow = record_json(r).to_string() + "\n";
        assert_eq!(String::from_utf8(fast).expect("UTF-8"), slow);
    }

    #[test]
    fn the_fast_writer_prints_what_record_json_prints() {
        let from = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut c = Collector::default();
        let mut records = Vec::new();
        let mut packets = mix(11);
        for v in [5, 9, 10] {
            packets.extend(traffic(v, 12, 40, 20).0);
        }
        for p in &packets {
            records.extend(c.decode(from, &p.bytes, 0));
        }
        assert!(records.len() > 500);
        assert!(records.iter().any(|r| r.options));
        assert!(
            records
                .iter()
                .any(|r| r.fields.iter().any(|f| f.name.is_none()))
        );
        records.iter().for_each(same);

        // Shapes the generator does not make: a repeated element, text
        // that needs escaping, a nameless field that is not raw bytes.
        let mut r = records[0].clone();
        let mut again = r.fields[0].clone();
        again.value = Value::Unsigned(7);
        r.fields.push(again);
        r.fields.push(Field {
            id: 82,
            enterprise: None,
            name: Some("interfaceName"),
            scope: true,
            value: Value::Str("a\"b\\c\n\u{1}é".into()),
        });
        same(&r);
        r.fields.push(Field {
            id: 9999,
            enterprise: Some(1),
            name: None,
            scope: false,
            value: Value::Unsigned(3),
        });
        same(&r);
    }
}
