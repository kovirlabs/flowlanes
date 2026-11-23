//! Records and counters as JSON. One `flow` event per line is the
//! collector's output format.

use flowlanes_wire::{Counters, Record, Value};
use serde_json::{Map, Value as J, json};

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
