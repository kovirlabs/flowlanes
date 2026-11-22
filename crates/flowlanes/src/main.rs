//! `flowlanes` command line.
//!
//! ```text
//! flowlanes decode <file> [--honor-withdrawals]
//!     Decode a flowlanes packet file; one JSON object per record on stdout,
//!     the counters as one JSON object on stderr.
//! flowlanes generate --kind <v5|v9|ipfix|malformed|mix> [--seed N] [--packets N]
//!                    (--out <file> | --udp <host:port>)
//!     Write generated export packets to a file, or send them over UDP
//!     (for a cross-check collector on this machine).
//! ```
#![forbid(unsafe_code)]

use flowlanes_wire::{Collector, Config, Counters, Record, Value};
use serde_json::{Map, Value as J, json};
use std::io::Write;
use std::process::ExitCode;

/// Default UDP port for the collector (decided 2026-11-22; used from M2).
pub const DEFAULT_PORT: u16 = 2055;

const USAGE: &str = "usage:
  flowlanes decode <file> [--honor-withdrawals]
  flowlanes generate --kind <v5|v9|ipfix|malformed|mix> [--seed N] [--packets N] (--out <file> | --udp <host:port>)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("decode") => decode(&args[1..]),
        Some("generate") => generate(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

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

fn decode(args: &[String]) -> ExitCode {
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("flowlanes: {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let packets = match flowlanes_gen::read_packets(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("flowlanes: {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let config = Config {
        honor_withdrawals: args.iter().any(|a| a == "--honor-withdrawals"),
        ..Config::default()
    };
    let mut c = Collector::new(config);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for (i, (exp, bytes)) in packets.iter().enumerate() {
        // The file has no receive times; packets are one second apart.
        for r in c.decode(*exp, bytes, i as u64) {
            if writeln!(out, "{}", record_json(&r)).is_err() {
                return ExitCode::from(1);
            }
        }
    }
    c.finish();
    let _ = out.flush();
    eprintln!(
        "{}",
        json!({ "event": "counters", "counters": counters_json(&c.counters) })
    );
    ExitCode::SUCCESS
}

fn generate(args: &[String]) -> ExitCode {
    let mut kind = None;
    let mut seed = 1u64;
    let mut packets = 10usize;
    let mut out_path = None;
    let mut udp = None;
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--kind" => kind = v,
            "--seed" => seed = v.and_then(|s| s.parse().ok()).unwrap_or(1),
            "--packets" => packets = v.and_then(|s| s.parse().ok()).unwrap_or(10),
            "--out" => out_path = v,
            "--udp" => udp = v,
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("flowlanes: unknown argument '{other}'\n{USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let pk = match kind.as_deref() {
        Some("v5") => flowlanes_gen::traffic(5, seed, packets, 30).0,
        Some("v9") => flowlanes_gen::traffic(9, seed, packets, 20).0,
        Some("ipfix") => flowlanes_gen::traffic(10, seed, packets, 20).0,
        Some("malformed") => flowlanes_gen::malformed(seed),
        Some("mix") => flowlanes_gen::mix(seed),
        _ => {
            eprintln!("flowlanes: --kind is required\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match (out_path, udp) {
        (Some(p), None) => {
            if let Err(e) = std::fs::write(&p, flowlanes_gen::write_packets(&pk)) {
                eprintln!("flowlanes: {p}: {e}");
                return ExitCode::from(1);
            }
            eprintln!("wrote {} packets to {p}", pk.len());
        }
        (None, Some(target)) => {
            let sock = match std::net::UdpSocket::bind("127.0.0.1:0") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("flowlanes: bind: {e}");
                    return ExitCode::from(1);
                }
            };
            for p in &pk {
                if let Err(e) = sock.send_to(&p.bytes, &target) {
                    eprintln!("flowlanes: send to {target}: {e}");
                    return ExitCode::from(1);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            eprintln!("sent {} packets to {target}", pk.len());
        }
        _ => {
            eprintln!("flowlanes: give exactly one of --out or --udp\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
