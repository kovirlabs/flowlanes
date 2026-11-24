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
//! flowlanes collect [--listen ADDR:PORT] [--out FILE] [options]
//!     Receive export packets over UDP and write one JSON object per record
//!     (see `collect.rs` for the options).
//! ```
#![forbid(unsafe_code)]

mod collect;

use flowlanes_pipe::json::{counters_json, record_json};
use flowlanes_wire::{Collector, Config};
use serde_json::json;
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage:
  flowlanes decode <file> [--honor-withdrawals]
  flowlanes generate --kind <v5|v9|ipfix|malformed|mix> [--seed N] [--packets N] (--out <file> | --udp <host:port>)
  flowlanes collect [--listen ADDR:PORT] [--out FILE] [--recv-buffer BYTES] [--blocks N]
                    [--no-pin] [--priority normal|high|time-critical] [--idle backoff|spin]
                    [--template-timeout SECS] [--hold-sets N] [--hold-secs SECS]
                    [--honor-withdrawals] [--stats-secs N] [--duration SECS]
      Listens on 0.0.0.0:2055 by default. Records go to FILE (appended) or stdout;
      counters go to stderr as JSON every --stats-secs (60) and at the end.
      Stops on Ctrl-C or after --duration.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("decode") => decode(&args[1..]),
        Some("generate") => generate(&args[1..]),
        Some("collect") => collect::collect(&args[1..], USAGE),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
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
        // A packet file has no receive times, so templates cannot age.
        template_timeout_secs: 0,
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
