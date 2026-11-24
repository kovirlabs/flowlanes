//! R1 cross-check: the same generated packets decoded by goflow2 (an
//! existing open collector, BSD-3-Clause, image
//! `netsampler/goflow2:v2.2.7`) give the same field values as
//! `flowlanes-wire`.
//!
//! The test starts its own goflow2 container bound to 127.0.0.1, sends
//! generated v5, v9 and IPFIX packets (including the UniFi gateway's layout) to it over UDP on this machine,
//! reads goflow2's JSON output and compares. It prints SKIPPED and passes
//! when Docker or the image is not available, or when
//! `FLOWLANES_SKIP_LIVE` is set.

use flowlanes_wire::{Collector, Record, Value};
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

const IMAGE: &str = "netsampler/goflow2:v2.2.7";
const NAME: &str = "flowlanes-goflow2-r1";
const PORT: u16 = 20555;

fn docker(args: &[&str]) -> Option<String> {
    let out = Command::new("docker").args(args).output().ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    })
}

/// The fields both sides report, as comparable strings.
type Key = BTreeMap<&'static str, String>;

fn ours(r: &Record) -> Option<Key> {
    let u = |id| match r.get(id) {
        Some(Value::Unsigned(n)) => n.to_string(),
        _ => "0".into(),
    };
    let ip = |a, b| match r.get(a).or(r.get(b)) {
        Some(Value::Ipv4(x)) => Some(x.to_string()),
        Some(Value::Ipv6(x)) => Some(x.to_string()),
        _ => None,
    };
    let mut k = Key::new();
    k.insert("src_addr", ip(8, 27)?);
    k.insert("dst_addr", ip(12, 28)?);
    k.insert("src_port", u(7));
    k.insert("dst_port", u(11));
    k.insert(
        "proto",
        match u(4).as_str() {
            "6" => "TCP".into(),
            "17" => "UDP".into(),
            "1" => "ICMP".into(),
            other => other.into(),
        },
    );
    k.insert("bytes", u(1));
    k.insert("packets", u(2));
    k.insert("in_if", u(10));
    k.insert("out_if", u(14));
    k.insert("ip_tos", u(5));
    k.insert("tcp_flags", u(6));
    if let Some(Value::Unsigned(ms)) = r.get(152) {
        k.insert("time_flow_start_ns", (ms * 1_000_000).to_string());
    }
    k.insert(
        "type",
        match r.version.number() {
            5 => "NETFLOW_V5".into(),
            9 => "NETFLOW_V9".into(),
            _ => "IPFIX".into(),
        },
    );
    Some(k)
}

fn theirs(v: &serde_json::Value, with_time: bool) -> Key {
    let s = |f: &str| match &v[f] {
        serde_json::Value::String(x) => x.clone(),
        other => other.to_string(),
    };
    let mut k = Key::new();
    for f in [
        "src_addr",
        "dst_addr",
        "src_port",
        "dst_port",
        "proto",
        "bytes",
        "packets",
        "in_if",
        "out_if",
        "ip_tos",
        "tcp_flags",
        "type",
    ] {
        k.insert(f, s(f));
    }
    if with_time {
        k.insert("time_flow_start_ns", s("time_flow_start_ns"));
    }
    k
}

#[test]
fn r1_cross_check_with_goflow2() {
    if std::env::var("FLOWLANES_SKIP_LIVE").is_ok() {
        eprintln!("SKIPPED goflow2 cross-check: FLOWLANES_SKIP_LIVE is set");
        return;
    }
    if docker(&["image", "inspect", IMAGE]).is_none() {
        eprintln!("SKIPPED goflow2 cross-check: docker or image {IMAGE} not available");
        return;
    }
    let _ = docker(&["rm", "-f", NAME]);
    let port_map = format!("127.0.0.1:{PORT}:2055/udp");
    if docker(&[
        "run",
        "-d",
        "--name",
        NAME,
        "-p",
        &port_map,
        IMAGE,
        "-listen",
        "netflow://:2055",
        "-format",
        "json",
    ])
    .is_none()
    {
        eprintln!("SKIPPED goflow2 cross-check: container did not start");
        return;
    }
    // Wait for goflow2 to listen.
    let t0 = Instant::now();
    while !docker(&["logs", NAME])
        .unwrap_or_default()
        .contains("starting collection")
    {
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "goflow2 did not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let mut packets = Vec::new();
    for (v, seed) in [(5u16, 101u64), (9, 102), (10, 103)] {
        packets.extend(flowlanes_gen::traffic(v, seed, 12, 15).0);
    }
    // IPFIX in the layout a UniFi gateway sends (docs/unifi.md).
    packets.extend(flowlanes_gen::unifi::traffic(104, 12, 15));
    let mut c = Collector::default();
    let mut expect: Vec<Key> = Vec::new();
    for p in &packets {
        for r in c.decode(p.exporter, &p.bytes, 0) {
            if !r.options {
                expect.push(ours(&r).expect("address fields"));
            }
        }
    }
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    for p in &packets {
        sock.send_to(&p.bytes, ("127.0.0.1", PORT)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    // Collect goflow2's JSON lines.
    let t0 = Instant::now();
    let mut lines: Vec<serde_json::Value>;
    loop {
        let logs = docker(&["logs", NAME]).unwrap_or_default();
        lines = logs
            .lines()
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if lines.len() >= expect.len() || t0.elapsed() > Duration::from_secs(20) {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let _ = docker(&["rm", "-f", NAME]);

    let mut got: Vec<Key> = lines
        .iter()
        .map(|v| theirs(v, v["type"] == "IPFIX"))
        .collect();
    let mut want = expect.clone();
    got.sort();
    want.sort();
    let missing: Vec<_> = want.iter().filter(|k| !got.contains(k)).take(5).collect();
    let extra: Vec<_> = got.iter().filter(|k| !want.contains(k)).take(5).collect();
    eprintln!(
        "goflow2 cross-check: {} records from flowlanes, {} from goflow2",
        want.len(),
        got.len()
    );
    assert_eq!(
        got, want,
        "first differences: flowlanes-only {missing:?}, goflow2-only {extra:?}"
    );
}
