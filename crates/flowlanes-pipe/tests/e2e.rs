//! R3 end to end: generated packets over loopback UDP through the staged
//! collector. Nothing is lost without being counted.

use flowlanes_gen::*;
use flowlanes_pipe::platform::SocketDrops;
use flowlanes_pipe::{Chunk, Config, Idle, Pipeline, Sink, json};
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Collects the lines; `write` waits while the gate is shut.
struct Gated {
    lines: Arc<Mutex<Vec<u8>>>,
    shut: Arc<AtomicBool>,
}

impl Sink for Gated {
    fn write(&mut self, chunk: &Chunk<'_>) -> io::Result<()> {
        while self.shut.load(Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.lines
            .lock()
            .expect("lines")
            .extend_from_slice(chunk.json);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn config() -> Config {
    Config {
        // Tests share the machine with other tests: no pinning.
        pin: false,
        ..Config::new("127.0.0.1:0".parse().expect("address"))
    }
}

/// Waits until `done` holds, up to 20 s.
fn wait(mut done: impl FnMut() -> bool) {
    let t = Instant::now();
    while !done() {
        assert!(t.elapsed() < Duration::from_secs(20), "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn run_mix(idle: Idle) {
    let packets = mix(7);
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Gated {
        lines: lines.clone(),
        shut: Arc::new(AtomicBool::new(false)),
    };
    let p = Pipeline::start(Config { idle, ..config() }, sink).expect("start");
    let to = p.info().local;
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
    for (i, pk) in packets.iter().enumerate() {
        tx.send_to(&pk.bytes, to).expect("send");
        // Paced, and checked, so the socket buffer cannot overflow here.
        if i % 8 == 7 {
            wait(|| p.snapshot().datagrams == i as u64 + 1);
        }
    }
    wait(|| p.snapshot().datagrams == packets.len() as u64);
    let report = p.stop();
    let s = &report.snapshot;

    // The same bytes through the decoder alone. Over UDP every packet
    // comes from the loopback address, whatever exporter the generator
    // had in mind.
    let from = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut reference = flowlanes_wire::Collector::default();
    let mut expected = Vec::new();
    for pk in &packets {
        for r in reference.decode(from, &pk.bytes, 0) {
            expected.extend_from_slice(json::record_json(&r).to_string().as_bytes());
            expected.push(b'\n');
        }
    }
    reference.finish();

    assert_eq!(s.datagrams, packets.len() as u64);
    assert_eq!(
        s.wire, reference.counters,
        "same counters as the decoder alone"
    );
    assert!(
        s.wire.packets_malformed > 0,
        "the mix has malformed packets"
    );
    assert_eq!(s.records_failed, 0);
    assert!(s.balanced(), "{}", s.json());
    let got = lines.lock().expect("lines");
    assert_eq!(
        got.iter().filter(|&&b| b == b'\n').count() as u64,
        s.lines_written
    );
    assert!(*got == expected, "same lines, in the same order");
    assert!(s.latency.is_some());
}

#[test]
fn r3_every_packet_of_the_mix_is_written_or_counted() {
    run_mix(Idle::BACKOFF);
}

#[test]
fn r3_every_packet_of_the_mix_is_written_or_counted_spinning() {
    run_mix(Idle::Spin);
}

#[test]
fn r3_datagrams_dropped_at_the_socket_are_accounted_for() {
    const PER_PACKET: u32 = 10;
    const FLOOD: u32 = 6000;
    let fields = ipfix_v4_fields();
    let mut rng = Rng::new(3);
    let mut data = Vec::new();
    for _ in 0..PER_PACKET {
        let f = random_flow(&mut rng, false, u64::from(BASE_SECS) * 1000);
        data.extend(record(&fields, &values(&fields, &f, "")));
    }
    let packet = |n: u32| ipfix_message(1, n * PER_PACKET, BASE_SECS, &[set(256, &data)]);

    let lines = Arc::new(Mutex::new(Vec::new()));
    let shut = Arc::new(AtomicBool::new(false));
    let sink = Gated {
        lines: lines.clone(),
        shut: shut.clone(),
    };
    let p = Pipeline::start(
        Config {
            // A small socket buffer and a small pool, so a stalled
            // pipeline overflows quickly.
            recv_buffer_bytes: Some(16 * 1024),
            blocks: 4,
            ..config()
        },
        sink,
    )
    .expect("start");
    let to = p.info().local;
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");

    // The template arrives first, on its own.
    let template = ipfix_message(1, 0, BASE_SECS, &[set(2, &ipfix_template(256, &fields))]);
    tx.send_to(&template, to).expect("send");
    wait(|| p.snapshot().datagrams == 1);

    // Stall the output, then send far more than the links and the socket
    // buffer can hold.
    shut.store(true, Relaxed);
    for n in 0..FLOOD {
        tx.send_to(&packet(n), to).expect("send");
    }
    shut.store(false, Relaxed);
    // Let it drain, then send three more, slowly: a gap is only seen when
    // a later packet arrives.
    let mut last = 0;
    wait(|| {
        std::thread::sleep(Duration::from_millis(50));
        let now = p.snapshot().datagrams;
        let quiet = now == last;
        last = now;
        quiet
    });
    for n in FLOOD..FLOOD + 3 {
        let before = p.snapshot().datagrams;
        tx.send_to(&packet(n), to).expect("send");
        wait(|| p.snapshot().datagrams == before + 1);
    }
    let report = p.stop();
    let s = &report.snapshot;

    let sent = u64::from(FLOOD) + 4;
    let records_sent = u64::from((FLOOD + 3) * PER_PACKET);
    let dropped = sent - s.datagrams;
    assert!(dropped > 0, "the flood overflowed the socket: {}", s.json());
    assert!(
        s.pool_empty_waits > 0,
        "the receive stage ran out of blocks"
    );
    // Every record sent was written, or is in a counted sequence gap.
    assert_eq!(
        records_sent,
        s.lines_written + s.wire.sequence_missing,
        "{}",
        s.json()
    );
    assert_eq!(s.wire.sequence_missing, dropped * u64::from(PER_PACKET));
    assert!(s.balanced(), "{}", s.json());
    assert_eq!(
        lines
            .lock()
            .expect("lines")
            .iter()
            .filter(|&&b| b == b'\n')
            .count() as u64,
        s.lines_written
    );
    // Where the kernel counts drops per socket, its count is the same.
    match s.socket_drops {
        SocketDrops::Counted(n) => assert_eq!(n, dropped),
        SocketDrops::Unavailable(_) => {}
    }
}
