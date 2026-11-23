//! Load runs for the collector (R5): generated IPFIX over loopback UDP at
//! rising rates, through the staged collector in this process.
//!
//! For each rate the run records what was sent, what the collector read
//! from the socket, what it wrote, and two latencies per record:
//!
//! - **send to flush**: from the packet's *scheduled* send time to the
//!   flush of its lines, so time queued in the socket buffer counts and a
//!   sender that falls behind cannot hide delay;
//! - **receipt to flush**: from the receive stage's read to the flush, as
//!   the collector itself measures it.
//!
//! The sender shares the machine with the collector and the path is
//! loopback, not a network card. Run files go to
//! `runs/<machine>/<date>-collector[-n].json` and are never overwritten.
#![forbid(unsafe_code)]

use flowlanes_gen::{
    BASE_SECS, Rng, ipfix_message, ipfix_template, ipfix_v4_fields, random_flow, record, set,
    values,
};
use flowlanes_pipe::hist::Histogram;
use flowlanes_pipe::{Chunk, Config, Idle, Latency, Pipeline, Priority, Sink};
use serde_json::{Value as J, json};
use std::io::{self, Write};
use std::net::UdpSocket;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: flowlanes-bench --machine NAME --machine-desc TEXT
    [--rates PPS,PPS,...] [--secs N] [--warmup N] [--per-packet N] [--template-every N]
    [--idle backoff|spin] [--priority normal|high|time-critical] [--sink null|file]
    [--recv-buffer BYTES] [--blocks N] [--note TEXT] [--date YYYY-MM-DD] [--out-dir DIR]
  Rates are packets per second. Run from the flowlanes repo root.";

/// Shared between the sender and the sink: when each data packet was due.
struct SendLog {
    t0: Instant,
    due_ns: Vec<AtomicU64>,
    /// Packets before this index are warm-up and not measured.
    measure_from: u64,
}

struct Timed<W: Write + Send + 'static> {
    inner: io::BufWriter<W>,
    log: Arc<SendLog>,
    per_packet: u32,
    pending: Vec<u32>,
    hist: Arc<Mutex<Histogram>>,
}

impl<W: Write + Send + 'static> Sink for Timed<W> {
    fn write(&mut self, chunk: &Chunk<'_>) -> io::Result<()> {
        self.inner.write_all(chunk.json)?;
        self.pending.push(chunk.sequence / self.per_packet);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()?;
        let now = self.log.t0.elapsed().as_nanos() as u64;
        if let Ok(mut h) = self.hist.lock() {
            for i in self.pending.drain(..) {
                if u64::from(i) >= self.log.measure_from
                    && let Some(due) = self.log.due_ns.get(i as usize)
                {
                    h.record_n(
                        now.saturating_sub(due.load(Relaxed)),
                        u64::from(self.per_packet),
                    );
                }
            }
        }
        Ok(())
    }
}

struct Options {
    machine: String,
    machine_desc: String,
    rates: Vec<u64>,
    secs: u64,
    warmup: u64,
    per_packet: u32,
    template_every: u64,
    idle: Idle,
    priority: Priority,
    sink_file: bool,
    recv_buffer: Option<usize>,
    blocks: Option<usize>,
    note: String,
    date: Option<String>,
    out_dir: String,
}

fn parse() -> Result<Options, String> {
    let mut o = Options {
        machine: String::new(),
        machine_desc: String::new(),
        rates: vec![1_000, 5_000, 20_000, 50_000, 100_000, 150_000, 200_000],
        secs: 10,
        warmup: 2,
        per_packet: 24,
        template_every: 20,
        idle: Idle::BACKOFF,
        priority: Priority::Normal,
        sink_file: false,
        recv_buffer: None,
        blocks: None,
        note: String::new(),
        date: None,
        out_dir: "runs".into(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let v = args
            .get(i + 1)
            .ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("{flag}: cannot use '{v}'");
        match flag {
            "--machine" => o.machine = v.clone(),
            "--machine-desc" => o.machine_desc = v.clone(),
            "--rates" => {
                o.rates = v
                    .split(',')
                    .map(|r| r.parse().map_err(|_| bad()))
                    .collect::<Result<_, _>>()?
            }
            "--secs" => o.secs = v.parse().map_err(|_| bad())?,
            "--warmup" => o.warmup = v.parse().map_err(|_| bad())?,
            "--per-packet" => o.per_packet = v.parse().map_err(|_| bad())?,
            "--template-every" => o.template_every = v.parse().map_err(|_| bad())?,
            "--idle" => {
                o.idle = match v.as_str() {
                    "backoff" => Idle::BACKOFF,
                    "spin" => Idle::Spin,
                    _ => return Err(bad()),
                }
            }
            "--priority" => {
                o.priority = match v.as_str() {
                    "normal" => Priority::Normal,
                    "high" => Priority::High,
                    "time-critical" => Priority::TimeCritical,
                    _ => return Err(bad()),
                }
            }
            "--sink" => {
                o.sink_file = match v.as_str() {
                    "null" => false,
                    "file" => true,
                    _ => return Err(bad()),
                }
            }
            "--recv-buffer" => o.recv_buffer = Some(v.parse().map_err(|_| bad())?),
            "--blocks" => o.blocks = Some(v.parse().map_err(|_| bad())?),
            "--note" => o.note = v.clone(),
            "--date" => o.date = Some(v.clone()),
            "--out-dir" => o.out_dir = v.clone(),
            _ => return Err(format!("unknown argument '{flag}'")),
        }
        i += 2;
    }
    if o.machine.is_empty() || o.machine_desc.is_empty() {
        return Err("--machine and --machine-desc are required".into());
    }
    if o.per_packet == 0 || o.template_every == 0 || o.rates.contains(&0) {
        return Err("rates, --per-packet and --template-every must be above 0".into());
    }
    Ok(o)
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty() && out.status.success()).then(|| s.to_owned())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Days since 1970 to a civil date (Howard Hinnant's algorithm).
fn utc_date() -> String {
    let z = (now_secs() / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn git(dir: &str) -> J {
    json!({
        "commit": run("git", &["-C", dir, "rev-parse", "HEAD"]),
        "branch": run("git", &["-C", dir, "rev-parse", "--abbrev-ref", "HEAD"]),
        "uncommitted_changes":
            run("git", &["-C", dir, "status", "--porcelain", "--untracked-files=no"]).is_some(),
    })
}

fn us(l: Option<Latency>) -> J {
    l.map_or(J::Null, |l| l.json())
}

/// One rate: a fresh collector, `warmup + secs` seconds of load.
fn step(o: &Options, pps: u64, sender_cpu: Option<stagelanes_arch::OsCpu>) -> Result<J, String> {
    // Packets: one template, and data packets of `per_packet` IPv4 flows.
    let fields = ipfix_v4_fields();
    let mut rng = Rng::new(pps);
    let mut bodies: Vec<Vec<u8>> = (0..64)
        .map(|_| {
            let mut data = Vec::new();
            for _ in 0..o.per_packet {
                let f = random_flow(&mut rng, false, u64::from(BASE_SECS) * 1000);
                data.extend(record(&fields, &values(&fields, &f, "")));
            }
            ipfix_message(1, 0, BASE_SECS, &[set(256, &data)])
        })
        .collect();
    let mut template = ipfix_message(1, 0, BASE_SECS, &[set(2, &ipfix_template(256, &fields))]);
    let datagram_bytes = bodies[0].len();

    let total = pps * (o.warmup + o.secs);
    let log = Arc::new(SendLog {
        t0: Instant::now(),
        due_ns: (0..total).map(|_| AtomicU64::new(0)).collect(),
        measure_from: pps * o.warmup,
    });
    let hist = Arc::new(Mutex::new(Histogram::default()));
    let out: Box<dyn Write + Send> = if o.sink_file {
        let dir = std::path::Path::new("target").join("bench-out");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Box::new(
            std::fs::File::create(dir.join(format!("{pps}.jsonl"))).map_err(|e| e.to_string())?,
        )
    } else {
        Box::new(io::sink())
    };
    let sink = Timed {
        inner: io::BufWriter::with_capacity(256 * 1024, out),
        log: log.clone(),
        per_packet: o.per_packet,
        pending: Vec::with_capacity(1024),
        hist: hist.clone(),
    };
    let mut config = Config::new("127.0.0.1:0".parse().expect("address"));
    config.idle = o.idle;
    config.priority = o.priority;
    if let Some(b) = o.recv_buffer {
        config.recv_buffer_bytes = Some(b);
    }
    if let Some(b) = o.blocks {
        config.blocks = b;
    }
    let pipeline = Pipeline::start(config, sink).map_err(|e| e.to_string())?;
    let info = pipeline.info().json();
    let to = pipeline.info().local;
    let tx = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;

    let mut sender_notes = Vec::new();
    if let Some(cpu) = sender_cpu
        && let Err(e) = stagelanes_arch::pin_current_thread(cpu)
    {
        sender_notes.push(format!("sender not pinned: {e}"));
    }

    let gap_ns = 1_000_000_000 / pps;
    let mut templates_sent = 0u64;
    let mut max_lag_ns = 0u64;
    let start = Instant::now();
    let start_ns = log.t0.elapsed().as_nanos() as u64;
    for i in 0..total {
        if i == log.measure_from {
            pipeline.reset_latency();
        }
        let seq = (i as u32).wrapping_mul(o.per_packet);
        if i % o.template_every == 0 {
            // A template refresh, as an exporter sends it.
            template[8..12].copy_from_slice(&seq.to_be_bytes());
            tx.send_to(&template, to).map_err(|e| e.to_string())?;
            templates_sent += 1;
        }
        let due = start_ns + i * gap_ns;
        loop {
            let now = log.t0.elapsed().as_nanos() as u64;
            if now >= due {
                max_lag_ns = max_lag_ns.max(now - due);
                break;
            }
            std::hint::spin_loop();
        }
        log.due_ns[i as usize].store(due, Relaxed);
        let body = &mut bodies[(i % 64) as usize];
        body[8..12].copy_from_slice(&seq.to_be_bytes());
        tx.send_to(body, to).map_err(|e| e.to_string())?;
    }
    let send_secs = start.elapsed().as_secs_f64();

    // Let the collector finish what it has, then stop it.
    let mut last = u64::MAX;
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let s = pipeline.snapshot();
        let now = s.datagrams + s.lines_written;
        if now == last {
            break;
        }
        last = now;
    }
    let drain_secs = start.elapsed().as_secs_f64() - send_secs;
    let report = pipeline.stop();
    let s = &report.snapshot;

    let sent = total + templates_sent;
    let records_sent = total * u64::from(o.per_packet);
    let not_read = sent - s.datagrams;
    let send_to_flush = hist.lock().ok().and_then(|h| Latency::of(&h));
    let stages: Vec<J> = report
        .stages
        .iter()
        .map(|st| {
            json!({
                "name": st.name,
                "cpu": st.cpu.map(|c| c.to_string()),
                "busy_polls": st.busy_polls,
                "idle_polls": st.idle_polls,
                "setup_errors": st.setup_errors,
            })
        })
        .collect();
    eprintln!(
        "{pps:>8} pkt/s: sent {sent}, not read {not_read}, written {} of {records_sent} records, send-to-flush p50 {} p99 {} us",
        s.lines_written,
        send_to_flush.map_or("-".into(), |l| format!("{:.1}", l.p50 as f64 / 1e3)),
        send_to_flush.map_or("-".into(), |l| format!("{:.1}", l.p99 as f64 / 1e3)),
    );
    Ok(json!({
        "target_packets_per_sec": pps,
        "target_records_per_sec": pps * u64::from(o.per_packet),
        "data_packets_sent": total,
        "template_packets_sent": templates_sent,
        "datagram_bytes": datagram_bytes,
        "send_secs": send_secs,
        "achieved_packets_per_sec": total as f64 / send_secs,
        "achieved_records_per_sec": records_sent as f64 / send_secs,
        "sender_max_lag_us": max_lag_ns as f64 / 1e3,
        "drain_secs_after_last_send": drain_secs,
        "datagrams_read": s.datagrams,
        "datagrams_sent_not_read": not_read,
        "records_sent": records_sent,
        "records_written": s.lines_written,
        "records_lost": records_sent - s.lines_written,
        "sequence_missing": s.wire.sequence_missing,
        "lossless": not_read == 0 && records_sent == s.lines_written,
        "balanced": s.balanced(),
        "latency_send_to_flush": us(send_to_flush),
        "latency_receipt_to_flush": us(s.latency),
        "collector": s.json(),
        "start": info,
        "stages": stages,
        "sender_notes": sender_notes,
    }))
}

fn main() -> ExitCode {
    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("flowlanes-bench: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // The sender gets the last physical core; the stages take the second
    // to fifth.
    let sender_cpu = stagelanes_arch::Topology::detect().ok().and_then(|t| {
        let core = t.cores.last()?;
        core.cpus.first().map(|&i| t.cpus[i].os)
    });
    let mut steps = Vec::new();
    for &pps in &o.rates {
        match step(&o, pps, sender_cpu) {
            Ok(j) => steps.push(j),
            Err(e) => {
                eprintln!("flowlanes-bench: {pps} packets/s: {e}");
                return ExitCode::from(1);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let highest_lossless = steps
        .iter()
        .filter(|s| s["lossless"] == json!(true))
        .map(|s| s["achieved_records_per_sec"].as_f64().unwrap_or(0.0))
        .fold(0.0, f64::max);
    let secs_of_day = now_secs() % 86_400;
    let run_file = json!({
        "benchmark": "flowlanes collector, loopback UDP load (R5)",
        "machine": o.machine,
        "machine_desc": o.machine_desc,
        "os_build": run("cmd", &["/C", "ver"]).or_else(|| run("uname", &["-srv"])),
        "rustc": env!("BENCH_RUSTC"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "flowlanes": git("."),
        "stagelanes": git("../stagelanes"),
        "command": std::env::args().collect::<Vec<_>>().join(" "),
        "utc_date": utc_date(),
        "utc_time": format!(
            "{:02}:{:02}:{:02}Z",
            secs_of_day / 3600,
            (secs_of_day / 60) % 60,
            secs_of_day % 60
        ),
        "note": o.note,
        "method": {
            "path": "sender thread and collector in one process, UDP over loopback; no network card",
            "traffic": "IPFIX, one data set of --per-packet IPv4 flow records per datagram, a template before every --template-every data packets, evenly spaced",
            "per_packet": o.per_packet,
            "template_every": o.template_every,
            "measured_secs": o.secs,
            "warmup_secs": o.warmup,
            "idle": format!("{:?}", o.idle),
            "priority": format!("{:?}", o.priority),
            "sink": if o.sink_file {
                "file under target/bench-out"
            } else {
                "null (lines are formatted, then discarded)"
            },
            "sender_cpu": sender_cpu.map(|c| c.to_string()),
            "latency_send_to_flush": "per record, from the packet's scheduled send time to the flush of its line; warm-up excluded",
            "latency_receipt_to_flush": "per record, from the receive stage's read to the flush; warm-up excluded",
            "lossless": "every datagram sent was read and every record sent was written",
        },
        "highest_lossless_achieved_records_per_sec": highest_lossless,
        "steps": steps,
    });
    let date = o.date.clone().unwrap_or_else(utc_date);
    let dir = std::path::Path::new(&o.out_dir).join(&o.machine);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("flowlanes-bench: {}: {e}", dir.display());
        return ExitCode::from(1);
    }
    let mut path = dir.join(format!("{date}-collector.json"));
    let mut n = 2;
    while path.exists() {
        path = dir.join(format!("{date}-collector-{n}.json"));
        n += 1;
    }
    let text = serde_json::to_string_pretty(&run_file).expect("JSON") + "\n";
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("flowlanes-bench: {}: {e}", path.display());
        return ExitCode::from(1);
    }
    eprintln!("wrote {}", path.display());
    ExitCode::SUCCESS
}
