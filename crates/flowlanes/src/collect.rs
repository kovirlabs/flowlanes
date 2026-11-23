//! `flowlanes collect`: the staged collector as a program.

use flowlanes_pipe::{Config, DEFAULT_PORT, Idle, JsonLines, Pipeline, Priority};
use serde_json::json;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

struct Options {
    config: Config,
    out: Option<String>,
    stats_secs: u64,
    duration: Option<u64>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        config: Config::new(SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))),
        out: None,
        stats_secs: 60,
        duration: None,
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        // Flags without a value.
        match flag {
            "--no-pin" => {
                o.config.pin = false;
                i += 1;
                continue;
            }
            "--honor-withdrawals" => {
                o.config.wire.honor_withdrawals = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        let v = args
            .get(i + 1)
            .ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = || format!("{flag}: cannot use '{v}'");
        match flag {
            "--listen" => o.config.listen = v.parse().map_err(|_| bad())?,
            "--out" => o.out = Some(v.clone()),
            "--recv-buffer" => o.config.recv_buffer_bytes = Some(v.parse().map_err(|_| bad())?),
            "--blocks" => o.config.blocks = v.parse().map_err(|_| bad())?,
            "--priority" => {
                o.config.priority = match v.as_str() {
                    "normal" => Priority::Normal,
                    "high" => Priority::High,
                    "time-critical" => Priority::TimeCritical,
                    _ => return Err(bad()),
                }
            }
            "--idle" => {
                o.config.idle = match v.as_str() {
                    "backoff" => Idle::BACKOFF,
                    "spin" => Idle::Spin,
                    _ => return Err(bad()),
                }
            }
            "--template-timeout" => {
                o.config.wire.template_timeout_secs = v.parse().map_err(|_| bad())?
            }
            "--hold-sets" => o.config.wire.hold_max_sets = v.parse().map_err(|_| bad())?,
            "--hold-secs" => o.config.wire.hold_max_age_secs = v.parse().map_err(|_| bad())?,
            "--stats-secs" => o.stats_secs = v.parse().map_err(|_| bad())?,
            "--duration" => o.duration = Some(v.parse().map_err(|_| bad())?),
            _ => return Err(format!("unknown argument '{flag}'")),
        }
        i += 2;
    }
    Ok(o)
}

pub fn collect(args: &[String], usage: &str) -> ExitCode {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("flowlanes: {e}\n{usage}");
            return ExitCode::from(2);
        }
    };
    let out: Box<dyn Write + Send> = match &o.out {
        Some(path) => match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("flowlanes: {path}: {e}");
                return ExitCode::from(1);
            }
        },
        None => Box::new(std::io::stdout()),
    };
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        if let Err(e) = ctrlc::set_handler(move || stop.store(true, Relaxed)) {
            eprintln!("flowlanes: no Ctrl-C handler ({e}); stop with --duration");
        }
    }
    let pipeline = match Pipeline::start(o.config, JsonLines::new(out)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("flowlanes: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "{}",
        json!({ "event": "collector_start", "collector": pipeline.info().json() })
    );
    let started = Instant::now();
    let mut next_stats = o.stats_secs;
    while !stop.load(Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        let secs = started.elapsed().as_secs();
        if o.duration.is_some_and(|d| secs >= d) {
            break;
        }
        if o.stats_secs > 0 && secs >= next_stats {
            next_stats = secs + o.stats_secs;
            eprintln!(
                "{}",
                json!({ "event": "collector_stats", "uptime_secs": secs, "collector": pipeline.snapshot().json() })
            );
        }
    }
    let report = pipeline.stop();
    let stages: Vec<_> = report
        .stages
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "cpu": s.cpu.map(|c| c.to_string()),
                "busy_polls": s.busy_polls,
                "idle_polls": s.idle_polls,
                "setup_errors": s.setup_errors,
            })
        })
        .collect();
    eprintln!(
        "{}",
        json!({
            "event": "collector_stop",
            "uptime_secs": started.elapsed().as_secs(),
            "balanced": report.snapshot.balanced(),
            "collector": report.snapshot.json(),
            "stages": stages,
        })
    );
    if report.snapshot.balanced() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
