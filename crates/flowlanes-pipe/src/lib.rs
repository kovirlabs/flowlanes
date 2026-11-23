//! The staged collector: UDP in, JSON lines out, on `stagelanes` stages.
//!
//! ```text
//! socket ─► receive ─► decode ─► encode ─► output ─► sink
//!              ▲ blocks │           ▲ buffers │
//!              └────────┘           └─────────┘
//! ```
//!
//! - **receive** reads one datagram into a block from a pool set up at
//!   start, stamps the time of receipt and passes the block on.
//! - **decode** owns the template state ([`flowlanes_wire::Collector`]),
//!   decodes the packet and returns the block.
//! - **encode** turns records into JSON lines in a reused buffer.
//! - **output** hands the lines to the [`Sink`], flushes, and records the
//!   time from receipt to flush for every record.
//!
//! Each stage is one thread, pinned to its own core when the machine has
//! enough, joined by `stagelanes-pipe` links. A full link makes the sender
//! wait, so the pipeline never drops anything itself: when it cannot keep
//! up, the block pool runs dry, the receive stage stops reading, and the
//! kernel drops datagrams at the socket. That is the one place loss can
//! happen inside the collector. It is counted where the OS allows
//! ([`platform::SocketDrops`]) and shows as sequence gaps everywhere (R3).
#![forbid(unsafe_code)]

pub mod hist;
pub mod json;
pub mod platform;

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use flowlanes_wire::{Counters, Record};
use hist::Histogram;
use platform::SocketDrops;
use serde_json::{Value as J, json};
use socket2::{Domain, Protocol, Socket, Type};
use stagelanes_arch::{OsCpu, Topology};
use stagelanes_mem::{Block, BlockPool, LargePages, Region, RegionConfig};
use stagelanes_pipe::{CorePlan, StageCtx, StageSpec, link, spawn_stage};

pub use stagelanes_arch::Priority;
pub use stagelanes_pipe::StageReport;

/// Default UDP port (decided 2026-11-22).
pub const DEFAULT_PORT: u16 = 2055;

/// Bytes per packet block. A UDP datagram cannot be larger, so a datagram
/// is never truncated.
pub const BLOCK_BYTES: usize = 65536;

/// Most blocks a pool may have (the size of the link that returns them).
pub const MAX_BLOCKS: usize = 4096;

/// Slots in each forward link.
const LINK: usize = 1024;

/// What a stage does when it has no work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idle {
    /// Poll again at once. Lowest delay; each stage keeps a core busy.
    Spin,
    /// Poll `spins` times, then sleep `sleep` between polls. The receive
    /// stage blocks in the socket read instead of polling.
    Backoff { spins: u32, sleep: Duration },
}

impl Idle {
    /// The default: gives the cores back when there is no traffic.
    pub const BACKOFF: Idle = Idle::Backoff {
        spins: 2000,
        sleep: Duration::from_millis(1),
    };
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Address and port to listen on.
    pub listen: SocketAddr,
    /// Socket receive buffer to ask the OS for (`SO_RCVBUF`); `None` keeps
    /// the OS default. What the OS granted is in [`StartInfo`].
    pub recv_buffer_bytes: Option<usize>,
    /// Packet blocks in the pool, each [`BLOCK_BYTES`]; at most
    /// [`MAX_BLOCKS`]. Datagrams the stages have not finished with.
    pub blocks: usize,
    /// Decoder limits: hold limits, template timeout, withdrawals.
    pub wire: flowlanes_wire::Config,
    /// Pin each stage to its own core (socket 0, first core left to the
    /// OS). Falls back to unpinned when there are not enough cores.
    pub pin: bool,
    pub priority: Priority,
    pub idle: Idle,
}

impl Config {
    /// Defaults for `listen`. The numbers are starting points, not
    /// measured optima; every one is a field.
    pub fn new(listen: SocketAddr) -> Config {
        Config {
            listen,
            recv_buffer_bytes: Some(8 << 20),
            blocks: 256,
            wire: flowlanes_wire::Config::default(),
            pin: true,
            priority: Priority::Normal,
            idle: Idle::BACKOFF,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(&'static str, io::Error),
    Memory(stagelanes_mem::Error),
    Stage(stagelanes_pipe::Error),
    Config(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(what, e) => write!(f, "{what}: {e}"),
            Error::Memory(e) => write!(f, "packet pool: {e}"),
            Error::Stage(e) => write!(f, "{e}"),
            Error::Config(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for Error {}

/// The JSON lines of the records of one packet, as the output stage hands
/// them to a [`Sink`].
pub struct Chunk<'a> {
    /// When the receive stage got the packet.
    pub received: Instant,
    /// Number of lines.
    pub records: u32,
    /// Header sequence number of the packet the first record came from.
    pub sequence: u32,
    /// The lines, each ending in a newline.
    pub json: &'a [u8],
}

/// Where the lines go.
pub trait Sink: Send + 'static {
    fn write(&mut self, chunk: &Chunk<'_>) -> io::Result<()>;
    /// Called when the output stage has nothing more waiting, and at
    /// least every few hundred chunks. Records count as written only after
    /// this returns `Ok`.
    fn flush(&mut self) -> io::Result<()>;
}

/// A [`Sink`] that writes the lines to a file, pipe or any writer.
pub struct JsonLines<W: Write + Send + 'static>(pub io::BufWriter<W>);

impl<W: Write + Send + 'static> JsonLines<W> {
    pub fn new(w: W) -> Self {
        JsonLines(io::BufWriter::with_capacity(256 * 1024, w))
    }
}

impl<W: Write + Send + 'static> Sink for JsonLines<W> {
    fn write(&mut self, chunk: &Chunk<'_>) -> io::Result<()> {
        self.0.write_all(chunk.json)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Counters the stages update while running.
#[derive(Default)]
struct Shared {
    datagrams: AtomicU64,
    bytes: AtomicU64,
    recv_errors: AtomicU64,
    pool_empty_waits: AtomicU64,
    lines_written: AtomicU64,
    records_failed: AtomicU64,
    flushes: AtomicU64,
    wire: Mutex<Counters>,
    latency: Mutex<Histogram>,
}

/// A copy of every counter at one moment.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Datagrams read from the socket, and their bytes.
    pub datagrams: u64,
    pub bytes: u64,
    /// Socket reads that failed for a reason other than "nothing there".
    pub recv_errors: u64,
    /// Times the receive stage had to wait for a free block (the stages
    /// behind it were not keeping up).
    pub pool_empty_waits: u64,
    /// Datagrams the kernel dropped at the socket.
    pub socket_drops: SocketDrops,
    /// The decoder's counters, as last published by the decode stage.
    pub wire: Counters,
    /// Records flushed to the sink.
    pub lines_written: u64,
    /// Records decoded but not written: the sink returned an error.
    pub records_failed: u64,
    pub flushes: u64,
    /// Time from receipt to flush, per record.
    pub latency: Option<Latency>,
}

/// Latency in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Latency {
    pub count: u64,
    pub p50: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
}

impl Latency {
    pub fn of(h: &Histogram) -> Option<Latency> {
        Some(Latency {
            count: h.count(),
            p50: h.quantile(0.5)?,
            p99: h.quantile(0.99)?,
            p999: h.quantile(0.999)?,
            max: h.max(),
        })
    }

    pub fn json(&self) -> J {
        json!({
            "records": self.count,
            "p50_us": self.p50 as f64 / 1e3,
            "p99_us": self.p99 as f64 / 1e3,
            "p99_9_us": self.p999 as f64 / 1e3,
            "max_us": self.max as f64 / 1e3,
        })
    }
}

impl Snapshot {
    /// The R3 identity from socket to sink. Holds once the pipeline has
    /// stopped (while it runs, packets are in flight between stages):
    /// every datagram read reached the decoder, every data set is decoded,
    /// rejected or malformed, and every decoded record was written or
    /// counted as failed.
    pub fn balanced(&self) -> bool {
        self.datagrams == self.wire.packets
            && self.wire.sets_balance()
            && self.wire.records_out + self.wire.options_records_out
                == self.lines_written + self.records_failed
    }

    pub fn json(&self) -> J {
        let (drops, why) = match self.socket_drops {
            SocketDrops::Counted(n) => (json!(n), J::Null),
            SocketDrops::Unavailable(why) => (J::Null, json!(why)),
        };
        json!({
            "datagrams": self.datagrams,
            "bytes": self.bytes,
            "recv_errors": self.recv_errors,
            "pool_empty_waits": self.pool_empty_waits,
            "socket_drops": drops,
            "socket_drops_unavailable": why,
            "lines_written": self.lines_written,
            "records_failed": self.records_failed,
            "flushes": self.flushes,
            "latency_receipt_to_flush": self.latency.map(|l| l.json()),
            "decoder": json::counters_json(&self.wire),
        })
    }
}

impl Shared {
    fn snapshot(&self, port: u16) -> Snapshot {
        Snapshot {
            datagrams: self.datagrams.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            recv_errors: self.recv_errors.load(Relaxed),
            pool_empty_waits: self.pool_empty_waits.load(Relaxed),
            socket_drops: platform::socket_drops(port),
            wire: self.wire.lock().map(|c| c.clone()).unwrap_or_default(),
            lines_written: self.lines_written.load(Relaxed),
            records_failed: self.records_failed.load(Relaxed),
            flushes: self.flushes.load(Relaxed),
            latency: self.latency.lock().ok().and_then(|h| Latency::of(&h)),
        }
    }
}

/// What start-up found and set.
#[derive(Debug, Clone)]
pub struct StartInfo {
    pub local: SocketAddr,
    pub recv_buffer_asked: Option<usize>,
    /// `SO_RCVBUF` as the OS reports it after the request.
    pub recv_buffer_granted: usize,
    pub blocks: usize,
    /// Whether the pool's pages are locked in memory.
    pub pool_locked: bool,
    /// The core of each stage (receive, decode, encode, output), or `None`
    /// when unpinned.
    pub cpus: [Option<OsCpu>; 4],
    /// Why something asked for was not done (pinning, locking).
    pub notes: Vec<String>,
}

impl StartInfo {
    pub fn json(&self) -> J {
        json!({
            "listen": self.local.to_string(),
            "recv_buffer_asked": self.recv_buffer_asked,
            "recv_buffer_granted": self.recv_buffer_granted,
            "blocks": self.blocks,
            "block_bytes": BLOCK_BYTES,
            "pool_locked": self.pool_locked,
            "stage_cpus": self.cpus.iter().map(|c| c.map(|c| c.to_string())).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

struct Packet {
    block: Block,
    len: u32,
    src: IpAddr,
    received: Instant,
}

struct Decoded {
    received: Instant,
    records: Vec<Record>,
}

struct Lines {
    received: Instant,
    records: u32,
    sequence: u32,
    buf: Vec<u8>,
}

struct Idler {
    idle: Idle,
    polls: u32,
}

impl Idler {
    fn wait(&mut self, ctx: &mut StageCtx) {
        ctx.idle();
        if let Idle::Backoff { spins, sleep } = self.idle {
            if self.polls >= spins {
                std::thread::sleep(sleep);
            } else {
                self.polls += 1;
            }
        }
    }

    fn worked(&mut self, ctx: &mut StageCtx) {
        ctx.busy();
        self.polls = 0;
    }
}

/// A running collector.
pub struct Pipeline<S: Sink> {
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    info: StartInfo,
    receive: JoinHandle<(StageReport, SocketDrops)>,
    decode: JoinHandle<(StageReport, Counters)>,
    encode: JoinHandle<(StageReport, ())>,
    output: JoinHandle<(StageReport, S)>,
}

/// What a stopped collector hands back.
pub struct Report<S> {
    pub sink: S,
    pub snapshot: Snapshot,
    /// receive, decode, encode, output.
    pub stages: Vec<StageReport>,
}

fn bind(config: &Config) -> Result<(UdpSocket, usize), Error> {
    let socket = Socket::new(
        Domain::for_address(config.listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(|e| Error::Io("socket", e))?;
    if let Some(bytes) = config.recv_buffer_bytes {
        socket
            .set_recv_buffer_size(bytes)
            .map_err(|e| Error::Io("set receive buffer", e))?;
    }
    let granted = socket
        .recv_buffer_size()
        .map_err(|e| Error::Io("read receive buffer size", e))?;
    socket
        .bind(&config.listen.into())
        .map_err(|e| Error::Io("bind", e))?;
    match config.idle {
        Idle::Spin => socket.set_nonblocking(true),
        // Blocking reads; the timeout is how often the stage looks at the
        // stop flag.
        Idle::Backoff { .. } => socket.set_read_timeout(Some(Duration::from_millis(100))),
    }
    .map_err(|e| Error::Io("socket mode", e))?;
    Ok((socket.into(), granted))
}

fn pool(blocks: usize, notes: &mut Vec<String>) -> Result<BlockPool, Error> {
    let want = RegionConfig {
        large_pages: LargePages::Off,
        ..RegionConfig::new(blocks * BLOCK_BYTES)
    };
    let region = match Region::new(&want) {
        Ok(r) => r,
        Err(e) => {
            notes.push(format!("packet pool not locked in memory: {e}"));
            Region::new(&RegionConfig {
                lock: false,
                ..want
            })
            .map_err(Error::Memory)?
        }
    };
    BlockPool::new(region, BLOCK_BYTES).map_err(Error::Memory)
}

fn cores(pin: bool, notes: &mut Vec<String>) -> [Option<OsCpu>; 4] {
    if !pin {
        return [None; 4];
    }
    let topo = match Topology::detect() {
        Ok(t) => t,
        Err(e) => {
            notes.push(format!("stages not pinned: {e}"));
            return [None; 4];
        }
    };
    let mut plan = CorePlan::for_socket(&topo, 0);
    // Leave the first core to the OS when there is one to spare.
    if plan.left() > 4 {
        let _ = plan.take(1);
    }
    match plan.take(4) {
        Ok(c) => [Some(c[0]), Some(c[1]), Some(c[2]), Some(c[3])],
        Err(e) => {
            notes.push(format!("stages not pinned: {e}"));
            [None; 4]
        }
    }
}

impl<S: Sink> Pipeline<S> {
    /// Binds the socket, sets up the pool and starts the four stages.
    pub fn start(config: Config, sink: S) -> Result<Pipeline<S>, Error> {
        if config.blocks == 0 || config.blocks > MAX_BLOCKS {
            return Err(Error::Config("blocks must be between 1 and 4096"));
        }
        let mut notes = Vec::new();
        let (socket, granted) = bind(&config)?;
        let local = socket
            .local_addr()
            .map_err(|e| Error::Io("local address", e))?;
        let pool = pool(config.blocks, &mut notes)?;
        let pool_locked = pool.region_info().locked();
        let cpus = cores(config.pin, &mut notes);
        let info = StartInfo {
            local,
            recv_buffer_asked: config.recv_buffer_bytes,
            recv_buffer_granted: granted,
            blocks: pool.capacity(),
            pool_locked,
            cpus,
            notes,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared::default());
        let (mut pkt_tx, mut pkt_rx) = link::<Packet, LINK>();
        let (mut blk_tx, mut blk_rx) = link::<Block, MAX_BLOCKS>();
        let (mut dec_tx, mut dec_rx) = link::<Decoded, LINK>();
        let (mut line_tx, mut line_rx) = link::<Lines, LINK>();
        let (mut buf_tx, mut buf_rx) = link::<Vec<u8>, LINK>();
        let spec = |name: &str, cpu| StageSpec {
            name: format!("flowlanes-{name}"),
            cpu,
            priority: config.priority,
        };
        let idle = config.idle;

        let receive = {
            let (stop, shared) = (stop.clone(), shared.clone());
            spawn_stage(spec("receive", cpus[0]), move |ctx| {
                let mut pool = pool;
                let mut idler = Idler { idle, polls: 0 };
                let mut current: Option<Block> = None;
                let mut waiting = false;
                ctx.ready();
                while !stop.load(Relaxed) {
                    blk_rx.recv_with(MAX_BLOCKS, |b| {
                        let _ = pool.put(b);
                    });
                    if current.is_none() {
                        current = pool.take();
                    }
                    let Some(block) = current.as_mut() else {
                        // Every block is with a later stage: wait for one.
                        // Meanwhile the kernel queues, then drops.
                        if !waiting {
                            waiting = true;
                            shared.pool_empty_waits.fetch_add(1, Relaxed);
                        }
                        idler.wait(ctx);
                        continue;
                    };
                    waiting = false;
                    match socket.recv_from(block.as_mut_slice()) {
                        Ok((n, src)) => {
                            let received = Instant::now();
                            shared.datagrams.fetch_add(1, Relaxed);
                            shared.bytes.fetch_add(n as u64, Relaxed);
                            if let Some(block) = current.take() {
                                pkt_tx.send(Packet {
                                    block,
                                    len: n as u32,
                                    src: src.ip(),
                                    received,
                                });
                            }
                            idler.worked(ctx);
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            // Spin mode polls; blocking mode has already
                            // waited in the read.
                            ctx.idle();
                        }
                        Err(_) => {
                            shared.recv_errors.fetch_add(1, Relaxed);
                            idler.wait(ctx);
                        }
                    }
                }
                ctx.finish();
                // The kernel's count, read after the last read and before
                // the socket closes.
                platform::socket_drops(local.port())
            })
            .map_err(Error::Stage)?
        };

        let decode = {
            let shared = shared.clone();
            let wire = config.wire.clone();
            spawn_stage(spec("decode", cpus[1]), move |ctx| {
                let mut collector = flowlanes_wire::Collector::new(wire);
                let mut idler = Idler { idle, polls: 0 };
                let start = Instant::now();
                let mut unpublished = 0usize;
                let publish = |c: &Counters| {
                    if let Ok(mut w) = shared.wire.lock() {
                        w.clone_from(c);
                    }
                };
                ctx.ready();
                loop {
                    let got = pkt_rx.recv_with(64, |p: Packet| {
                        let bytes = &p.block.as_slice()[..p.len as usize];
                        let records = collector.decode(p.src, bytes, start.elapsed().as_secs());
                        blk_tx.send(p.block);
                        if !records.is_empty() {
                            dec_tx.send(Decoded {
                                received: p.received,
                                records,
                            });
                        }
                    });
                    match got {
                        None => break,
                        Some(0) => {
                            if unpublished > 0 {
                                publish(&collector.counters);
                                unpublished = 0;
                            }
                            idler.wait(ctx);
                        }
                        Some(n) => {
                            unpublished += n;
                            if unpublished >= 4096 {
                                publish(&collector.counters);
                                unpublished = 0;
                            }
                            idler.worked(ctx);
                        }
                    }
                }
                // Nothing more can arrive: data still waiting for a
                // template is rejected, and counted.
                collector.finish();
                publish(&collector.counters);
                ctx.finish();
                collector.counters
            })
            .map_err(Error::Stage)?
        };

        let encode = {
            let shared = shared.clone();
            spawn_stage(spec("encode", cpus[2]), move |ctx| {
                let mut free: Vec<Vec<u8>> =
                    (0..64).map(|_| Vec::with_capacity(32 * 1024)).collect();
                let mut idler = Idler { idle, polls: 0 };
                ctx.ready();
                loop {
                    let got = dec_rx.recv_with(64, |d: Decoded| {
                        buf_rx.recv_with(LINK, |b| free.push(b));
                        let mut buf = free.pop().unwrap_or_default();
                        buf.clear();
                        let mut records = 0u32;
                        for r in &d.records {
                            let before = buf.len();
                            if serde_json::to_writer(&mut buf, &json::record_json(r)).is_ok() {
                                buf.push(b'\n');
                                records += 1;
                            } else {
                                buf.truncate(before);
                                shared.records_failed.fetch_add(1, Relaxed);
                            }
                        }
                        line_tx.send(Lines {
                            received: d.received,
                            records,
                            sequence: d.records.first().map_or(0, |r| r.sequence),
                            buf,
                        });
                    });
                    match got {
                        None => break,
                        Some(0) => idler.wait(ctx),
                        Some(_) => idler.worked(ctx),
                    }
                }
                ctx.finish();
            })
            .map_err(Error::Stage)?
        };

        let output = {
            let shared = shared.clone();
            spawn_stage(spec("output", cpus[3]), move |ctx| {
                let mut sink = sink;
                let mut pending: Vec<(Instant, u32)> = Vec::with_capacity(1024);
                let mut idler = Idler { idle, polls: 0 };
                let flush = |sink: &mut S, pending: &mut Vec<(Instant, u32)>| {
                    if pending.is_empty() {
                        return;
                    }
                    shared.flushes.fetch_add(1, Relaxed);
                    let ok = sink.flush().is_ok();
                    let now = Instant::now();
                    if ok && let Ok(mut h) = shared.latency.lock() {
                        for &(t, n) in pending.iter() {
                            h.record_n(now.duration_since(t).as_nanos() as u64, u64::from(n));
                        }
                    }
                    let records: u64 = pending.drain(..).map(|(_, n)| u64::from(n)).sum();
                    if ok {
                        shared.lines_written.fetch_add(records, Relaxed);
                    } else {
                        shared.records_failed.fetch_add(records, Relaxed);
                    }
                };
                ctx.ready();
                loop {
                    let got = line_rx.recv_with(64, |l: Lines| {
                        let chunk = Chunk {
                            received: l.received,
                            records: l.records,
                            sequence: l.sequence,
                            json: &l.buf,
                        };
                        match sink.write(&chunk) {
                            Ok(()) => pending.push((l.received, l.records)),
                            Err(_) => {
                                shared
                                    .records_failed
                                    .fetch_add(u64::from(l.records), Relaxed);
                            }
                        }
                        // Give the buffer back if there is room; the
                        // encode stage makes a new one otherwise.
                        if buf_tx.free() > 0 {
                            buf_tx.send(l.buf);
                        }
                    });
                    match got {
                        None => break,
                        Some(0) => {
                            flush(&mut sink, &mut pending);
                            idler.wait(ctx);
                        }
                        Some(_) => {
                            if pending.len() >= 512 {
                                flush(&mut sink, &mut pending);
                            }
                            idler.worked(ctx);
                        }
                    }
                }
                flush(&mut sink, &mut pending);
                ctx.finish();
                sink
            })
            .map_err(Error::Stage)?
        };

        Ok(Pipeline {
            stop,
            shared,
            info,
            receive,
            decode,
            encode,
            output,
        })
    }

    pub fn info(&self) -> &StartInfo {
        &self.info
    }

    /// The counters now. While running, the decoder's part lags by up to
    /// 4,096 packets under load.
    pub fn snapshot(&self) -> Snapshot {
        self.shared.snapshot(self.info.local.port())
    }

    /// Forgets the latency recorded so far (for a warm-up).
    pub fn reset_latency(&self) {
        if let Ok(mut h) = self.shared.latency.lock() {
            h.clear();
        }
    }

    /// Stops reading the socket, lets every stage finish what it has, and
    /// returns the sink and the final counters.
    pub fn stop(self) -> Report<S> {
        let port = self.info.local.port();
        self.stop.store(true, Relaxed);
        let (r, drops) = self.receive.join().expect("receive stage panicked");
        let (d, wire) = self.decode.join().expect("decode stage panicked");
        let (e, ()) = self.encode.join().expect("encode stage panicked");
        let (o, sink) = self.output.join().expect("output stage panicked");
        let mut snapshot = self.shared.snapshot(port);
        snapshot.socket_drops = drops;
        snapshot.wire = wire;
        Report {
            sink,
            snapshot,
            stages: vec![r, d, e, o],
        }
    }
}
