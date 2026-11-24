# flowlanes

A network flow collector with an anomaly engine, in Rust. It receives
NetFlow v5, NetFlow v9 and IPFIX, decodes and enriches flow records on
pinned `stagelanes` stages, runs security detectors over them, and writes
JSON events. A Wazuh decoder and rule pack turns those events into Wazuh
alerts.

Read `docs/SPEC.md` before any change. It is the source of truth. The
background is `../paralanes/docs/ROADMAP.md` (project 3).

> DRAFT. Items marked TBD are open decisions for Evan.

## Repo map

| Repo | Role | Used here as |
| --- | --- | --- |
| `flowlanes` (this repo) | Decoder library, collector, detectors, Wazuh pack | — |
| `../stagelanes` | Pinned stages, rings, pinned memory | Path dependency, read-only. `stagelanes-pipe` is on `main` |
| `../bytelanes` | The fixed-point FFT, for beaconing detection (M5) | Path dependency, read-only |
| `../rulelanes` | Decode-and-match engine; a consumer of this repo's events | Sibling; no code dependency |
| `../paralanes` | Roadmap and the measurements this design rests on | Read-only |

Never edit `stagelanes`, `bytelanes`, `diagsteno` or `paralanes` from here.
If this repo needs a change in one of them, write it under Requests in the
status file and stop that task.

## Hard rules

- **Agents push their own branches and open pull requests without asking.**
  The remote is `kovirlabs/flowlanes`. Never push to `main`.
- **Agents merge a pull request only when Evan asks for that merge.** They
  never tag or publish.
- **Run files carry no local paths.** A recorded command names the program,
  not the directory it ran from, so no user name reaches the repo.
- **One milestone per session unless Evan says otherwise.** Stop at the
  gate.
- **Decoding follows the RFCs and is cross-checked.** NetFlow v9 is RFC
  3954 and IPFIX is RFC 7011 with the IANA element registry. Every decoder
  has golden vectors, and decoded records are compared with an existing
  open collector on the same bytes.
- **No silent loss.** Sequence gaps, records without a template, malformed
  packets and socket drops are each counted and reported. Records in
  equals records out plus counted rejects.
- **Network data is private.** Real captures and flow records from Evan's
  network, or any real network, are never committed, never sent to an
  outside service and never pasted into a status file. Tests use generated
  flows. `captures/` is in `.gitignore`.
- **Detectors are deterministic and explained.** Every alert names the
  detector, the evidence (counts, hosts, ports, window) and the threshold
  it crossed. Every detector has labelled generated scenarios, including
  ones that must not alert.
- **No unmeasured numbers.** A performance or detection-rate figure appears
  only with the run file that produced it. Every run file records machine,
  OS and build number, Rust version and the exact command.
- **A negative result is a result.**
- **Measure, don't hard-code.** Baselines are learned per host from
  traffic. Detector thresholds are configuration with documented defaults,
  not constants buried in code.
- **`unsafe` is forbidden** (`#![forbid(unsafe_code)]` in every crate).
- **No `#[cfg(target_os)]`** outside a module named `platform`.
- **Look up current docs** before using any crate API, the RFCs, the IANA
  registry, UniFi settings, Wazuh syntax or Docker images. Do not write
  them from memory.
- **Licence compatibility.** This repo is Apache-2.0 (decided). Every new
  dependency must be MIT, Apache-2.0, BSD, ISC, Zlib or MPL-2.0. No GPL or
  LGPL dependencies. No Wazuh content is copied in; the Wazuh pack is
  written here.
- Crates carry `publish = false` until Evan removes it.

## Status files

Each milestone writes `docs/status/M<n>.md`:

```markdown
# M<n>: <title>
Machine: <name>   Date: <YYYY-MM-DD>
## Built
## Gate results
<check> | pass/fail | command that produced it
## Open questions for Evan
## Requests for other repos
```

Run files go in `runs/<machine>/<YYYY-MM-DD>-<name>.json`. Do not edit a
run file after it is committed.

## Branches

- `main` is Evan's. Work on `m<n>-<short-topic>`.
- Small commits, one logical change each. Run fmt, clippy and tests before
  each commit.

## Commands

```
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p flowlanes -- decode <file>        # decode a file of export packets to JSON lines
cargo run -p flowlanes -- generate --help      # generated export packets for tests and load
cargo run --release -p flowlanes -- collect --out <file>   # receive UDP 2055, write JSON lines
cargo run --release -p flowlanes-bench -- --machine <name> --machine-desc <text>   # R5 load run, writes a run file
```

## Machines and network

- First build machine: the Ryzen 7 5700X desktop (Windows 11, Docker
  Desktop). Tail latency figures from Windows are provisional.
- Flow source: Evan's UniFi gateway, which will export IPFIX to this PC on
  UDP 2055 (decided 2026-11-22; 2055 is the collector's default port).
  Flow data from his network is never committed and is used only to
  measure false-alert rates (R8). Pointing the gateway at
  this machine is Evan's action; agents do not change network equipment.

## Open decisions (TBD)

- GitHub owner (decided 2026-11-22: the name `flowlanes` is final, the
  licence is Apache-2.0, the gateway exports IPFIX to this PC on UDP 2055)
- Whether status and run files move to `paralanes` like the other repos'
- Whether enrichment may use an offline GeoIP or ASN database, and which
