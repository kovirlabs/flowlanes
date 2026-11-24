# flowlanes specification

Date: 2026-11-22. Status: DRAFT. Name (`flowlanes`), licence (Apache-2.0)
and the flow source (UniFi IPFIX to this PC on UDP 2055) are decided.
Items marked TBD are open decisions for
Evan. Items marked "verify in M0" are from memory or one web search and
must be checked against current documentation before code depends on them.

## 1. Purpose

Routers and gateways export summaries of the connections they carry:
NetFlow and IPFIX. `flowlanes` collects them and treats them as security
data. It has two halves:

1. **A collector:** receive, decode, enrich and write flow records without
   losing any silently.
2. **An anomaly engine:** detectors that read the flow stream and raise
   explained alerts: scans, new talkers, unusual volume, beaconing.

It feeds Wazuh first. Wazuh has no NetFlow module; it takes network device
data as syslog or JSON logs. `flowlanes` writes JSON events and ships the
Wazuh decoders and rules for them. The output is plain JSON lines, so
Elastic, Security Onion, Zabbix or `rulelanes` can read it too.

## 2. Why this should work

- Flow records are small and arrive at high rates, and the work per record
  is parse, look up, add to a counter. That is the `stagelanes` pipeline
  shape measured in M6
  (`../paralanes/atlas/runs/ryzen/2026-11-22-pipeline-3.json`).
- Beaconing is periodic traffic, and a periodicity test is a spectrum.
  `bytelanes` has a byte-exact fixed-point FFT with a CPU reference. The
  CPU reference is used first; the GPU is used only if a run shows the
  batch is large enough (`../paralanes/atlas/crossover.md`: 16 frames of
  4,096 samples on the Ryzen).

## 3. Requirements

| # | Requirement | How it is tested |
| --- | --- | --- |
| R1 | Decoding is correct | Golden vectors per protocol version, built from the RFCs; property tests that encode generated records and decode them back; the same packets decoded by an existing open collector give the same field values |
| R2 | Templates are handled as the RFCs say | Templates are kept per exporter address, observation domain (or source ID) and template ID; a template can be replaced or withdrawn (correction, M1: RFC 7011 §8.4 says UDP collectors MUST ignore withdrawals, so they are counted and ignored by default and applied only when configured); data that arrives before its template is held up to a limit, then counted as rejected; options templates are decoded |
| R3 | No silent loss | Per-exporter sequence gaps, malformed packets, records without a template and socket receive drops are counted and exposed. Records in equals records out plus counted rejects. Without its template the number of records in a data set is unknown, so the decode-side identity is kept per data set (sets in = decoded + rejected + malformed + held) and per record for v5 (M1). M2: end to end, datagrams read = packets decoded and records decoded = records written + records the output refused. Socket receive drops are read per socket on Linux; Windows gives no count, and there the loss shows only as sequence gaps (`docs/status/M2.md`) |
| R4 | Unknown fields are kept | An information element the decoder does not know, including enterprise elements, passes through as its ID and raw bytes |
| R5 | Throughput and latency are measured | Generated load at rising rates; records per second and p99 from receipt to output, in a run file. M2: `runs/ryzen/2026-11-23-collector*.json`, loopback; latency is also taken from the scheduled send time, so time queued in the socket counts |
| R6 | Wazuh raises alerts from it | With the pack installed in the Wazuh container, `wazuh-logtest` decodes every event type and the expected rule fires; one end-to-end run shows a detector alert in Wazuh's `alerts.json` |
| R7 | Detectors are deterministic and explained | The same input gives the same alerts. Each alert carries detector, evidence and threshold. Each detector passes labelled generated scenarios, both attack and benign |
| R8 | False alerts are measured | Each detector's alert count over a recorded period of normal traffic is reported, per day, before its default threshold is fixed. The traffic itself is not committed |
| R9 | Baselines are learned and survive a restart | Per-host baselines are built from traffic, saved, and reloaded; a restart does not re-learn from nothing or re-alert on known hosts |
| R10 | Windows and Linux from one tree | CI builds and tests both. OS-specific code only in `platform` modules |

## 4. Protocols

| Protocol | Reference | Milestone |
| --- | --- | --- |
| IPFIX (version 10) | RFC 7011, IANA IPFIX Information Elements | M1; what Evan's gateway will send (decided). That IPFIX is UniFi's *default* was not confirmed in M0 (`docs/unifi.md`) |
| NetFlow v9 | RFC 3954 | M1 |
| NetFlow v5 | Cisco's fixed format | M1 |
| sFlow v5 | sflow.org | M6 |

Transport is UDP first, default port 2055 (decided). IPFIX over TCP and
SCTP is not planned.

M0 records exactly what the UniFi gateway exports: version, template
fields, enterprise elements, active and inactive timeouts, sampling, and
whether the switches export at all or only the gateway. M0 result
(`docs/unifi.md`, from documentation only): v10, v9 and v5 are offered;
sampling is off by default; the active timeout is 5 minutes; templates are
re-sent every 20 packets; UniFi switches do not export flows; the template
field list and any enterprise elements are not publicly documented.
Observed on Evan's gateway on 2026-11-23 (`docs/unifi.md`,
`docs/status/ops-unifi-live.md`): IPFIX, IPv4 only, IANA elements only (no
enterprise elements, no NAT elements), template layouts that depend on the
sampling setting, sampling on (1 out of 512) until Evan switched it off,
and templates re-sent more often the more the gateway exports.

## 5. Architecture

```
UDP ──► receive ──► decode ──► enrich ──► aggregate ──► detect ──► output
        (socket,    (templates, (direction, (per-host     (detectors, (JSON
         batches)    records)    local or    and per-pair   baselines)  lines)
                                 remote,     windows)
                                 service)
```

- One pinned thread per stage, `stagelanes-pipe` links, pooled blocks.
- Template state belongs to the decode stage alone. With more than one
  decode worker, packets are routed by exporter so a template and its data
  meet in the same worker.
- Aggregation keeps fixed-size windows per internal host and per
  host-to-destination pair. Detectors read windows, not single records.
- Output writes two event kinds: `flow` (optional, for search) and `alert`.
- M2 has four stages: receive, decode, encode (JSON lines) and output.
  Enrich, aggregate and detect come with M4.

### Crates

| Crate | Holds |
| --- | --- |
| `flowlanes-wire` | Packet and record decoding for v5, v9 and IPFIX; the element registry; template store. `no_std` where practical (M1: uses `std` collections; no I/O) |
| `flowlanes-gen` | Generated export packets: valid traffic, attack scenarios, malformed packets. Used by tests and load runs |
| `flowlanes-detect` | Windows, baselines and detectors. Pure functions over records; no I/O |
| `flowlanes-pipe` | The staged collector on `stagelanes` |
| `flowlanes-bench` | Load runs; writes run files |
| `flowlanes` | CLI: `decode`, `generate`, `collect`, later `serve` |
| `wazuh/` | The Wazuh pack: decoders, rules, and install notes (not a crate) |

## 6. Detectors

Each is a reference implementation in `flowlanes-detect` with its
scenarios. Defaults are set only after R8 is measured.

| Detector | Signal | Milestone |
| --- | --- | --- |
| Horizontal scan | One source reaches many hosts on one port in a window | M4 |
| Vertical scan | One source reaches many ports on one host in a window | M4 |
| New talker | An internal host appears that the baseline has not seen | M4 |
| New destination | An internal host contacts an external address, or a port, outside its baseline | M4 |
| Volume | Bytes out from a host far above its own baseline for that hour | M4 |
| Fan-out | An internal host opens SMB, RDP or SSH to many internal hosts | M4 |
| Beaconing | Flows from a host to one destination at a regular interval, found as a peak in the spectrum of the arrival series | M5 |
| Long-lived flow | A connection kept open far longer than the host's baseline | M5 |
| Tunnel volume | DNS or ICMP bytes per host far above baseline | M5 |

Limits to state plainly in the README: flow records carry no payload, so
these detectors see behaviour, not content; sampled export weakens every
one of them; and encrypted DNS hides the tunnel signal.

## 7. Wazuh integration

- The collector writes JSON lines to a file. The Wazuh manager (or an
  agent) reads the file through log collection with the JSON format
  (checked in M0: `<localfile>` with `<log_format>json</log_format>` reads
  single-line JSON files and `location` takes wildcards; how the file on the
  Windows host reaches the manager container, bind mount or host agent, is
  decided in M3; see `docs/landscape.md`).
- The pack holds a rule for each alert kind, with levels, groups and MITRE
  ATT&CK IDs where one applies, and low-level rules for `flow` events.
- R6 is checked with `wazuh-logtest`, the same oracle `rulelanes` uses.

## 8. Milestones

| M | Title | Gate |
| --- | --- | --- |
| M0 | Setup and landscape | `docs/landscape.md` covers existing collectors (goflow2, pmacct, nfdump, Akvorado, ntopng, ElastiFlow), Rust decoding crates with their licences, and existing Wazuh or Security Onion NetFlow integrations, with a go or no-go and a build-or-reuse decision for decoding; `docs/unifi.md` records how export is enabled and what it sends |
| M1 | Wire decoding and generator | R1, R2, R3 (decode-side counts) and R4 pass; `flowlanes decode` turns a file of packets into JSON lines; `flowlanes generate` writes packets for every protocol version |
| M2 | Staged collector | The collector receives UDP and writes JSON lines; R3 passes end to end; R5 is measured |
| M3 | Wazuh pack | R6 passes on the Docker Wazuh |
| M4 | Anomaly engine v1 | The six M4 detectors pass R7; R8 is measured on Evan's network; R9 passes |
| M5 | Beaconing and the rest | The M5 detectors pass R7 and R8; the FFT batch size is measured before any GPU use |
| M6 | More inputs and outputs | sFlow; a metrics output for Zabbix or Prometheus (TBD which) |

## 9. Risks

| Risk | Effect | Answer |
| --- | --- | --- |
| A good Rust decoding crate already exists | Building our own wastes time | M0 decides build or reuse, on licence, correctness against the vectors, and allocation behaviour |
| The gateway exports sampled or sparse fields | Detectors are weak on this network | M0 records what arrives; the README states the limit |
| Home traffic gives too few flows to measure throughput | R5 cannot use real traffic | The generator provides load; real traffic is for R8 only |
| Baseline detectors alert too often | The tool is ignored | R8 comes before defaults; every alert carries its evidence |
| UDP reaches a Windows host process but not a container cleanly | Integration friction | The collector runs natively; only its output file reaches Wazuh |

## 10. Out of scope

Packet capture and payload inspection (Zeek and Suricata do that), a flow
database or dashboard of its own, and blocking traffic.
