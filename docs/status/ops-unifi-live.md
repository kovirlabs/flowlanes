# ops-unifi-live: the collector on the real UniFi export
Machine: Ryzen 7 5700X desktop (Windows 11 Home build 26300, rustc 1.99.1)   Date: 2026-11-23

Not a milestone. Branch `ops-unifi-live`, cut from `m2-staged-collector`
(PR #3). The collector was built against generated packets only; from
19:39 local the real gateway exported to it. This branch records what the
gateway sends, fixes what flowlanes got wrong, and states what is now
confirmed. No capture, record, address, MAC address or name from the
network is in this branch; the export is described by structure only.

**Flow records from the gateway decode end to end**: in every window below
every datagram was IPFIX, every data set decoded (none rejected, held at
the end, or malformed), every decoded record was written, and the only
sequence event was the gateway restarting its export when sampling was
switched off. Before this branch 16 of the gateway's elements came out as
unnamed raw bytes and its interface names carried NUL padding; and data
that arrived before its template (the first minutes after every collector
start) would have been rejected after 60 s.

## Built

- **Element names** (`flowlanes-wire/src/ie.rs`): the 16 IANA elements the
  gateway sends that the table lacked: 40, 41, 42, 82, 83, 163, 209, 256,
  300, 302, 309, 310, 318, 319, 390, 395. Names and types from the IANA
  registry CSV fetched 2026-11-23.
- **NUL padding cut from strings** (`decode_value`): the gateway's string
  elements are fixed-length and NUL-padded; trailing NULs are cut, a NUL
  inside the text is kept, non-UTF-8 stays raw bytes.
- **`collect --log-templates`**: a `template` event on stderr for every
  template that is new or arrives with a different layout (fields in
  order with ID, PEN, length, IANA name). It carries no exporter address.
  In `flowlanes-wire` behind `Config::report_templates` (off by default).
- **Hold default 60 s -> 900 s** (`Config::hold_max_age_secs`,
  `--hold-secs`): see Deviations.
- **`flowlanes-gen::unifi`**: both template sets the gateway used, with
  generated values only (documentation addresses, locally administered
  MACs); `traffic` (sampling off, flows split by protocol over 258/259/260)
  and `traffic_sampled`; `flowlanes generate --kind unifi`.
- **Tests** (`crates/flowlanes-gen/tests/unifi.rs`): every gateway element
  named; NUL padding; template change reporting; the sampled export as it
  arrives after a collector start (options data minutes before its
  templates) decodes with nothing lost under the new default and is
  partly rejected under the old one; the unsampled export; the switch
  between them (IDs reused with new layouts, sequence restart). A JSON
  test that the template event has no address.
- The goflow2 R1 cross-check now also sends both gateway layouts.

## Observed export

Full layouts, rates and timing are in `docs/unifi.md`. In short, over
19:35-20:32 local (2026-11-23):

- IPFIX only, one exporter, observation domain 0, IPv4 only, **IANA
  elements only: no enterprise (PEN) elements**, no NAT elements.
- **Two template sets, chosen by the sampling setting.** Sampling on
  (19:35-19:53; "hash" in Evan's UI): five options templates (domain
  info, sampling configuration, interface table, export counters,
  selector counters) and flow templates 261 (TCP) and 262 (UDP), each
  carrying selectorId. Sampling off (from 19:54): the gateway restarted
  its export (sequence from 0), reused IDs 257-261 with new layouts:
  interface table, TCP flows with tcpOptions, TCP/UDP flows without,
  ICMP flows, export counters.
- **Sampling** while on: flowSelectorAlgorithm 3 (Random n-out-of-N),
  1 out of 512, per the gateway's own options records; the UI said "hash".
  Flow records: 3 in 10 minutes and 4 in 7 minutes sampled; 429 to 480 a
  minute unsampled (19:54-20:32), in datagrams of about 1,350 bytes,
  about 23 a minute.
- **Options data** every 60 s (counters) and every 300 s (domain info,
  sampling configuration, interface table) while sampled.
- **Template re-sends**: every 5 minutes while sampled and nearly idle; 3
  to 9 template re-sends a minute unsampled. Fits a packet-count rule
  ("20 packets" in the UI) but that is inferred.
- **Active timeout about 30 minutes**: the 16 records that ended by
  active timeout lasted 1,785 to 1,801 s.
- **flowDirection is 255 in every record** (17,708 records), a value the
  IANA registry does not define.
- **Nothing rejected, held at the end, malformed or expired; no sequence
  gap**; one out-of-order sequence at the sampling switch.

Which sampling mode each window was taken under, as far as the options
records tell: 19:35-19:53 sampled (template 257 present, algorithm 3,
1/512, every 300 s; last seen 19:52); from 19:53:49 no sampling template
or selector element in any template, so unsampled. That Evan switched to
"off" (and not to another mode without options) is inferred from this
and the flow rate, not confirmed by him.

## Gate results

check | result | command that produced it
--- | --- | ---
Live: the gateway's export is received on `0.0.0.0:2055` from another host through the Windows firewall | pass: 941 datagrams from one non-loopback exporter, 19:39-20:32 | `flowlanes collect --out captures/... --stats-secs 60 --no-pin` (first run), then `flowlanes collect --out captures/unifi-2026-11-23-b.jsonl --stats-secs 60 --no-pin --log-templates --hold-secs 3600`
Live: flow records decode end to end | pass: 17,546 flow and 326 options records decoded and written (17,872 lines) by 20:32; every data set decoded; `sets_balance: true`; no element left unnamed in the second run | same; counters in the stats log; structure checked with a script that prints no values
Live: no loss | pass: 0 malformed, 0 rejected, 0 expired, 0 sequence missing; 1 out-of-order (export restart) | same
Clean Ctrl-C: flush and final counters | pass: in its own console, Ctrl-C stopped the collector in 0.09 s with exit code 0, `collector_stop` printed, `balanced: true`, 205 lines written for 36 packets (the M2 count) | `flowlanes collect --listen 127.0.0.1:2056 --out ... --stats-secs 0 --no-pin`, `flowlanes generate --kind mix --seed 7 --udp 127.0.0.1:2056`, then CTRL_C_EVENT to that console (test harness in Python, not in the repo)
Gateway-shaped packets decode (both layouts, the switch, the start-up order) | pass, 6 tests | `cargo test -p flowlanes-gen --test unifi`
Template event names no address | pass | `cargo test -p flowlanes-pipe template`
R1 cross-check against goflow2 v2.2.7, now with both gateway layouts | pass: 447 records from each side, equal | `cargo test -p flowlanes --test r1_goflow2 -- --nocapture` (Docker Desktop running)
fmt, clippy, tests | pass | `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `FLOWLANES_SKIP_LIVE=1 cargo test --workspace`
Linux type-check | pass | `cargo check --workspace --all-targets --target x86_64-unknown-linux-gnu`
Each commit builds on its own | not checked: the worktree check failed to load the `../stagelanes` path dependency from a scratch directory; only the branch head was built and tested | —

## Deviations and corrections

- **Hold default changed, template timeout not.** RFC 7011 §8.4 suggests
  a template lifetime of at least 3 times the observed re-send interval.
  The longest re-send interval seen was 300 s (sampled, nearly idle), so
  the 1,800 s template timeout is 6 times that and stays. The hold limit
  for data without a template was 60 s, shorter than that interval: after
  every collector start (this PC starts at 9am daily) the first minutes of
  options data, and flows when the export is quiet, were rejected. It is
  now 900 s, 3 times the interval; `hold_max_sets` (256 per exporter)
  stays, since 256 sets is minutes of the busiest export seen. Both are
  from under one hour of observation on one evening, with the export
  changing setting in the middle; they are defaults, configurable, and
  should be revisited after a full day.
- **The first live collector was stopped with `Stop-Process`** (no final
  counters) at 19:45:55 to run the new build; collection resumed at
  19:45:58. Its capture file is kept. The collector left running
  (`target\live\run\flowlanes-live.exe`, a copy of a release build of
  this branch before the hold-default and generator commits) uses
  `--hold-secs 3600 --log-templates` and writes
  `captures\unifi-2026-11-23-b.jsonl` and `.stats.log`.
- **Template IDs reused with new layouts.** When sampling was switched off
  the gateway gave IDs 257-261 new layouts. flowlanes replaces a template
  when its new layout arrives; data for a reused ID that arrived before
  the new template would be decoded with the old layout and could not be
  told apart. The gateway sent the new templates first, so this did not
  happen; nothing detects it. Not changed (see questions).
- **Scope of unnamed elements in JSON**: an options record's `scope` list
  names only known elements. All the gateway's scope elements are now
  known, so nothing is lost for it; an unknown scope element would still
  appear in `unknown` without being marked as scope. Not changed.
- **Sampling is not applied to counts.** Records carry selectorId, and the
  1/512 configuration is decoded, but nothing scales packet or byte counts.
  Detectors must not run on sampled export (SPEC §6).
- `ie.rs` was said to list 53 elements in M1; it lists 52 plus the 16
  added here, 68 in all.

## Open questions for Evan

1. **Sampling.** Is sampling now off on purpose (the export says so since
   19:54)? The detectors need it off. The UI said "hash" while the export
   reported algorithm 3, random 1 out of 512; if you can, note which mode
   gives which, for `docs/unifi.md`.
2. **Active timeout.** Records that ended by active timeout lasted about
   30 minutes. Is the UI's "timeout rate" set to 30 minutes, or is that
   what "5 minutes (default)" really does? The long-lived-flow detector
   (M5) depends on it.
3. **flowDirection 255** in every record: does the UI have a direction
   setting? Without it, direction must come from interfaces or addresses
   (M4 enrichment).
4. **Template ID reuse.** Should the collector drop an exporter's
   templates when it sees the export restart (sequence going back, or a
   changed systemInitTimeMilliseconds in template 256), so data for a
   reused ID is held instead of misread? Not seen to matter today.
5. **Hold default 900 s** and template timeout 1,800 s: keep, or revisit
   after a day of data? This PC's daily start at 9am is when the hold
   limit matters.
6. **Collector as a service.** The collector now running stops at 9:30pm
   with the PC and does not restart; M2 question 7 stands.

## Requests for other repos

None.
