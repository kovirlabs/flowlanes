# Landscape: flow collectors, decoding crates and Wazuh integrations

Checked 2026-11-22 (M0). Facts carry their source. **[NV]** marks what could
not be verified from a primary source.

## Summary and decisions

- **Go.** No Wazuh NetFlow/IPFIX integration exists (Wazuh's own answer is
  that it does not support NetFlow); Security Onion takes flows only through
  Elastic's NetFlow integration. A collector that writes explained security
  events as JSON lines, with a Wazuh pack, fills a gap.
- **Decoding: build, with a cross-check.** `netflow_parser` (MIT OR
  Apache-2.0) is mature and covers v5/v9/IPFIX, template scoping, options
  templates and unknown fields, so "reuse" was a real option. We build
  `flowlanes-wire` anyway because: (1) the M2 pipeline needs decoding into
  pooled blocks with no per-record allocation and per-exporter counters for
  R3 (sequence gaps, records without template, held-then-rejected records),
  which the crate does not expose as such [NV for its internals]; (2) the
  decode stage must own template state and its limits (R2's "held up to a
  limit, then counted"); (3) the format is small (RFC 3954 and RFC 7011 §3,
  §8). `netflow_parser` is kept as a candidate second decoder for tests if
  goflow2 proves unsuitable. This is a judgement call; Evan may prefer reuse.
- **Cross-check collector for R1: goflow2** (`netsampler/goflow2`,
  BSD-3-Clause, Docker Hub image, JSON on stdout by default, NetFlow v5/v9
  and IPFIX). The generated packets are sent to it over UDP on the Docker
  network and its JSON is compared field by field (M1).

## Existing collectors

| Collector | Language | Licence | Latest release | Protocols | Output | Docker | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| goflow2 | Go | BSD-3-Clause | v2.2.7, 2026-09-30 | NetFlow v5, v9, IPFIX, sFlow v5 | JSON on stdout by default; protobuf with `-format=bin`; file or Kafka transports | `netsampler/goflow2` | Listens with `-listen 'netflow://:2055'`; custom fields through `-mapping`; experimental ReFlow reads pcap |
| pmacct (nfacctd) | C | GPL-2.0 with ISC parts | v1.7.9, 2024-08-01 (repo active 2026-11) | NetFlow, IPFIX, sFlow | print plugin with `print_output: json`, others | `pmacct/nfacctd` | Can read a pcap (`pcap_savefile`) |
| nfdump / nfcapd | C | BSD-3-Clause | v1.7.10, 2026-09-07 | v1, v5, v7, v9, IPFIX; sFlow via sfcapd | text, CSV, JSON | no official image | pcap input only when built with `--enable-readpcap` |
| Akvorado | Go | AGPL-3.0 | v2026.10.1, 2026-10-25 | NetFlow/IPFIX, sFlow | ClickHouse (with Kafka) | compose stack | A full flow analytics stack, not a decoder |
| ntopng / nProbe | C/Lua; nProbe commercial | ntopng GPL-3.0; nProbe proprietary | ntopng 7.0, 2026-09-22 | NetFlow, IPFIX, sFlow (nProbe) | JSON export in paid tiers | `ntop/nprobe` (needs a licence) | |
| ElastiFlow | [NV] | proprietary (free community tier) | ~7.21.4 [NV] | NetFlow, IPFIX, sFlow | Elasticsearch, OpenSearch, Kafka, Splunk, stdout | `elastiflow/flow-collector` | |
| Logstash netflow codec | Ruby | [NV] | v4.3.4, 2026-02-11 | v5, v9, IPFIX | Logstash events | with Logstash | Custom field definitions in YAML |
| Elastic Agent "NetFlow Records" | Go (Beats) | Elastic licence [NV] | 2.25.1 | v1, v5, v6, v7, v8, v9, IPFIX | Elasticsearch | with Elastic Agent | Undefined vendor fields can cause parse errors (its own docs) |
| vflow | Go | Apache-2.0 | last push 2024-08-22 | IPFIX, sFlow, NetFlow | Kafka/NSQ | | Dormant |

## Rust decoding crates

| Crate | Licence | Latest | Protocols | Templates and fields |
| --- | --- | --- | --- | --- |
| `netflow_parser` | MIT OR Apache-2.0 | 1.0.6, 2026-07-23 | v5, v7, v9, IPFIX | Scoped by (source address, source ID / observation domain); options templates; vendor enterprise IEs and registration of custom ones; unknown fields returned as raw bytes (`parse_unknown_fields`, on by default); RFC 7011 §8.1 withdrawals supported. no_std not mentioned |
| `netgauze-flow-pkt` | Apache-2.0 | 0.14.0, 2026-11-10 | v9, IPFIX | IEs generated from an IANA registry snapshot; serialises and parses; template scoping and withdrawal not documented [NV] |
| `ipfixrw` | MIT | 0.1.0, 2023-03-15 | IPFIX | Stale |
| `ipfix` | [NV] | 0.1.1, 2018 | IPFIX | Abandoned |
| `flowparser-sflow` | MIT OR Apache-2.0 | 0.3.0, 2026-03-16 | sFlow v5 | For M6 |
| `netflow_generator` | [NV] | 0.2.8 | v5, v7, v9, IPFIX generation | Same author as `netflow_parser` |

Others found and not evaluated: `packet-dissector-ipfix` 0.6.3,
`netflow_analyzer_core` 0.3.0, `ipfix-parser` 0.2.0.

## Wazuh and Security Onion

- **Wazuh:** no NetFlow or IPFIX module, document or community decoder was
  found. A Wazuh team reply on the mailing list says Wazuh is a host IDS and
  does not support NetFlow. Wazuh reads a JSON-lines file through
  `<localfile>` with `<log_format>json</log_format>` ("used for single-line
  JSON files"); `location` accepts wildcards on Linux and Windows. That is
  the integration path for SPEC §7 (checked; it answers the spec's
  "verify in M0" on `localfile`). How the file on the Windows host reaches
  the manager container is a bind mount or a Wazuh agent on the host; to
  be decided in M3.
- Related third-party work: Alertflex/Altprobe streams NetFlow beside Wazuh
  alerts; ntopng can ingest Wazuh alerts (the other direction). No
  "wazuh netflow" project was found.
- **Security Onion:** ingests flows through the Elastic Agent "NetFlow
  Records" integration added in Fleet (UDP 2055 by default, host changed
  from localhost to 0.0.0.0, firewall host and port groups opened, NetFlow
  dashboard). Documented for versions 2.4 and 3.

## Evan's UniFi decoder and rules on the Wazuh manager

Installed on the rulelanes oracle (see `../rulelanes/docs/status/M0.md`).
The flowlanes pack (M3) must not collide with them:

| Repo | Commit used | Names and IDs |
| --- | --- | --- |
| `evangress/wazuh-unifi-decoder` | `3a9a2d522840ed876e3f634232ea36392d94478f` | 153 decoders, all named `ubiquiti` (parent plus same-named sibling children); top decoder declares `program_name` (pcre2 `.*`) and matches CEF lines |
| `evangress/wazuh-unifi-rules` | `36193597001b99c94994972412253c3c712fcb93` | 33 rules, IDs 100010-100392 inside the reserved range **100010-100399**; group `unifi,syslog,` plus `authentication_success`, `config_changed`, `firewall`, `ids`, `attack`, `wireless` |

So the flowlanes pack should use decoder names starting `flowlanes` and a
rule ID range outside 100010-100399 (proposal for M3: 100500-100599; TBD).

## Sources

- goflow2: https://github.com/netsampler/goflow2 ; releases https://github.com/netsampler/goflow2/releases ; image https://hub.docker.com/r/netsampler/goflow2
- pmacct: https://github.com/pmacct/pmacct
- nfdump: https://github.com/phaag/nfdump
- Akvorado: https://github.com/akvorado/akvorado
- nProbe: https://www.ntop.org/guides/nprobe/configurations.html
- ElastiFlow: https://hub.docker.com/r/elastiflow/flow-collector ; https://elastiflow.com/docs/flowcoll/config_gen
- Logstash codec: https://www.elastic.co/docs/reference/logstash/plugins/plugins-codecs-netflow
- Elastic NetFlow integration: https://www.elastic.co/docs/reference/integrations/netflow
- vflow: https://github.com/Edgio/vflow
- netflow_parser: https://github.com/mikemiles-dev/netflow_parser ; NetGauze: https://github.com/NetGauze/NetGauze ; ipfixrw: https://github.com/ad1217/rs-ipfix-rw
- Wazuh mailing list on NetFlow: https://groups.google.com/g/wazuh/c/6vQ1BtMnv4w
- Wazuh localfile: https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/localfile.html
- Alertflex: https://alertflex.github.io/doc/pages/altprobe_config.html ; ntopng and Wazuh: https://www.ntop.org/guides/ntopng/third_party_integrations/wazuh.html
- Security Onion NetFlow: https://docs.securityonion.net/en/3/main/netflow/ ; https://docs.securityonion.net/en/2.4/_sources/netflow.rst.txt
