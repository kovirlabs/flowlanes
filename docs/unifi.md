# UniFi gateway flow export

Two kinds of statement are here. **Observed** ones come from the live
export of Evan's gateway to the flowlanes collector on 2026-11-23, from
19:39 local time (section "Observed on Evan's gateway"); each figure names
its time window. The rest is from documentation and community reports
(2026-11-22, M0); **[NV]** marks claims not confirmed by an official
source, and **[confirmed]** or **[contradicted]** marks what the live
export settled. No capture, record or address from the network is in this
repo; the export is described by structure only. No device setting was
changed by an agent.

## Observed on Evan's gateway (2026-11-23)

How it was observed: `flowlanes collect` (branch `ops-unifi-live`) on
`0.0.0.0:2055`, with `--log-templates` from 19:45:56 local, which prints
every new or changed template layout. Counters once a minute. Captures
stay in `captures/` (git-ignored).

### Settings (from Evan's UI, relayed by the coordinating session)

- **Sampling mode** offers four choices: **hash, random, deterministic and
  off**. At the start of the observation it was set to "hash". Evan was
  advised to switch it off; the export changed at 19:53-19:54 local in the
  way a switch to off would (below). That he switched it is inferred from
  the export, not confirmed by him.

### Transport

- IPFIX (version 10) only; no v5 or v9 packets. One exporter address
  (a private IPv4 address, not this machine), observation domain 0.
- Datagrams arrived through the Windows firewall rule on the `0.0.0.0`
  bind: the first receipt from another host (M2 had only used loopback).
- Datagrams of 1,315 to 1,351 bytes on average while flows were flowing
  (19:53-19:59), about 360 bytes while sampled and idle (19:46-19:53).
- Sets are not padded to 4 bytes (allowed by RFC 7011 §3.3.1).
- The sequence number counts options records as well as flow records;
  flowlanes counts them the same way and saw no gap.

### Templates with sampling on ("hash" in the UI; 19:39-19:53)

All elements are IANA elements; **no enterprise (PEN) elements** were sent.
Lengths in bytes. Options templates have one scope field.

| ID | Kind | Fields in order (element ID:length) |
| --- | --- | --- |
| 256 | options, scope observationDomainId | 149:4, systemInitTimeMilliseconds 160:8, observationDomainName 300:29, flowStartMilliseconds 152:8, flowEndMilliseconds 153:8 |
| 257 | options, scope observationDomainId | 149:4, selectorId 302:1, flowSelectorAlgorithm 390:1, samplingSize 309:1, samplingPopulation 310:2 |
| 258 | options, scope observationDomainId | 149:4, ingressInterface 10:2, interfaceName 82:16, interfaceDescription 83:32 |
| 259 | options, scope observationDomainId | 149:4, exportedMessageTotalCount 41:8, exportedFlowRecordTotalCount 42:8, exportedOctetTotalCount 40:8, observedFlowTotalCount 163:8 |
| 260 | options, scope selectorId | 302:1, selectorIDTotalFlowsSelected 395:8, selectorIdTotalPktsObserved 318:8, selectorIdTotalPktsSelected 319:8, 152:8, 153:8 |
| 261 | flows | 8:4, 12:4, 15:4, 60:1, 7:2, 11:2, 6:1, 10:2, 14:2, 2:4, 1:4, 152:8, 153:8, 4:1, 5:1, 136:1, tcpOptions 209:4, 80:6, 56:6, ethernetType 256:2, 61:1, selectorId 302:1 |
| 262 | flows (seen with UDP) | as 261 without tcpOptions 209 |

The sampling configuration in template 257 said **flowSelectorAlgorithm
3, "Random n-out-of-N Sampling"** (IANA flowSelectorAlgorithm registry),
**samplingSize 1, samplingPopulation 512**: 1 out of 512. The UI said
"hash"; the IANA registry has hash-based values (6 to 8) that the gateway
did not send. Which of the two is right is not known.

### Templates with sampling off (from 19:54)

A new export: the sequence numbers started again (counted once as
`sequence_out_of_order`), and template IDs 257 to 261 came back with other
layouts. 256 was unchanged. No selector or sampling elements.

| ID | Kind | Fields in order |
| --- | --- | --- |
| 256 | options | as above |
| 257 | options, scope observationDomainId | the interface table (old 258) |
| 258 | TCP flows | 8:4, 12:4, 15:4, 60:1, 7:2, 11:2, 6:1, 10:2, 14:2, 2:4, 1:4, 152:8, 153:8, 4:1, 5:1, 136:1, 209:4, 80:6, 56:6, 256:2, 61:1 |
| 259 | TCP and UDP flows | as 258 without tcpOptions 209 |
| 260 | ICMP flows | 8:4, 12:4, 15:4, 60:1, icmpTypeCodeIPv4 32:2, 10:2, 14:2, 2:4, 1:4, 152:8, 153:8, 4:1, 5:1, 136:1, 80:6, 56:6, 256:2, 61:1 |
| 261 | options, scope observationDomainId | the export counters (old 259) |

The new templates arrived before (or with) the first data that used them;
no data was decoded with a stale layout. flowlanes cannot tell an ID
reused with a new layout from the old one until the new template arrives,
so data sent in between would be misread; this was not seen.

### Content of flow records

- IPv4 only (ipVersion 4 in every record, no IPv6 template); next hop
  0.0.0.0 in most records.
- Packet and octet counters in 4 bytes (reduced-size encoding), interfaces
  in 2 bytes, MAC addresses on both sides.
- **flowDirection is 255 in every record.** The IANA registry defines 0
  (ingress) and 1 (egress) only, so direction cannot be taken from it.
- flowEndReason 1 (idle timeout, 87% of 17,708 flow records from 19:46
  to 20:32), 3 (end of flow detected, 12%) and 2 (active timeout, 16
  records).
- tcpOptions (209) is deprecated in the IANA registry in favour of
  tcpOptionsFull.
- The string elements (interfaceName, interfaceDescription,
  observationDomainName) are fixed-length and padded with NUL bytes.

### Timing and rates

Counters once a minute, so times below are to the minute. "Sampled" is
19:35-19:53, "unsampled" 19:54-20:32 (local, 2026-11-23).

| Window | Datagrams | Flow records | Options records | Template re-sends |
| --- | --- | --- | --- | --- |
| 19:35-19:45, sampled (first collector) | 12 (1.2/min, mean 373 B) | 3 | 72 | 3 |
| 19:46-19:53, sampled (second collector) | 13 (1.9/min, mean 360 B) | 4 | 77 | 2 |
| 19:54-20:04, unsampled | 249 (24.9/min, mean 1,353 B) | 4,804 (480/min) | 70 | 48 |
| 20:04-20:14, unsampled | 225 (22.5/min) | 4,286 (429/min) | 70 | 44 |
| 20:14-20:24, unsampled | 233 (23.3/min) | 4,437 (444/min) | 70 | 47 |
| 20:24-20:32, unsampled | 188 (23.5/min) | 3,637 (455/min) | 38 | 34 |

- **Options data:** export counters (259 sampled, 261 unsampled) and, when
  sampled, selector counters (260) every 60 s; domain information (256),
  the sampling configuration (257 sampled) and the interface table every
  300 s while sampled (19:35-19:53).
- **Template re-sends:** with sampling on and the export nearly idle, the
  options templates 256-258 came back every 5 minutes (the 300 s spacing of
  their data, and `templates_replaced` rising by 3 at that time). With
  sampling off and about 23 datagrams a minute, `templates_replaced` rose
  by 3 to 9 every minute (179 re-sends from 19:53 to 20:32), so a template
  came back every one to two minutes. That re-sends follow the amount
  exported fits the UI's "refresh rate 20 packets", but per-template times
  were not recorded, so the exact rule is inferred, not measured.
- **Active timeout:** 16 flow records ended with flowEndReason 2 (active
  timeout) from 19:54 to 20:32; each lasted 1,785 to 1,801 s. The active
  timeout in effect is therefore **about 30 minutes**, not the 5 minutes the
  community screenshots show as default **[contradicted]** (Evan's setting
  may differ from the default).
- **Flow-record rate with sampling on** was 3 records in 10 minutes and 4
  in 7 minutes; with it off, 429 to 480 a minute. The sampled rate fits 1
  out of 512, but the two windows are minutes apart at different times, so
  that is not a measured ratio.

### Loss and errors

From 19:35 to 20:32 (two collector runs; 941 datagrams counted in the last counter lines of each):
no malformed packets or sets, no data set rejected for want of a
template, no template expired (timeout 1,800 s), no sequence gap. One
`sequence_out_of_order`, when the gateway restarted its export at the
sampling switch. 8 data sets that arrived before their templates after
the second collector start were held up to 230 s and then decoded (that
run used `--hold-secs 3600`; under the old 60 s default most of them would
have been rejected). Every decoded record was written (17,872 lines =
17,872 records at 20:32).

### What flowlanes changed because of it (branch `ops-unifi-live`)

- The 16 IANA elements above that flowlanes did not know are named.
- NUL padding is cut from string elements.
- `collect --log-templates` prints template layouts without addresses.
- The default hold for data without a template went from 60 s to 900 s.
- `flowlanes-gen` generates both layouts (`unifi::traffic`,
  `unifi::traffic_sampled`), and the goflow2 cross-check decodes them.

## Decided

The gateway will export IPFIX to this PC on **UDP 2055** (Evan, 2026-11-22).
2055 is the documented default port of the flowlanes collector. Flow data
from the network is never committed and is used only to measure detector
false-alert rates (R8).

## Enabling export (official)

- UniFi Network **8.5.6** (release notes, 2024-10-07) added NetFlow:
  "Versions 10, 9 and 5 are supported. Customize the collector address, port
  and rates. Requires a UniFi (Cloud) Gateway firmware version 4.1 or
  newer. NetFlow is not supported on the UniFi Express and UXG-Lite
  models."
- Help-centre article "Traffic Flows and Traffic Logging in UniFi Network":
  *Settings > CyberSecure > Traffic Logging >* enable **NetFlow (IPFIX)** "to
  send sampled traffic data to a third-party SIEM or collection server".
  The same article says some gateways (UDM, UDR, UCG Ultra, Express) log
  only blocked flows by default, while UDM Pro/SE, UCG Max/Fiber, EFG and
  UXG Pro/Enterprise log allowed and blocked. Whether that logging policy
  also limits what NetFlow exports is not stated **[NV]**.

## Settings shown in the UI (community screenshots)

From a vendor blog (TeskaLabs, 2026-08) and a personal blog (2025-01); not
official:

| Setting | Values seen |
| --- | --- |
| Networks to export | per network |
| Version | 10 (IPFIX), 9, 5. IPFIX received **[confirmed]** |
| Collector address and port | e.g. port 2055 |
| Engine ID | Auto |
| Sampling mode | Off; Deterministic with rate 512 in one example. Evan's UI: hash, random, deterministic, off **[confirmed]**; set to hash at first, 1 out of 512 per the export |
| Flow logging | All traffic or blocked only; optional gateway DNS, UniFi services, device management |
| Timeout rate | "5 minutes (default)", re-reporting long-lived flows (active timeout). Observed on Evan's gateway: about 30 minutes |
| Refresh rate | "20 packets (default)", template re-send interval. Re-sends follow traffic, consistent with a packet count but not proven (see Timing) |

## What is sent

- **Version default:** the help-centre names the feature "NetFlow (IPFIX)",
  and 8.5.6 lists 10, 9 and 5. No source states that IPFIX is the default,
  and the 9.3 release announcement does not mention NetFlow. The claim in
  SPEC §4 and the roadmap ("version 10 by default, checked, UniFi Network
  9.3") is **not confirmed** here **[NV]**. flowlanes decodes all three, so
  this does not block anything; Evan should note the version his gateway
  shows. Evan's gateway sends IPFIX **[confirmed]**; whether that was the
  default or his choice is still not known.
- **Fields:** community reports show source and destination address and
  port, protocol, packets, bytes, start and end timestamps, in datagrams of
  about 1.4 KB. Interfaces appear as `eth#`. On a UXG-Pro (firmware
  4.1.13, 2025-06) templates omit the RFC 8158 NAT elements
  (postNAT*/postNAPT*, natEvent). No public capture listing the full
  template or any enterprise (PEN) elements was found **[NV]**; R4 (unknown
  fields kept as ID and raw bytes) covers whatever arrives. On Evan's
  gateway: those fields **[confirmed]**, plus MAC addresses, next hop,
  ToS, TCP flags, flowEndReason, flowDirection and ethernetType; no NAT
  elements and no enterprise elements **[confirmed]**; datagrams of about
  1.3 KB when busy **[confirmed]**. Full templates are listed above.
- **Sampling:** off by default per the screenshots; when on, every detector
  is weakened (SPEC §6 limits). On Evan's gateway sampling was **on**
  ("hash" in the UI, 1 out of 512 per the export) when export was first
  enabled; whether that is the default is not known **[contradicted]** for
  this gateway as configured.
- **Active / inactive timeouts:** the "timeout rate" (5 minutes default)
  is the active timeout; an inactive timeout setting was not found **[NV]**.
  Observed: about 30 minutes on Evan's gateway (see Timing); an inactive
  timeout setting is still not known.

## Switches

UniFi switches do not export flows; Ubiquiti staff on the community forum:
"None of our current switches have flow export support" and "Switches do
not support netflow at this time" (old, undated threads). Only the gateway
exports.

## What M1 does with this

Nothing UniFi-specific is hard-coded. The generator produces IPFIX,
NetFlow v9 and v5 with the common fields above, plus enterprise elements
and NAT elements, so the decoder is tested on more than the gateway is
known to send.

## Sources

- UniFi Network 8.5.6 release notes: https://community.ui.com/releases/UniFi-Network-Application-8-5-6/bfa15dd8-8b58-4d40-9d83-73ebe8c9a955
- Traffic Flows and Traffic Logging: https://help.ui.com/hc/en-us/articles/32201256219799
- UniFi Network 9.3 announcement: https://blog.ui.com/article/introducing-network-9-3
- TeskaLabs (community vendor blog): https://docs.teskalabs.com/logman.io/blog/2026/08/10/how-to-connect-ubiquiti-dream-machine-to-logmanio-to-collect-and-monitor-netflows/
- kmsigma (personal blog): https://blog.kmsigma.com/testing-netflow-with-ubiquiti/
- NAT elements missing (forum): https://community.ui.com/questions/Does-unifi-netflow-not-send-NAT-events-and-information-elements-rfc8158/76fb7702-0696-466d-b236-b1fafe897f8a
- Switches (forum): https://community.ui.com/questions/US-24-netflow-and-SPAN-port-support/767be802-3e9b-45bb-826f-ee0e654624f1 ; https://community.ui.com/questions/b5d07487-d95f-4463-9ab4-7cb4b9e1d01d
