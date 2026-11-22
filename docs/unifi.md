# UniFi gateway flow export

From documentation and community reports only (2026-11-22, M0). Nothing
here was observed on Evan's network: no traffic was captured and no device
setting was changed. Enabling export is Evan's action. **[NV]** marks claims
not confirmed by an official source.

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
| Version | 10 (IPFIX), 9, 5 |
| Collector address and port | e.g. port 2055 |
| Engine ID | Auto |
| Sampling mode | Off; Deterministic with rate 512 in one example |
| Flow logging | All traffic or blocked only; optional gateway DNS, UniFi services, device management |
| Timeout rate | "5 minutes (default)", re-reporting long-lived flows (active timeout) |
| Refresh rate | "20 packets (default)", template re-send interval |

## What is sent

- **Version default:** the help-centre names the feature "NetFlow (IPFIX)",
  and 8.5.6 lists 10, 9 and 5. No source states that IPFIX is the default,
  and the 9.3 release announcement does not mention NetFlow. The claim in
  SPEC §4 and the roadmap ("version 10 by default, checked, UniFi Network
  9.3") is **not confirmed** here **[NV]**. flowlanes decodes all three, so
  this does not block anything; Evan should note the version his gateway
  shows.
- **Fields:** community reports show source and destination address and
  port, protocol, packets, bytes, start and end timestamps, in datagrams of
  about 1.4 KB. Interfaces appear as `eth#`. On a UXG-Pro (firmware
  4.1.13, 2025-06) templates omit the RFC 8158 NAT elements
  (postNAT*/postNAPT*, natEvent). No public capture listing the full
  template or any enterprise (PEN) elements was found **[NV]**; R4 (unknown
  fields kept as ID and raw bytes) covers whatever arrives.
- **Sampling:** off by default per the screenshots; when on, every detector
  is weakened (SPEC §6 limits).
- **Active / inactive timeouts:** the "timeout rate" (5 minutes default)
  is the active timeout; an inactive timeout setting was not found **[NV]**.

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
