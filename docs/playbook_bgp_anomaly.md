# Playbook: BGP anomalies (route leak, hijack, flap) — PCAP analysis only

This lab dissects **crafted BGP UPDATE messages** inside a PCAP. You are **not** configuring routers here; you are practicing control-plane forensics.

## 1. Indicators of attack or operational fault

- **Unexpected origin AS** for a prefix your organization expects from a known upstream (possible leak or hijack).
- **AS_PATH length** anomalies versus historical baselines (policy mistakes, prepending abuse).
- **Route flaps**: withdrawal followed quickly by re-announcement of the same prefix (instability, BGP churn).
- **UPDATE rate spikes** on a peering session in telemetry (this lab approximates via `bgp_update_messages_seen` / duration).

## 2. Wireshark and analysis steps

1. Filter: `tcp.port == 179` — BGP uses TCP.
2. Expand BGP **UPDATE** messages: check **Withdrawn Routes**, **Path Attributes** (AS_PATH, NEXT_HOP), and **NLRI**.
3. Lab tools:

   ```bash
   python analysis/bgp_path_analyzer.py pcaps/bgp_anomaly.pcap -o /tmp/bgp.json
   python analysis/traffic_analyzer.py pcaps/bgp_anomaly.pcap -o /tmp/bgp_traffic.json
   python analysis/anomaly_detector.py /tmp/bgp_traffic.json --bgp-analysis /tmp/bgp.json
   ```

   Compare `unexpected_origin_events` and `route_flaps` in `bgp.json` with the synthetic scenario in `attacks/generate_bgp_anomaly.py`.

## 3. Mitigation actions (real networks — high level)

- **Prefix filters** on customers; **IRR** and **RPKI ROV** where supported.
- **Maximum-prefix** limits per peer; **GTSM** (TTL security) and **TCP-AO** where deployed.
- **RTBH** only after explicit policy and victim consent (see `bgp_rtbh_suggestion.txt` template).
- **Peer coordination**: notify upstream when a leak is observed; they withdraw or filter.

## 4. Validation

- Prefix visibility returns to expected **AS_PATH** in public looking glasses (where available).
- **UPDATE churn** and **flap damping** counters normalize.
- No unintended **blackholes** — verify RTBH scope.

## 5. Prevention

- **RPKI** signing for your own prefixes; drop **invalids** when operationally ready.
- **Peer lock** and explicit **as-path filters** for critical sessions.
- Change control on **import/export** route-maps; peer review.
