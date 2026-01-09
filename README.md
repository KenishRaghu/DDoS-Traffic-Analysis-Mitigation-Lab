# DDoS Traffic Analysis & Mitigation Lab

Portfolio-style lab for **volumetric (L3)**, **protocol abuse (L4)**, and **application-layer (L7)** denial-of-service patterns, plus **BGP control-plane anomalies** dissected from PCAPs only. Everything runs on a laptop with **Python** and **Scapy**; traffic is **synthetic** and written to PCAP files—no cloud, VMs, Mininet, Snort/Suricata, or live BGP sessions.

## What this demonstrates

- How common attacks look **on the wire** (SYN flood, UDP volumetric, DNS amplification pattern, HTTP GET and slow-header patterns, crafted BGP UPDATEs).
- How to turn a PCAP into **metrics** (rates, ratios, protocol mix, DNS query types, BGP AS paths).
- **Threshold-based detection** with explicit evidence fields (good for explaining logic in interviews).
- **Suggested mitigations** as commented config snippets—**never auto-applied**.

## Pipeline

```text
attacks/*.py  →  pcaps/*.pcap
       ↓
analysis/traffic_analyzer.py  →  traffic profile JSON
       ↓
analysis/anomaly_detector.py  →  detected attacks JSON
       ↓
mitigation/auto_mitigate.py   →  mitigation/generated_rules/*
       ↓
docs/playbook_*.md + reports/lab_findings.md  →  analyst runbooks & summary
```

For BGP, also run `analysis/bgp_path_analyzer.py` and pass its JSON into the detector with `--bgp-analysis` so **unexpected origin** and **route flap** logic can fire.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./pcaps/generate_all.sh
```

Each generator supports **`--dry-run`** (no Scapy import on generators that exit early—SYN/UDP/DNS/HTTP still import Scapy only when not dry). Every attack script starts with a **lab-only** warning banner.

Analyze one capture:

```bash
.venv/bin/python analysis/traffic_analyzer.py pcaps/syn_flood.pcap -o /tmp/profile.json
.venv/bin/python analysis/anomaly_detector.py /tmp/profile.json -o /tmp/alerts.json
.venv/bin/python mitigation/auto_mitigate.py /tmp/alerts.json
```

BGP example:

```bash
.venv/bin/python analysis/bgp_path_analyzer.py pcaps/bgp_anomaly.pcap -o /tmp/bgp.json
.venv/bin/python analysis/traffic_analyzer.py pcaps/bgp_anomaly.pcap -o /tmp/bgp_traffic.json
.venv/bin/python analysis/anomaly_detector.py /tmp/bgp_traffic.json --bgp-analysis /tmp/bgp.json -o /tmp/bgp_alerts.json
```

## Interview notes (detection math)

- **SYN:ACK ratio**: Legitimate handshakes produce comparable **SYN** and **SYN-ACK** counts for new flows. A SYN flood sends many **SYN-only** segments; if the capture is at the victim, you may see huge SYN volume and few SYN-ACKs from the target, so the ratio **SYN-only / SYN-ACK** explodes.
- **DNS amplification**: Compare **average DNS query packet size** to **average DNS response packet size** at the resolver/victim edge. A large ratio suggests amplification (this lab exaggerates sizes for teaching).
- **L7 floods**: **GET/POST-shaped** payloads raise `http_request_like` rates. **Slowloris-style** traffic shows many **small PSH payloads** toward web ports without a high full-request rate—see `l7_small_tcp_payload_count` in the profile JSON.

## Repository layout

| Path | Role |
|------|------|
| `attacks/` | Scapy generators (≤1999 packets per PCAP) |
| `pcaps/` | Outputs + `generate_all.sh` (uses `.venv/bin/python` when present) |
| `analysis/` | `traffic_analyzer.py`, `anomaly_detector.py`, `bgp_path_analyzer.py` |
| `mitigation/` | `auto_mitigate.py` → `generated_rules/` (commented templates) |
| `docs/` | Analyst playbooks |
| `reports/` | `lab_findings.md` summary |

## Ethics

Use only in **isolated lab** environments on data you own. Synthetic PCAPs here are for **education and portfolio** use only.
