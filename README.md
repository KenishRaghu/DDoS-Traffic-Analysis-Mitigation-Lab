# DDoS Traffic Analysis & Mitigation Lab

Portfolio-style lab for **volumetric (L3)**, **protocol abuse (L4)**, and **application-layer (L7)** denial-of-service patterns, plus **BGP control-plane anomalies** dissected from PCAPs only. Everything runs on a laptop with **Python** and **Scapy**; traffic is **synthetic** and written to PCAP files—no cloud, VMs, Mininet, Snort/Suricata, or live BGP sessions.

## What this demonstrates

- How common attacks look **on the wire** (SYN flood, UDP volumetric, DNS amplification pattern, HTTP GET and slow-header patterns, crafted BGP UPDATEs).
- How to turn a PCAP into **metrics** (rates, ratios, protocol mix, DNS query types, BGP AS paths).
- **Threshold-based detection** with explicit evidence fields
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
