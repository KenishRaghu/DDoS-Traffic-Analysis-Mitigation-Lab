# Lab findings summary

This report describes what each synthetic PCAP is meant to represent, what the **threshold-based** toolchain reported after regenerating captures with `./pcaps/generate_all.sh`, and what **mitigation templates** `mitigation/auto_mitigate.py` produces. Re-run the pipeline locally if you change generators or thresholds (`analysis/anomaly_detector.py` defaults).

## Baseline

- **File:** `pcaps/baseline_normal.pcap` (embedded Python in `generate_all.sh`)
- **Contents:** Short DNS exchanges, TCP handshakes, small HTTP GET/200 pairs, occasional UDP noise.
- **Detector:** No alerts with default thresholds (healthy SYN:ACK balance, no amplification ratio, moderate rates).

## SYN flood (L4)

- **Simulation:** Many **SYN-only** TCP segments toward `192.0.2.50:80` from randomized documentation-block sources; timestamps ramp up inter-arrival rate.
- **Profile highlights:** `syn_ack_ratio` reported as **infinity** (no SYN-ACK in this victim-side-style capture), ~1999 TCP packets, ~40 B average size.
- **Detector:** `syn_flood` (high confidence).
- **Mitigation artifacts:** `syn_flood_iptables.sh` (hashlimit + SYN cookie sysctl notes).

## UDP volumetric flood (L3/L4)

- **Simulation:** ~1300 B UDP payloads to random destination ports on one host—bandwidth-style noise.
- **Profile highlights:** **100% UDP**, high aggregate **packets/sec**, large **average packet size**; sources are spread (typical of spoofed/volumetric mixes).
- **Detector:** `udp_flood` (high confidence) using **aggregate** UDP rate + size heuristics (not only single-source PPS).
- **Mitigation artifacts:** `udp_flood_iptables.sh` (commented drop examples tied to top ports / CIDR).

## DNS amplification pattern (L3/L4)

- **Simulation:** Queries toward a resolver with **qtype 255 (ANY)** and large **TXT-style** answers; demonstrates **small query vs large response** byte sizes in-file.
- **Profile highlights:** `dns_response_to_query_size_ratio` ≈ **24.6×** in the last full run (exact value varies slightly with Scapy encoding).
- **Detector:** `dns_amplification` only—generic **UDP flood** is suppressed when the DNS amplification ratio rule fires to avoid duplicate classification.
- **Mitigation artifacts:** `dns_amplification_iptables.sh` (rate-limit sketch + resolver hygiene notes).

## HTTP GET flood (L7)

- **Simulation:** Single source sending **GET/POST** shaped TCP payloads to `8080` with **User-Agent rotation** and **path rotation**.
- **Profile highlights:** High **`http_request_like_per_source_per_sec`** for `198.51.100.77`.
- **Detector:** `http_flood` (high confidence).
- **Mitigation artifacts:** `http_flood_nginx.conf`, `http_flood_blocklist.txt`.

## Slowloris-style HTTP pattern (L7)

- **Simulation:** Many flows with **small PSH segments** carrying header fragments toward `8080`, spread over ~**98 s** of capture time.
- **Profile highlights:** ~**1899** TCP segments with **PSH** payloads **under 128 B** to port **8080**, but **low** full GET/POST rate.
- **Detector:** `http_slowloris_style` (medium confidence).
- **Mitigation artifacts:** `http_slowloris_nginx.conf` (timeout / connection-holding guidance).

## BGP anomaly (control plane, PCAP only)

- **Simulation:** Crafted **BGP UPDATE** over TCP/179: legitimate announcement for `198.51.100.0/24`, **unexpected origin AS** (65001 vs expected 64512), **withdrawal**, **re-announcement**, then a burst of duplicate suspicious updates.
- **Path analyzer:** **571** UPDATE events parsed; **331** unexpected-origin hits (includes repeated spike duplicates); **80** paired withdraw→re-announce events with the lab’s pairing rule.
- **Traffic profile:** **571** BGP UPDATE messages, high **updates/sec** → `bgp_anomaly`; with `--bgp-analysis`, also **route leak/hijack indicator** and **route flap** entries.
- **Mitigation artifacts:** `bgp_prefix_filter_suggestion.txt`, `bgp_rtbh_suggestion.txt` (documentation-level, not router configs).

## L3 vs L4 vs L7 (comparison)

| Layer | Example in this repo | Dominant signal | Volume vs CPU | Filtering difficulty |
|-------|----------------------|-----------------|---------------|----------------------|
| L3 | UDP size + pps; DNS byte amplification | Bits/sec, packet size, IP/proto mix | Often **bandwidth**-bound first | Easier at edge with ACLs/scrubbing; **spoofed sources** complicate source-based blocks |
| L4 | SYN flood | State table / SYN queue, SYN:ACK ratio | Mix of **state** and bandwidth | **SYN cookies**, SYN rate limits, SYN proxies |
| L7 | HTTP GET + slow headers | App threads, WAF, reverse proxy | Often **CPU / concurrency** before link saturation | **Hardest**: must preserve real users; needs rate limits, WAF, behavioral signals |

## Regenerating this report’s numbers

```bash
./pcaps/generate_all.sh
# Then run traffic_analyzer → anomaly_detector (and bgp_path_analyzer for BGP)
# as shown in README.md; optionally re-open this file and paste updated metrics.
```

Thresholds are JSON-overridable:

```bash
python analysis/anomaly_detector.py profile.json --thresholds my_thresholds.json
```
