# Playbook: HTTP / application-layer flood (L7)

## 1. Indicators of attack

- High rate of **HTTP requests** (GET/POST-shaped TCP payloads) from one or few IPs, or distributed low-and-slow across many IPs.
- **Slowloris-style** behavior: many connections with **tiny PSH segments** dribbling headers, holding server workers (this lab flags many small payloads to web ports without a high full-request rate).
- Application CPU, thread pools, or WAF **request limits** saturate before network links do.
- Harder than L3/L4: traffic resembles real browsers unless you inspect **entropy, JA3/TLS**, or behavioral signals (not used in this threshold-only lab).

## 2. Wireshark and analysis steps

1. Follow TCP stream on port 80/8080/443 (decrypt only where you have keys and legal authority).
2. Display filter examples: `http.request` when Wireshark’s HTTP dissector applies; for raw TCP, search for `GET ` or `POST ` in **Analyze → Follow → TCP Stream**.
3. Compare `http_flood_get.pcap` vs `http_flood_slowloris.pcap` in this repo.
4. Lab pipeline:

   ```bash
   python analysis/traffic_analyzer.py pcaps/http_flood_get.pcap -o /tmp/h.json
   python analysis/anomaly_detector.py /tmp/h.json
   python analysis/traffic_analyzer.py pcaps/http_flood_slowloris.pcap -o /tmp/s.json
   python analysis/anomaly_detector.py /tmp/s.json
   ```

   Inspect `http_request_like_per_source_per_sec` vs `l7_small_tcp_payload_count`.

## 3. Mitigation actions

- **Reverse proxy rate limits** (see `http_flood_nginx.conf` and `http_slowloris_nginx.conf` templates from `auto_mitigate.py`).
- **IP blocklists** after validating collateral damage (`http_flood_blocklist.txt`).
- **WAF rules** for path abuse, missing headers, or bot signatures.
- **CAPTCHA / proof-of-work** only when user experience cost is acceptable.
- Scale **horizontally** (more app instances) buys time but does not replace filtering.

## 4. Validation

- 4xx/429 or early drops at proxy before app tier; app CPU falls.
- Legitimate user journeys tested from representative networks.
- Slowloris: **connection count per IP** drops after timeouts and `limit_conn`.

## 5. Prevention

- Design **stateless** APIs where possible; cache static assets at CDN.
- **Bot management** with continuous tuning.
- **TLS 1.3** and modern cipher defaults reduce some TLS-based L7 tricks (separate from HTTP body floods).
