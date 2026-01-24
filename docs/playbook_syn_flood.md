# Playbook: TCP SYN flood (L4)

Step-by-step notes for a junior analyst. Follow sections in order.

## 1. Indicators of attack

- Sudden rise in **TCP segments with SYN set and ACK clear** toward one service (web, mail, VPN).
- **SYN:ACK ratio** skewed: many SYN-only packets relative to SYN-ACK replies (legitimate new flows are roughly paired until backlog fills).
- Connection table growth on the target: many **half-open** or **SYN_RECEIVED** sockets.
- Legitimate users time out when opening new connections while existing sessions may still work briefly.

## 2. Wireshark and analysis steps

1. Open the PCAP. Apply display filter: `tcp.flags.syn == 1 && tcp.flags.ack == 0` to isolate SYN-only packets.
2. **Statistics → I/O Graphs**: graph packet count filtered by the same expression to see ramp-up.
3. **Statistics → Conversations → IPv4**: check whether sources are highly dispersed (spoofed or botnet) or concentrated.
4. Run the lab profiler:

   ```bash
   python analysis/traffic_analyzer.py pcaps/syn_flood.pcap -o /tmp/profile.json
   python analysis/anomaly_detector.py /tmp/profile.json
   ```

   Read `syn_ack_ratio` and `tcp_syn_only_count` in the JSON. In this lab, SYN-ACK is absent in the synthetic capture, so the ratio is flagged as infinite for teaching purposes.

## 3. Mitigation actions

- **SYN cookies** (`tcp_syncookies`): kernel sends a cryptographic cookie instead of allocating full socket state on SYN. Enable under load; persist via `sysctl`.
- **Host rate limits**: `iptables`/`nftables` hashlimits on `--syn` per source IP or per destination port (see `mitigation/generated_rules/syn_flood_iptables.sh` after running `auto_mitigate.py`).
- **Upstream / scrubbing**: when volume exceeds your edge, provider scrubbing or anycast absorption spreads load.
- **Load balancer behavior**: ensure health checks and backend protections do not amplify errors.

## 4. Validation

- After changes, re-capture at the edge: SYN-only rate should fall; successful **three-way handshakes** should recover.
- Application metrics: new connection success rate, TLS handshake latency, HTTP 5xx during peaks.
- False positives: aggressive SYN dropping can hurt NAT-heavy corporate egress; tune limits.

## 5. Prevention

- Architect for **stateless front ends** where possible (SYN proxy appliances, CDNs).
- Capacity planning for **SYN table** and firewall state.
- Participate in **threat intelligence** sharing for botnet C2 and reflector lists where relevant.
