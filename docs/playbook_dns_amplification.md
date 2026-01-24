# Playbook: DNS amplification / reflection

## 1. Indicators of attack

- Large UDP/53 **responses** toward a victim while queries appear to originate from the victim (spoofed source in real attacks).
- **Response size much larger than query size** (amplification factor). In this lab, `traffic_analyzer.py` computes `dns_response_to_query_size_ratio` from packet lengths.
- Historical abuse involved **ANY** and large TXT responses; modern networks should block or rate-limit these patterns.
- Open resolvers answering **recursive** queries from the whole Internet are a prerequisite for large-scale reflection.

## 2. Wireshark and analysis steps

1. Filter: `udp.port == 53`.
2. For each conversation, compare **query** (QR=0) vs **response** (QR=1) sizes in the packet bytes column.
3. **Statistics → Conversations → UDP**: many small queries from one IP toward resolvers, large return path to another IP suggests reflection (in live data).
4. Lab commands:

   ```bash
   python analysis/traffic_analyzer.py pcaps/dns_amplification.pcap -o /tmp/d.json
   python analysis/anomaly_detector.py /tmp/d.json
   ```

   Read `dns_avg_query_packet_bytes`, `dns_avg_response_packet_bytes`, and `dns_response_to_query_size_ratio`.

## 3. Mitigation actions

- **Resolver hardening**: disable recursion for untrusted clients; use RRL (response rate limiting) on authoritative servers.
- **Network edge**: filter spoofed egress (BCP38); rate-limit UDP/53 toward your authoritative infrastructure.
- **Host iptables** ideas are in `dns_amplification_iptables.sh` (lab template only).
- Coordinate with **upstream** if the victim is off-net; they may need flowspec or ACLs.

## 4. Validation

- Ratio of response-to-query bytes returns toward baseline.
- Resolver query logs show **no abnormal recursion** from foreign space.
- Victim interface UDP volume drops.

## 5. Prevention

- Never operate an **open resolver** without explicit design.
- Keep software patched; monitor for ANY/TXT policy violations.
- Participate in **OARC**-style best practices for DNS operators.
