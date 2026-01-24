# Playbook: UDP volumetric flood (L3/L4)

## 1. Indicators of attack

- Sharp increase in **UDP traffic** toward one host or subnet, often with **large average packet size** (bandwidth exhaustion).
- **Many random destination ports** (classic “spray”) or one hot port (game, VoIP, custom service).
- CPU on routers and hosts spent on **routing and socket demux**, not on useful work.
- SNMP, NetFlow, or sFlow showing UDP dominance and elevated **bits per second**.

## 2. Wireshark and analysis steps

1. Display filter: `udp` — confirm protocol mix.
2. **Statistics → Protocol Hierarchy** — UDP share of total bytes.
3. **Statistics → Endpoints → IPv4** — see whether one source dominates (sometimes true for misconfigured stress tests) or traffic is **highly distributed** (spoofed sources).
4. Lab tools:

   ```bash
   python analysis/traffic_analyzer.py pcaps/udp_flood.pcap -o /tmp/u.json
   python analysis/anomaly_detector.py /tmp/u.json
   ```

   Compare `protocol_distribution`, `avg_packet_size_bytes`, and aggregate `packets_per_second_timeline` to `baseline_normal.pcap`.

## 3. Mitigation actions

- **ACLs / firewall rules**: drop UDP to affected ports or from worst offender prefixes when sources are not spoofed (see `udp_flood_iptables.sh` from `auto_mitigate.py`).
- **Upstream blackholing or RTBH** for overwhelmed destinations (coordinate with provider).
- **Scrubbing centers** that absorb UDP before clean traffic returns on a GRE tunnel.
- For **DNS/NTP**-specific floods, use dedicated playbooks; generic UDP filters may overlap legitimate traffic.

## 4. Validation

- Bits per second and packet rate drop on the victim interface after the rule or scrubbing path engages.
- Legitimate UDP applications (if any on same ports) still function — if not, narrow the filter.
- Repeat PCAP or flow sample to confirm attack signature is gone.

## 5. Prevention

- **BCP38** anti-spoofing at network edge reduces reflection and spoofed floods elsewhere.
- Do not expose unnecessary UDP services to the Internet.
- **Capacity and burst** agreements with transit providers.
