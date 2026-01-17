#!/usr/bin/env python3
"""
auto_mitigate.py — translate anomaly_detector JSON into *suggested* configs.

Nothing here is applied. Files are starting points for engineers to review.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_syn_flood_rules(out_dir: Path, ev: dict) -> None:
    p = out_dir / "syn_flood_iptables.sh"
    text = r"""#!/usr/bin/env bash
# Suggested mitigations for SYN flood (half-open connection exhaustion)
# NOT APPLIED — review, adapt interface names, and test in a lab.
#
# What this does:
#   - hashlimit caps new SYNs per source IP (adjust --hashlimit-* to taste)
#   - SYN cookies let the kernel allocate state only after ACK (see sysctl below)
#
# Why: SYN floods inflate the SYN queue without completing handshakes; rate limits
#      slow attackers; SYN cookies remove reliance on per-SYN socket state.

# Example: rate-limit new SYNs to 50/sec per source with burst 100
# iptables -A INPUT -p tcp --syn -m hashlimit \
#   --hashlimit-name syn_src --hashlimit-mode srcip --hashlimit-upto 50/sec \
#   --hashlimit-burst 100 -j ACCEPT
# iptables -A INPUT -p tcp --syn -j DROP

echo "Enable SYN cookies (Linux):"
echo "  sysctl -w net.ipv4.tcp_syncookies=1"
echo "  # Persist in /etc/sysctl.d/"
"""
    p.write_text(text, encoding="utf-8")
    p.chmod(0o755)


def write_udp_flood_rules(out_dir: Path, ev: dict) -> None:
    p = out_dir / "udp_flood_iptables.sh"
    ports = ev.get("top_destination_ports") or []
    top_ip = ev.get("top_source_ip") or "0.0.0.0/0"
    port_hint = ports[0]["port"] if ports else None
    text = f"""#!/usr/bin/env bash
# UDP volumetric / flood mitigation ideas (NOT APPLIED)
#
# What this does:
#   - Drops UDP to heavily hit destination ports from the worst offender /24
#   - You should replace PORT and CIDR with values from your PCAP evidence
#
# Why: UDP is connectionless; filtering on dst port + source prefix cuts noise
#      when a dominant attacker prefix exists. Many floods spoof sources — then
#      edge scrubbing / upstream ACLs matter more than host iptables.

# Example (edit PORT and CIDR):
# PORT={port_hint or 12345}
# iptables -A INPUT -p udp --dport $PORT -s {top_ip if top_ip else "x.x.x.0/24"} -j DROP

# Evidence snapshot (from detector):
# {json.dumps(ev, indent=2)}
"""
    p.write_text(text, encoding="utf-8")
    p.chmod(0o755)


def write_dns_amp_rules(out_dir: Path, ev: dict) -> None:
    p = out_dir / "dns_amplification_iptables.sh"
    text = r"""#!/usr/bin/env bash
# DNS amplification / open resolver abuse — host-level ideas (NOT APPLIED)
#
# What this does:
#   - Rate-limit UDP/53 toward your authoritative servers
#   - Block obvious spoofed ranges only if you know your legitimate traffic
#
# Why: Attackers send small queries with forged victim source IPs; resolvers
#      reply large answers to the victim. Fix the ecosystem: disable open
#      recursion toward the Internet, implement BCP38 at edges, response rate
#      limiting (RRL) on authoritative servers.

# Example rate limit (adjust):
# iptables -A INPUT -p udp --dport 53 -m limit --limit 1000/sec -j ACCEPT
# iptables -A INPUT -p udp --dport 53 -j DROP

echo "Operational recommendation: ensure this resolver is NOT open to the world."
"""
    p.write_text(text, encoding="utf-8")
    p.chmod(0o755)


def write_http_flood_rules(out_dir: Path, ev: dict) -> None:
    nginx = out_dir / "http_flood_nginx.conf"
    blk = out_dir / "http_flood_blocklist.txt"
    ip = ev.get("source_ip", "198.51.100.1")
    nginx.write_text(
        f"""# nginx rate limiting snippet (NOT APPLIED — merge into server {{}} manually)
#
# What this does:
#   - limit_req_zone tracks requests per client IP
#   - limit_conn_zone caps concurrent connections per IP
#
# Why: L7 floods look like HTTP; you need cheap early rejects before app work.

limit_req_zone $binary_remote_addr zone=lab_req:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=lab_conn:10m;

# Inside location / {{
#   limit_req zone=lab_req burst=20 nodelay;
#   limit_conn lab_conn 20;
# }}
""",
        encoding="utf-8",
    )
    blk.write_text(
        f"""# IPs to deny at edge/WAF after validation (example)
# deny {ip};
""",
        encoding="utf-8",
    )


def write_http_slow_rules(out_dir: Path, ev: dict) -> None:
    p = out_dir / "http_slowloris_nginx.conf"
    p.write_text(
        r"""# Slow header / slowloris-style connection exhaustion (NOT APPLIED)
#
# What this does:
#   - Timeouts cap how long a client may send headers/body bytes
#
# Why: Slowloris wins by holding many idle connections; tight timeouts + low
#      concurrent limits per IP reduce impact.

client_header_timeout 10s;
client_body_timeout 10s;
send_timeout 10s;
keepalive_timeout 15s;
# limit_conn as in http_flood_nginx.conf
""",
        encoding="utf-8",
    )


def write_bgp_rules(out_dir: Path, ev: dict) -> None:
    filt = out_dir / "bgp_prefix_filter_suggestion.txt"
    rtbh = out_dir / "bgp_rtbh_suggestion.txt"
    filt.write_text(
        """# Prefix / AS-path filtering (documentation — not a live router config)
#
# What this does:
#   - Only accept customer prefixes you expect (prefix-list or RPKI ROAs)
#   - Reject unexpected longer prefixes for your own aggregates
#
# Why: Route leaks and hijacks inject bogus reachability; filters limit blast
#      radius while you coordinate with peers.

Example policy intent:
  - If you expect 198.51.100.0/24 ONLY from AS64512 upstream, drop the same
    prefix when learned with origin AS65001 unless a trusted exception exists.
""",
        encoding="utf-8",
    )
    rtbh.write_text(
        """# Remotely triggered blackhole (RTBH) — concept only
#
# What this does:
#   - Announce a more-specific /32 (or IPv6 /128) toward upstream with a
#     well-known blackhole community so traffic stops before your edge
#
# Why: When you are drowning in attack volume to one IP, blackholing that host
#      sacrifices reachability for that address but protects the rest.

# Typical pattern: tag prefix with community agreed with transit (example only)
# network 192.0.2.99/32 route-map SET-BH-community
""",
        encoding="utf-8",
    )


HANDLERS = {
    "syn_flood": write_syn_flood_rules,
    "udp_flood": write_udp_flood_rules,
    "dns_amplification": write_dns_amp_rules,
    "http_flood": write_http_flood_rules,
    "http_slowloris_style": write_http_slow_rules,
    "bgp_anomaly": write_bgp_rules,
    "bgp_route_leak_or_hijack_indicator": write_bgp_rules,
    "bgp_route_flap": write_bgp_rules,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate mitigation artifacts from detector JSON.")
    parser.add_argument("detections_json", type=Path)
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Default: mitigation/generated_rules next to this script",
    )
    args = parser.parse_args()

    data = _load(args.detections_json)
    attacks = data.get("detected_attacks") or []
    repo = Path(__file__).resolve().parent
    out_dir = args.output_dir or (repo / "generated_rules")
    out_dir.mkdir(parents=True, exist_ok=True)

    seen = set()
    for a in attacks:
        t = a.get("type")
        if t not in HANDLERS or t in seen:
            continue
        seen.add(t)
        HANDLERS[t](out_dir, a.get("evidence") or {})

    print(f"Wrote suggested rules under {out_dir}")
    for f in sorted(out_dir.iterdir()):
        if f.name != ".gitkeep":
            print(f"  - {f.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
