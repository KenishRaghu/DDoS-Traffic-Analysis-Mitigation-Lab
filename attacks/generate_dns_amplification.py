#!/usr/bin/env python3
"""
================================================================================
LAB / EDUCATIONAL USE ONLY — DO NOT USE ON NETWORKS YOU DO NOT OWN OR OPERATE
================================================================================
Simulates the *pattern* of DNS reflection/amplification in a PCAP: small queries
with a forged (victim) source IP and larger responses to that victim.

Amplification factor (conceptual):
  Historically, ANY queries could yield very large responses (often cited in the
  ~28–54× range vs a ~60 B query for some zones — actual factor depends on
  zone content and EDNS). This lab uses crafted sizes to make the ratio obvious
  for analysis (response bytes >> query bytes).

Open resolvers should not answer recursive queries from arbitrary clients;
BCP38 prevents spoofed sources. This file only writes a PCAP.
================================================================================
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

MAX_PACKETS = 1999
# Documentation IPs (RFC 5737 / lab)
VICTIM_IP = "192.0.2.100"
RESOLVER_IP = "203.0.113.53"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate synthetic DNS amplification scenario PCAP (lab only)."
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out = Path(args.output) if args.output else repo_root / "pcaps" / "dns_amplification.pcap"

    if args.dry_run:
        print(f"[dry-run] Would write ~{MAX_PACKETS} DNS query/response pairs to {out}")
        print("[dry-run] Pattern: src=victim (spoofed on queries) → resolver; resolver → victim")
        return 0

    from scapy.all import IP, UDP, wrpcap  # noqa: WPS433
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    random.seed(44)
    packets = []
    base_time = 1_700_000_200.0
    t = 0.0
    # Alternate: query then response, under MAX_PACKETS total
    pairs = MAX_PACKETS // 2
    big_txt = b"x" * 1400  # simulated large answer payload

    for i in range(pairs):
        qname = f"f{i % 50}.example.lab."
        # Query: appears from VICTIM toward resolver (attacker forged src in real attack)
        q_pkt = (
            IP(src=VICTIM_IP, dst=RESOLVER_IP)
            / UDP(sport=random.randint(40000, 50000), dport=53)
            / DNS(
                id=random.randint(1, 65535),
                qr=0,
                opcode=0,
                qd=DNSQR(qname=qname, qtype=255),  # ANY (deprecated but iconic for amplification labs)
            )
        )
        q_pkt.time = base_time + t
        packets.append(q_pkt)
        t += 0.0003

        # Large response to victim (what an amplifier sends back)
        r_pkt = (
            IP(src=RESOLVER_IP, dst=VICTIM_IP)
            / UDP(sport=53, dport=q_pkt[UDP].sport)
            / DNS(
                id=q_pkt[DNS].id,
                qr=1,
                aa=1,
                qd=DNSQR(qname=qname, qtype=255),  # ANY (deprecated but iconic for amplification labs)
                an=DNSRR(rrname=qname, type=16, rclass="IN", ttl=300, rdata=big_txt),
            )
        )
        r_pkt.time = base_time + t
        packets.append(r_pkt)
        t += 0.0003

    while len(packets) < MAX_PACKETS:
        p = (
            IP(src=VICTIM_IP, dst=RESOLVER_IP)
            / UDP(sport=random.randint(40000, 50000), dport=53)
            / DNS(qd=DNSQR(qname="pad.example.lab.", qtype="A"))
        )
        p.time = base_time + t
        packets.append(p)
        t += 0.0002

    packets = packets[:MAX_PACKETS]
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
