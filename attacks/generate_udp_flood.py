#!/usr/bin/env python3
"""
================================================================================
LAB / EDUCATIONAL USE ONLY — DO NOT USE ON NETWORKS YOU DO NOT OWN OR OPERATE
================================================================================
Synthetic volumetric UDP traffic for PCAP analysis. Crafted frames are not
meant to be injected toward real victims. Unauthorized flooding is illegal.
================================================================================
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path

MAX_PACKETS = 1999
VICTIM_IP = "192.0.2.50"
UDP_PAYLOAD_SIZE = 1300  # large UDP datagrams → bandwidth-focused simulation


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic UDP volumetric-flood PCAP (lab only)."
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out = Path(args.output) if args.output else repo_root / "pcaps" / "udp_flood.pcap"

    if args.dry_run:
        print(f"[dry-run] Would write ~{MAX_PACKETS} large UDP packets to {out}")
        print(f"[dry-run] Random destination ports on {VICTIM_IP}, payload ~{UDP_PAYLOAD_SIZE} B")
        return 0

    from scapy.all import IP, UDP, Raw, wrpcap  # noqa: WPS433

    random.seed(43)
    payload = os.urandom(UDP_PAYLOAD_SIZE)
    packets = []
    base_time = 1_700_000_100.0
    gap = 0.0004

    for i in range(MAX_PACKETS):
        dport = random.randint(1, 65535)
        sport = random.randint(32768, 61000)
        src = f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}"
        p = IP(src=src, dst=VICTIM_IP) / UDP(sport=sport, dport=dport) / Raw(load=payload)
        p.time = base_time + i * gap
        packets.append(p)

    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
