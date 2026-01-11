#!/usr/bin/env python3
"""
================================================================================
LAB / EDUCATIONAL USE ONLY — DO NOT USE ON NETWORKS YOU DO NOT OWN OR OPERATE
================================================================================
This script crafts SYN segments in a PCAP for offline analysis. It does not
establish real TCP sessions. Sending spoofed or attack traffic on production
or third-party networks is illegal and unethical.
================================================================================
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

# Load Scapy only after argparse so --dry-run works without deps for quick checks
MAX_PACKETS = 1999
VICTIM_IP = "192.0.2.50"
VICTIM_PORT = 80


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic L4 SYN-flood PCAP (lab only)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan and exit without importing Scapy or writing files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output PCAP path (default: pcaps/syn_flood.pcap relative to repo root).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out = Path(args.output) if args.output else repo_root / "pcaps" / "syn_flood.pcap"

    if args.dry_run:
        print(f"[dry-run] Would write ~{MAX_PACKETS} SYN packets to {out}")
        print(f"[dry-run] Victim {VICTIM_IP}:{VICTIM_PORT}, randomized sources (documentation address blocks)")
        return 0

    from scapy.all import IP, TCP, wrpcap  # noqa: WPS433

    random.seed(42)
    packets = []
    base_time = 1_700_000_000.0

    # Ramp-up: phase i uses inter-arrival ~ 1/(10 * (i+1)) so PPS increases over time.
    phases = 5
    per_phase = MAX_PACKETS // phases
    pkt_idx = 0
    for phase in range(phases):
        rate_factor = (phase + 1) / phases  # grows toward 1.0
        gap = max(0.0002, 0.02 * (1.0 - 0.7 * rate_factor))
        for _ in range(per_phase):
            # Randomized spoofed source (documentation / lab ranges)
            src = f"198.51.{random.randint(0, 255)}.{random.randint(1, 254)}"
            sport = random.randint(1024, 65535)
            p = (
                IP(src=src, dst=VICTIM_IP)
                / TCP(
                    sport=sport,
                    dport=VICTIM_PORT,
                    flags="S",
                    seq=random.randint(1, 2**31 - 1),
                    window=8192,
                )
            )
            p.time = base_time + pkt_idx * gap
            packets.append(p)
            pkt_idx += 1

    while len(packets) < MAX_PACKETS:
        src = f"203.0.113.{random.randint(1, 254)}"
        sport = random.randint(1024, 65535)
        p = IP(src=src, dst=VICTIM_IP) / TCP(
            sport=sport, dport=VICTIM_PORT, flags="S", seq=random.randint(1, 2**31 - 1)
        )
        p.time = base_time + pkt_idx * 0.0005
        packets.append(p)
        pkt_idx += 1

    packets = packets[:MAX_PACKETS]
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
