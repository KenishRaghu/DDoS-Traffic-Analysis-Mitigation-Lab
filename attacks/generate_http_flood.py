#!/usr/bin/env python3
"""
================================================================================
LAB / EDUCATIONAL USE ONLY — DO NOT USE ON NETWORKS YOU DO NOT OWN OR OPERATE
================================================================================
Builds HTTP-like TCP payloads in a PCAP (rapid GET/POST and slow header dribbling).
Does not perform real application-layer attacks against live services.
================================================================================
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

MAX_PACKETS_PER_FILE = 1999
TARGET_IP = "192.0.2.50"
TARGET_PORT = 8080

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "curl/8.5.0",
    "python-requests/2.31.0",
]

PATHS = [
    "/",
    "/index.html",
    "/api/v1/status",
    "/search?q=test",
    "/static/app.js",
    "/login",
    "/cart/add",
]


def build_get(path: str, ua: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {TARGET_IP}:{TARGET_PORT}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/json\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()


def build_post(path: str, ua: str) -> bytes:
    body = b'{"item":"lab","qty":1}'
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {TARGET_IP}:{TARGET_PORT}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTTP flood PCAPs (lab only).")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--mode",
        choices=("get", "slowloris", "both"),
        default="both",
        help="get: rapid GET/POST; slowloris: partial headers across packets; both: write two PCAPs",
    )
    parser.add_argument("--out-get", default=None)
    parser.add_argument("--out-slowloris", default=None)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_get = Path(args.out_get) if args.out_get else repo_root / "pcaps" / "http_flood_get.pcap"
    out_slow = (
        Path(args.out_slowloris) if args.out_slowloris else repo_root / "pcaps" / "http_flood_slowloris.pcap"
    )

    if args.dry_run:
        print(f"[dry-run] mode={args.mode}")
        if args.mode in ("get", "both"):
            print(f"[dry-run] Would write ~{MAX_PACKETS_PER_FILE} packets to {out_get}")
        if args.mode in ("slowloris", "both"):
            print(f"[dry-run] Would write ~{MAX_PACKETS_PER_FILE} packets to {out_slow}")
        return 0

    from scapy.all import IP, TCP, Raw, wrpcap  # noqa: WPS433

    random.seed(45)

    def write_get_pcap(path: Path) -> None:
        packets = []
        base = 1_700_000_300.0
        attacker = "198.51.100.77"
        for i in range(MAX_PACKETS_PER_FILE):
            ua = random.choice(USER_AGENTS)
            pth = random.choice(PATHS)
            meth = random.choice((build_get, build_post))
            raw = meth(pth, ua)
            sport = 40000 + (i % 20000)
            pkt = (
                IP(src=attacker, dst=TARGET_IP)
                / TCP(sport=sport, dport=TARGET_PORT, flags="PA", seq=1000 + i * 100, ack=5000)
                / Raw(load=raw)
            )
            pkt.time = base + i * 0.00025
            packets.append(pkt)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), packets)
        print(f"Wrote {len(packets)} packets to {path}")

    def write_slowloris_pcap(path: Path) -> None:
        """
        Slowloris-style *appearance*: many flows with tiny PSH segments carrying
        fragments of a request (not a full slow socket hold — PCAP is static).
        """
        packets = []
        base = 1_700_000_400.0
        t = 0.0
        n_flows = 120
        parts_per_flow = MAX_PACKETS_PER_FILE // n_flows
        for f in range(n_flows):
            attacker = f"203.0.113.{(f % 200) + 1}"
            sport = 50000 + f
            chunks = [
                b"GET /slow HTTP/1.1\r\n",
                b"Host: " + TARGET_IP.encode() + b"\r\n",
                b"User-Agent: " + random.choice(USER_AGENTS).encode() + b"\r\n",
                b"X-a: " + b"0" * 80 + b"\r\n",
            ]
            for j in range(parts_per_flow):
                chunk = chunks[j % len(chunks)]
                pkt = (
                    IP(src=attacker, dst=TARGET_IP)
                    / TCP(
                        sport=sport,
                        dport=TARGET_PORT,
                        flags="PA",
                        seq=2000 + j * 10,
                        ack=8000,
                    )
                    / Raw(load=chunk)
                )
                pkt.time = base + t
                packets.append(pkt)
                t += 0.05  # spaced in time → "slow" send pattern
        while len(packets) < MAX_PACKETS_PER_FILE:
            pkt = (
                IP(src="198.51.100.9", dst=TARGET_IP)
                / TCP(sport=60000, dport=TARGET_PORT, flags="PA", seq=9999, ack=1)
                / Raw(load=b"X-pad: " + b"z" * 64 + b"\r\n")
            )
            pkt.time = base + t
            packets.append(pkt)
            t += 0.02
        packets = packets[:MAX_PACKETS_PER_FILE]
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), packets)
        print(f"Wrote {len(packets)} packets to {path}")

    if args.mode in ("get", "both"):
        write_get_pcap(out_get)
    if args.mode in ("slowloris", "both"):
        write_slowloris_pcap(out_slow)
    return 0


if __name__ == "__main__":
    sys.exit(main())
