#!/usr/bin/env bash
# Regenerate all synthetic PCAPs for the lab (local only, no network required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ROOT
cd "$ROOT"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

if [[ -x "${ROOT}/.venv/bin/python" ]]; then
  PY="${ROOT}/.venv/bin/python"
else
  PY="python3"
fi

"${PY}" attacks/generate_syn_flood.py
"${PY}" attacks/generate_udp_flood.py
"${PY}" attacks/generate_dns_amplification.py
"${PY}" attacks/generate_http_flood.py --mode both
"${PY}" attacks/generate_bgp_anomaly.py

"${PY}" - <<'PY'
"""Embedded baseline generator — normal browsing-like mix (PCAP only)."""
import os
from pathlib import Path
from scapy.all import IP, TCP, UDP, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR

root = Path(os.environ["ROOT"])
out = root / "pcaps" / "baseline_normal.pcap"
client = "192.0.2.88"
server_web = "192.0.2.50"
server_dns = "192.0.2.53"
packets = []
t = 1_700_000_600.0
MAX_PACKETS = 800

def add(pkt, dt=0.01):
    global t
    pkt.time = t
    packets.append(pkt)
    t += dt

# DNS lookups
for name in ("www.example.lab.", "cdn.example.lab.", "api.example.lab."):
    add(
        IP(src=client, dst=server_dns)
        / UDP(sport=53000, dport=53)
        / DNS(qd=DNSQR(qname=name, qtype=1)),
        0.02,
    )
    add(
        IP(src=server_dns, dst=client)
        / UDP(sport=53, dport=53000)
        / DNS(qd=DNSQR(qname=name, qtype=1), an=None, qr=1, aa=1),
        0.02,
    )

# TCP handshakes + short HTTP GET (simplified happy path)
for i in range(25):
    sport = 40000 + i
    add(IP(src=client, dst=server_web) / TCP(sport=sport, dport=80, flags="S", seq=1000 * i), 0.005)
    add(
        IP(src=server_web, dst=client) / TCP(sport=80, dport=sport, flags="SA", seq=5000, ack=1000 * i + 1),
        0.005,
    )
    add(
        IP(src=client, dst=server_web)
        / TCP(sport=sport, dport=80, flags="A", seq=1000 * i + 1, ack=5001),
        0.005,
    )
    body = (
        f"GET /page{i % 5}.html HTTP/1.1\r\nHost: {server_web}\r\n"
        "User-Agent: Mozilla/5.0 (compatible; LabBrowser/1.0)\r\n\r\n"
    ).encode()
    add(
        IP(src=client, dst=server_web)
        / TCP(sport=sport, dport=80, flags="PA", seq=1000 * i + 1, ack=5001)
        / Raw(load=body),
        0.01,
    )
    add(
        IP(src=server_web, dst=client)
        / TCP(sport=80, dport=sport, flags="PA", seq=5001, ack=1000 * i + 1 + len(body))
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello lab!\n"),
        0.01,
    )

while len(packets) < MAX_PACKETS:
    add(
        IP(src=client, dst=server_web)
        / UDP(sport=44000, dport=443)
        / Raw(load=b"\x16\x03\x01\x00\x05" + b"\x00" * 20),
        0.003,
    )

packets = packets[: min(len(packets), 1999)]
out.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(out), packets)
print(f"Wrote {len(packets)} packets to {out}")
PY

echo "All PCAPs generated under ${ROOT}/pcaps/"
