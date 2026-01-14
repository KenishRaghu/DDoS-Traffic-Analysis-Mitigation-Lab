#!/usr/bin/env python3
"""
traffic_analyzer.py — build a traffic profile from any PCAP using Scapy.

Interview notes (why these metrics):
  • SYN:ACK ratio: In a healthy TCP handshake you see one SYN and one SYN-ACK per
    new flow. A SYN flood sends many SYNs without completing handshakes, so
    SYNs (SYN-only) pile up relative to SYN-ACKs → ratio climbs.
  • DNS amplification: small queries (often spoofed src) vs large responses.
    Comparing mean response size to mean query size approximates amplifier gain.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, UDP, Raw, rdpcap  # noqa: S404 — lab tool
from scapy.layers.dns import DNS


def _tcp_flags(pkt) -> tuple[bool, bool, bool]:
    """Returns (is_syn, is_ack, is_syn_ack)."""
    if TCP not in pkt:
        return False, False, False
    t = pkt[TCP]
    f = t.flags
    syn = bool(f & 0x02)
    ack = bool(f & 0x10)
    return syn, ack, syn and ack


def _bucket_key(ts: float, start: float, width: float) -> int:
    return int((ts - start) / width)


def analyze_pcap(path: Path, bucket_width: float = 0.1) -> dict[str, Any]:
    pkts = rdpcap(str(path))
    if not pkts:
        return {
            "source_pcap": str(path),
            "error": "empty_pcap",
            "total_packets": 0,
        }

    times = [float(p.time) for p in pkts]
    t0, t1 = min(times), max(times)
    duration = max(t1 - t0, 1e-9)

    proto_counter: Counter[str] = Counter()
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    dport_counter: Counter[int] = Counter()
    syn_only = 0
    syn_ack = 0
    pure_ack = 0
    total_bytes = 0
    dns_qtypes: Counter[str] = Counter()
    dns_query_sizes: list[int] = []
    dns_response_sizes: list[int] = []
    http_methods_per_src: Counter[str] = Counter()
    bgp_tcp_segments = 0
    bgp_update_messages = 0
    # Small TCP payloads (possible slow header dribbling / L7 connection exhaustion pattern)
    small_tcp_payload_by_dport: Counter[int] = Counter()
    per_src_packets: Counter[str] = Counter()
    bucket_counts: Counter[int] = Counter()

    for p in pkts:
        total_bytes += len(p)
        ts = float(p.time)
        bucket_counts[_bucket_key(ts, t0, bucket_width)] += 1

        if IP not in p:
            continue
        ip = p[IP]
        src, dst = ip.src, ip.dst
        per_src_packets[src] += 1
        src_counter[src] += 1
        dst_counter[dst] += 1

        proto = ip.proto
        if proto == 6:
            proto_counter["TCP"] += 1
            if TCP in p:
                dport_counter[p[TCP].dport] += 1
                syn, ack, is_sa = _tcp_flags(p)
                if syn and not ack:
                    syn_only += 1
                elif is_sa:
                    syn_ack += 1
                elif ack and not syn:
                    pure_ack += 1
                if Raw in p:
                    load = bytes(p[Raw].load)
                    if load.startswith(b"GET ") or load.startswith(b"POST "):
                        http_methods_per_src[src] += 1
                    fl = p[TCP].flags
                    if (fl & 0x08) and len(load) > 0 and len(load) < 128:
                        small_tcp_payload_by_dport[p[TCP].dport] += 1
                # BGP over TCP: port 179, marker 0xFF * 16
                pl = bytes(p[TCP].payload) if p[TCP].payload else b""
                if p[TCP].sport == 179 or p[TCP].dport == 179:
                    if len(pl) >= 19 and pl[:16] == b"\xff" * 16:
                        bgp_tcp_segments += 1
                        if len(pl) > 18 and pl[18] == 2:
                            bgp_update_messages += 1
        elif proto == 17:
            proto_counter["UDP"] += 1
            if UDP in p:
                dport_counter[p[UDP].dport] += 1
            if DNS in p:
                d = p[DNS]
                qtype = "UNKNOWN"
                qd = d.qd
                if qd is not None:
                    qlist = qd if isinstance(qd, list) else [qd]
                    for qr in qlist:
                        if hasattr(qr, "qtype"):
                            qtype = str(int(qr.qtype))
                            break
                dns_qtypes[qtype] += 1
                if d.qr == 0:
                    dns_query_sizes.append(len(p))
                else:
                    dns_response_sizes.append(len(p))
        else:
            proto_counter[f"IP_PROTO_{proto}"] += 1

    n = len(pkts)
    avg_size = total_bytes / n

    if syn_ack == 0:
        syn_ack_ratio = float("inf") if syn_only > 0 else 0.0
    else:
        syn_ack_ratio = syn_only / syn_ack

    timeline = []
    nb = max(bucket_counts.keys(), default=0) + 1
    for b in range(nb):
        cnt = bucket_counts[b]
        if cnt == 0:
            continue
        timeline.append(
            {
                "t_start": round(t0 + b * bucket_width, 6),
                "t_end": round(t0 + (b + 1) * bucket_width, 6),
                "packets": cnt,
                "pps": round(cnt / bucket_width, 2),
            }
        )

    top_sources = [{"ip": ip, "count": c} for ip, c in src_counter.most_common(15)]
    top_dports = [{"port": port, "count": c} for port, c in dport_counter.most_common(15)]

    dns_ratio = None
    if dns_query_sizes and dns_response_sizes:
        mq = sum(dns_query_sizes) / len(dns_query_sizes)
        mr = sum(dns_response_sizes) / len(dns_response_sizes)
        dns_ratio = mr / max(mq, 1e-9)

    per_src_pps = {ip: round(c / duration, 4) for ip, c in per_src_packets.items()}

    http_rps = {ip: round(c / duration, 4) for ip, c in http_methods_per_src.items()}

    top_small_dport = None
    top_small_count = 0
    if small_tcp_payload_by_dport:
        top_small_dport, top_small_count = small_tcp_payload_by_dport.most_common(1)[0]

    return {
        "source_pcap": str(path.resolve()),
        "total_packets": n,
        "duration_seconds": round(duration, 6),
        "avg_packet_size_bytes": round(avg_size, 4),
        "protocol_distribution": dict(proto_counter),
        "top_source_ips": top_sources,
        "top_destination_ports": top_dports,
        "tcp_syn_only_count": syn_only,
        "tcp_syn_ack_count": syn_ack,
        "tcp_pure_ack_count": pure_ack,
        "syn_ack_ratio": syn_ack_ratio if math.isfinite(syn_ack_ratio) else "inf",
        "dns_query_type_distribution": {str(k): v for k, v in dns_qtypes.items()},
        "dns_avg_query_packet_bytes": round(sum(dns_query_sizes) / len(dns_query_sizes), 4)
        if dns_query_sizes
        else None,
        "dns_avg_response_packet_bytes": round(sum(dns_response_sizes) / len(dns_response_sizes), 4)
        if dns_response_sizes
        else None,
        "dns_response_to_query_size_ratio": round(dns_ratio, 4) if dns_ratio is not None else None,
        "http_request_like_per_source_per_sec": http_rps,
        "packets_per_second_timeline": timeline,
        "per_source_packets_per_second": per_src_pps,
        "bgp_tcp_segments_seen": bgp_tcp_segments,
        "bgp_update_messages_seen": bgp_update_messages,
        "l7_small_tcp_payload_count": top_small_count,
        "l7_small_tcp_payload_top_dport": top_small_dport,
    }


def print_summary(profile: dict[str, Any]) -> None:
    if profile.get("error"):
        print(f"Error: {profile['error']}")
        return
    print("Traffic profile summary")
    print("-" * 52)
    print(f"  PCAP:              {profile['source_pcap']}")
    print(f"  Packets:           {profile['total_packets']}")
    print(f"  Duration (s):      {profile['duration_seconds']}")
    print(f"  Avg size (B):      {profile['avg_packet_size_bytes']}")
    sar = profile["syn_ack_ratio"]
    sar_s = "inf" if sar == "inf" else f"{float(sar):.4f}"
    print(f"  SYN-only / SYN-ACK: {sar_s}")
    print(f"  Top 5 sources:     {profile['top_source_ips'][:5]}")
    print(f"  Top 5 dports:      {profile['top_destination_ports'][:5]}")
    print(f"  Protos:            {profile['protocol_distribution']}")
    dnsr = profile.get("dns_response_to_query_size_ratio")
    if dnsr is not None:
        print(f"  DNS resp/qry size: {dnsr}")
    if profile.get("bgp_tcp_segments_seen"):
        print(f"  BGP (TCP/179) seg: {profile['bgp_tcp_segments_seen']}")
    if profile.get("bgp_update_messages_seen"):
        print(f"  BGP UPDATE msgs:   {profile['bgp_update_messages_seen']}")
    if profile.get("l7_small_tcp_payload_count"):
        print(
            f"  Small TCP payloads (<128B, PSH): {profile['l7_small_tcp_payload_count']} "
            f"(top dport {profile['l7_small_tcp_payload_top_dport']})"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze PCAP → traffic profile JSON.")
    parser.add_argument("pcap", type=Path, help="Input PCAP file")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON profile here")
    parser.add_argument(
        "--bucket-width",
        type=float,
        default=0.1,
        help="Seconds per timeline bucket (default 0.1)",
    )
    args = parser.parse_args()

    if not args.pcap.is_file():
        print(f"Not found: {args.pcap}", file=sys.stderr)
        return 1

    profile = analyze_pcap(args.pcap, bucket_width=args.bucket_width)
    # JSON cannot serialize inf — use string
    if profile.get("syn_ack_ratio") == float("inf"):
        profile["syn_ack_ratio"] = "inf"

    print_summary(profile)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        print(f"\nWrote JSON → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
