#!/usr/bin/env python3
"""
anomaly_detector.py — threshold- and ratio-based detection from traffic_profile JSON.

Designed for interview discussion: each rule maps observable metrics (SYN:ACK,
DNS response/query size, per-source HTTP rate, etc.) to a likely attack class.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_THRESHOLDS: dict[str, Any] = {
    "syn_flood_syn_ack_ratio": 3.0,
    "syn_flood_min_syn_only": 80,
    "single_source_pps": 600.0,
    "dns_response_query_size_ratio": 5.0,
    "http_requests_per_sec_per_source": 25.0,
    "udp_flood_min_avg_packet_bytes": 400.0,
    "udp_flood_min_udp_share": 0.75,
    # Volumetric UDP often uses many spoofed sources — use aggregate rate + packet size
    "udp_flood_min_total_pps": 800.0,
    "bgp_updates_per_second_spike": 120.0,
    "l7_slowloris_min_small_payloads": 400,
    "l7_web_candidate_ports": [80, 8080, 8000, 443, 8443],
}


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def detect(
    profile: dict[str, Any],
    thr: dict[str, Any],
    bgp_report: dict[str, Any] | None,
) -> dict[str, Any]:
    attacks: list[dict[str, Any]] = []
    pcap = profile.get("source_pcap", "")

    sar = profile.get("syn_ack_ratio")
    syn_only = profile.get("tcp_syn_only_count", 0)
    syn_ack = profile.get("tcp_syn_ack_count", 0)
    if sar == "inf":
        sar_val = float("inf")
    else:
        try:
            sar_val = float(sar)
        except (TypeError, ValueError):
            sar_val = 0.0

    if syn_only >= thr["syn_flood_min_syn_only"] and sar_val > thr["syn_flood_syn_ack_ratio"]:
        attacks.append(
            {
                "type": "syn_flood",
                "layer": "L4",
                "confidence": "high",
                "evidence": {
                    "syn_only": syn_only,
                    "syn_ack": syn_ack,
                    "syn_ack_ratio": sar,
                    "note": "Many SYNs without proportional SYN-ACKs → half-open handshake abuse",
                },
            }
        )

    proto = profile.get("protocol_distribution", {})
    total_pkts = max(profile.get("total_packets", 1), 1)
    udp_share = proto.get("UDP", 0) / total_pkts
    avg_sz = profile.get("avg_packet_size_bytes", 0)
    dur = max(profile.get("duration_seconds", 1.0), 1e-9)
    total_pps = total_pkts / dur
    per_src = profile.get("per_source_packets_per_second") or {}
    top_ip, top_pps = (None, 0.0)
    if per_src:
        top_ip, top_pps = max(per_src.items(), key=lambda kv: kv[1])

    dns_ratio_early = profile.get("dns_response_to_query_size_ratio")
    dns_like = dns_ratio_early is not None and dns_ratio_early > thr["dns_response_query_size_ratio"]

    udp_volumetric = (
        udp_share >= thr["udp_flood_min_udp_share"]
        and avg_sz >= thr["udp_flood_min_avg_packet_bytes"]
        and total_pps >= thr["udp_flood_min_total_pps"]
        and not dns_like
    )
    udp_single_source = top_pps > thr["single_source_pps"] and udp_share >= 0.5 and not dns_like
    if udp_volumetric or udp_single_source:
        top_ports = profile.get("top_destination_ports") or []
        attacks.append(
            {
                "type": "udp_flood",
                "layer": "L3/L4",
                "confidence": "high" if udp_volumetric else "medium",
                "evidence": {
                    "top_source_ip": top_ip,
                    "top_source_pps": top_pps,
                    "aggregate_pps": round(total_pps, 2),
                    "udp_share": round(udp_share, 4),
                    "avg_packet_size_bytes": avg_sz,
                    "top_destination_ports": top_ports[:8],
                },
            }
        )

    dns_ratio = profile.get("dns_response_to_query_size_ratio")
    if dns_ratio is not None and dns_ratio > thr["dns_response_query_size_ratio"]:
        attacks.append(
            {
                "type": "dns_amplification",
                "layer": "L3/L4",
                "confidence": "high",
                "evidence": {
                    "response_to_query_size_ratio": dns_ratio,
                    "avg_query_bytes": profile.get("dns_avg_query_packet_bytes"),
                    "avg_response_bytes": profile.get("dns_avg_response_packet_bytes"),
                    "query_types": profile.get("dns_query_type_distribution"),
                },
            }
        )

    http_rps = profile.get("http_request_like_per_source_per_sec") or {}
    max_http = max(http_rps.values()) if http_rps else 0.0
    for ip, rate in http_rps.items():
        if rate > thr["http_requests_per_sec_per_source"]:
            attacks.append(
                {
                    "type": "http_flood",
                    "layer": "L7",
                    "confidence": "high",
                    "evidence": {
                        "source_ip": ip,
                        "http_like_requests_per_sec": rate,
                        "note": "GET/POST-shaped payloads in TCP streams to likely web port",
                    },
                }
            )
            break

    small_n = profile.get("l7_small_tcp_payload_count") or 0
    sdport = profile.get("l7_small_tcp_payload_top_dport")
    web_ports = thr.get("l7_web_candidate_ports") or []
    if (
        small_n >= thr["l7_slowloris_min_small_payloads"]
        and sdport in web_ports
        and max_http < thr["http_requests_per_sec_per_source"]
    ):
        attacks.append(
            {
                "type": "http_slowloris_style",
                "layer": "L7",
                "confidence": "medium",
                "evidence": {
                    "small_psh_payload_count": small_n,
                    "destination_port": sdport,
                    "max_get_post_like_rps": max_http,
                    "note": "Many tiny PSH segments toward a web port without high full-request rate",
                },
            }
        )

    bgp_upd = profile.get("bgp_update_messages_seen") or 0
    ups = bgp_upd / dur
    if ups > thr["bgp_updates_per_second_spike"]:
        attacks.append(
            {
                "type": "bgp_anomaly",
                "layer": "control_plane",
                "confidence": "medium",
                "evidence": {
                    "bgp_update_messages": bgp_upd,
                    "updates_per_second": round(ups, 2),
                    "note": "High UPDATE rate in capture window (possible instability or session replay)",
                },
            }
        )

    if bgp_report:
        uo = bgp_report.get("unexpected_origin_events") or []
        rf = bgp_report.get("route_flaps") or []
        if uo:
            attacks.append(
                {
                    "type": "bgp_route_leak_or_hijack_indicator",
                    "layer": "control_plane",
                    "confidence": "high",
                    "evidence": {
                        "unexpected_origin_count": len(uo),
                        "sample": uo[0],
                    },
                }
            )
        if len(rf) >= 3:
            attacks.append(
                {
                    "type": "bgp_route_flap",
                    "layer": "control_plane",
                    "confidence": "medium",
                    "evidence": {
                        "flap_events": len(rf),
                        "sample": rf[0],
                    },
                }
            )

    return {
        "source_profile": pcap,
        "thresholds_used": thr,
        "detected_attacks": attacks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run threshold detection on a traffic profile JSON.")
    parser.add_argument("profile_json", type=Path)
    parser.add_argument(
        "--thresholds",
        type=Path,
        help="Optional JSON file overriding default thresholds",
    )
    parser.add_argument(
        "--bgp-analysis",
        type=Path,
        help="Optional bgp_path_analyzer JSON for control-plane findings",
    )
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    profile = _load_json(args.profile_json)
    thr = dict(DEFAULT_THRESHOLDS)
    if args.thresholds:
        thr.update(_load_json(args.thresholds))

    bgp_rep = _load_json(args.bgp_analysis) if args.bgp_analysis and args.bgp_analysis.is_file() else None

    result = detect(profile, thr, bgp_rep)

    print(f"Profile: {result['source_profile']}")
    print(f"Findings: {len(result['detected_attacks'])}")
    for a in result["detected_attacks"]:
        print(f"  - [{a['confidence']}] {a['type']} ({a['layer']})")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
