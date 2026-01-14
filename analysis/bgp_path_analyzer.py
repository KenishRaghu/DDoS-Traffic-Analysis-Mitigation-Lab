#!/usr/bin/env python3
"""
bgp_path_analyzer.py — parse BGP UPDATEs from a PCAP (TCP/179 payloads only).

This lab never talks to real routers. We dissect crafted messages to practice
spotting route leaks (unexpected origin AS), long AS paths, and flaps
(withdrawal followed quickly by re-announcement).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, rdpcap
from scapy.contrib.bgp import BGP, BGPUpdate, BGPPAASPath


# Lab ground truth for "expected" origin (from generate_bgp_anomaly.py)
EXPECTED_PREFIX = "198.51.100.0/24"
EXPECTED_ORIGIN_AS = 64512
MAX_NORMAL_AS_PATH_LEN = 8
FLAP_WINDOW_SEC = 0.5


def _prefix_str(nlri) -> str:
    return nlri.prefix if hasattr(nlri, "prefix") else str(nlri)


def _as_path_from_update(upd: BGPUpdate) -> list[int]:
    asns: list[int] = []
    for attr in upd.path_attr:
        if attr.type_code != 2:  # AS_PATH
            continue
        attr_inner = attr.attribute
        if not isinstance(attr_inner, BGPPAASPath):
            continue
        for seg in attr_inner.segments:
            asns.extend(list(seg.segment_value))
    return asns


def analyze_bgp_pcap(path: Path) -> dict[str, Any]:
    pkts = rdpcap(str(path))
    events: list[dict[str, Any]] = []
    unexpected_origin: list[dict[str, Any]] = []
    long_paths: list[dict[str, Any]] = []
    flaps: list[dict[str, Any]] = []

    last_withdraw_ts: dict[str, float] = {}

    for p in pkts:
        if TCP not in p or IP not in p:
            continue
        t = p[TCP]
        if t.sport != 179 and t.dport != 179:
            continue
        pl = bytes(t.payload)
        if len(pl) < 19 or pl[:16] != b"\xff" * 16:
            continue
        ts = float(p.time)
        try:
            layered = BGP(pl)
        except Exception:
            continue
        if not layered.haslayer(BGPUpdate):
            continue
        upd = layered[BGPUpdate]

        w = [_prefix_str(x) for x in upd.withdrawn_routes]
        n = [_prefix_str(x) for x in upd.nlri]
        as_path = _as_path_from_update(upd)
        origin = as_path[-1] if as_path else None
        ev = {
            "time": ts,
            "withdrawn": w,
            "nlri": n,
            "as_path": as_path,
            "origin_as": origin,
            "as_path_length": len(as_path),
        }
        events.append(ev)

        if len(as_path) > MAX_NORMAL_AS_PATH_LEN:
            long_paths.append({"time": ts, "as_path": as_path, "prefixes": n + w})

        for pref in n:
            if pref == EXPECTED_PREFIX and origin is not None and origin != EXPECTED_ORIGIN_AS:
                unexpected_origin.append(
                    {
                        "time": ts,
                        "prefix": pref,
                        "observed_origin_as": origin,
                        "expected_origin_as": EXPECTED_ORIGIN_AS,
                        "as_path": as_path,
                        "confidence": "high",
                        "evidence": "NLRI matches lab prefix but last ASN in AS_PATH != expected",
                    }
                )

        for pref in w:
            last_withdraw_ts[pref] = ts

        for pref in n:
            if pref in last_withdraw_ts and ts - last_withdraw_ts[pref] <= FLAP_WINDOW_SEC:
                flaps.append(
                    {
                        "prefix": pref,
                        "withdraw_time": last_withdraw_ts[pref],
                        "readvertise_time": ts,
                        "delta_sec": round(ts - last_withdraw_ts[pref], 6),
                        "as_path": as_path,
                    }
                )
                # Pair each withdrawal with the first following re-announcement only
                del last_withdraw_ts[pref]

    events.sort(key=lambda e: e["time"])
    report = {
        "source_pcap": str(path.resolve()),
        "expected_prefix": EXPECTED_PREFIX,
        "expected_origin_as": EXPECTED_ORIGIN_AS,
        "bgp_update_event_count": len(events),
        "timeline": events,
        "unexpected_origin_events": unexpected_origin,
        "as_path_length_anomalies": long_paths,
        "route_flaps": flaps,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze BGP UPDATEs in a PCAP.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="JSON output path")
    args = parser.parse_args()

    if not args.pcap.is_file():
        print(f"Not found: {args.pcap}", file=sys.stderr)
        return 1

    rep = analyze_bgp_pcap(args.pcap)
    print(f"BGP UPDATE events: {rep['bgp_update_event_count']}")
    print(f"Unexpected origin flags: {len(rep['unexpected_origin_events'])}")
    print(f"Path-length anomalies:   {len(rep['as_path_length_anomalies'])}")
    print(f"Route flaps detected:    {len(rep['route_flaps'])}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2)
        print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
