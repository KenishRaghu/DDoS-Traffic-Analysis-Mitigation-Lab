#!/usr/bin/env python3
"""
================================================================================
LAB / EDUCATIONAL USE ONLY — DO NOT USE ON NETWORKS YOU DO NOT OWN OR OPERATE
================================================================================
Crafts BGP UPDATE messages inside TCP/179 payloads for offline PCAP analysis.
This is NOT for injection into real BGP speakers — only for protocol study and
Wireshark/Python parsing practice (route leak / unexpected origin / flap).
================================================================================
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

MAX_PACKETS = 1999
# Lab ASNs (private use range 64512–65534)
EXPECTED_ORIGIN_AS = 64512
# 16-bit ASN space only in this PCAP (Scapy default AS_PATH encoding)
UNEXPECTED_ORIGIN_AS = 65001
PREFIX = "198.51.100.0/24"
PEER_A = "192.0.2.10"
PEER_B = "192.0.2.11"


def _bgp_update(
    withdrawn: list,
    nlri: list,
    as_path_segments: list | None,
    next_hop: str | None,
):
    from scapy.contrib.bgp import (
        BGPHeader,
        BGPUpdate,
        BGPPathAttr,
        BGPPAASPath,
        BGPPANextHop,
        BGPPAOrigin,
        BGPNLRI_IPv4,
    )

    if not withdrawn and not nlri:
        raise ValueError("withdrawn and nlri cannot both be empty")

    # Withdrawal-only UPDATEs typically carry no path attributes (RFC 4271).
    if not nlri:
        return BGPHeader(type=2) / BGPUpdate(
            withdrawn_routes=withdrawn,
            path_attr=[],
            nlri=[],
        )

    attrs = [
        BGPPathAttr(type_code=1, attribute=BGPPAOrigin(origin=0)),
    ]
    segs = []
    for seg_type, asns in as_path_segments or []:
        segs.append(
            BGPPAASPath.ASPathSegment(segment_type=seg_type, segment_value=asns),
        )
    attrs.append(BGPPathAttr(type_code=2, attribute=BGPPAASPath(segments=segs)))
    attrs.append(BGPPathAttr(type_code=3, attribute=BGPPANextHop(next_hop=next_hop or "0.0.0.0")))
    return BGPHeader(type=2) / BGPUpdate(
        withdrawn_routes=withdrawn,
        path_attr=attrs,
        nlri=nlri,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate BGP anomaly / flap PCAP (lab only, PCAP analysis).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-o", "--output", default=None)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out = Path(args.output) if args.output else repo_root / "pcaps" / "bgp_anomaly.pcap"

    if args.dry_run:
        print(f"[dry-run] Would write <= {MAX_PACKETS} IP/TCP/BGP frames to {out}")
        print(
            f"[dry-run] Scenario: {PREFIX} normally from AS{EXPECTED_ORIGIN_AS}, "
            f"then unexpected origin AS{UNEXPECTED_ORIGIN_AS}, withdraw, re-announce (flap)"
        )
        return 0

    from scapy.contrib.bgp import BGPNLRI_IPv4
    from scapy.all import IP, TCP, wrpcap  # noqa: WPS433

    nh = "192.0.2.1"
    prefix_nlri = [BGPNLRI_IPv4(prefix=PREFIX)]

    # 1) Legitimate announcement: AS_PATH ends at expected origin
    good = _bgp_update(
        [],
        prefix_nlri,
        [(2, [64511, EXPECTED_ORIGIN_AS])],
        nh,
    )
    # 2) Route leak / hijack appearance: unexpected origin at end of path
    bad = _bgp_update(
        [],
        prefix_nlri,
        [(2, [64511, UNEXPECTED_ORIGIN_AS])],
        nh,
    )
    # 3) Withdrawal
    wdraw = _bgp_update([BGPNLRI_IPv4(prefix=PREFIX)], [], None, None)
    # 4) Re-announcement (flap) — same as good, shortly after
    flap = _bgp_update(
        [],
        prefix_nlri,
        [(2, [64511, EXPECTED_ORIGIN_AS])],
        nh,
    )

    messages = [good, bad, wdraw, flap]
    # Repeat and interleave KEEPALIVE-sized noise using small UPDATE bursts to stay < MAX_PACKETS
    packets = []
    base = 1_700_000_500.0
    t = 0.0
    seq_a = 1000
    seq_b = 5000
    msg_round = 0
    while len(packets) < min(400, MAX_PACKETS):
        for m in messages:
            raw = bytes(m)
            # A -> B (eBGP session)
            pkt = (
                IP(src=PEER_A, dst=PEER_B)
                / TCP(sport=179, dport=179, flags="PA", seq=seq_a, ack=seq_b)
                / raw
            )
            pkt.time = base + t
            packets.append(pkt)
            t += 0.001
            seq_a += len(raw)
            msg_round += 1
        # Reverse direction ACK-only (simplified)
        ack = IP(src=PEER_B, dst=PEER_A) / TCP(
            sport=179, dport=179, flags="A", seq=seq_b, ack=seq_a
        )
        ack.time = base + t
        packets.append(ack)
        t += 0.0005
        seq_b = seq_a

    # Spike: many duplicate "bad" updates in short window
    spike_start = t
    while len(packets) < MAX_PACKETS and (t - spike_start) < 0.05:
        raw = bytes(bad)
        pkt = IP(src=PEER_A, dst=PEER_B) / TCP(
            sport=179, dport=179, flags="PA", seq=seq_a, ack=seq_b
        ) / raw
        pkt.time = base + t
        packets.append(pkt)
        t += 0.0002
        seq_a += len(raw)

    packets = packets[:MAX_PACKETS]
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Wrote {len(packets)} packets to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
