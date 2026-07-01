#!/usr/bin/env python3
"""
Failure Case Analysis
======================

Identifies and quantifies system failure modes.
Produces honest metrics for the Limitations section.

Failure modes:
1. Quick disconnect (<2s)
2. Protocol rejection (non-MAVLink data)
3. Deception detected (entropy spike mid-session)
4. Scanner dominance (most traffic = scanners)
5. Single-visit (no return engagement)

Usage::
    python analysis/failure_analysis.py --labeled analysis/labeled_sessions.csv
"""

import csv
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def analyze_failures(labeled_path, output_path="analysis/failure_report.json"):
    """Full failure mode analysis."""
    with open(labeled_path, newline="") as f:
        sessions = list(csv.DictReader(f))

    if not sessions:
        print("No sessions found.")
        return

    total = len(sessions)
    print("=" * 60)
    print("  Failure Case Analysis")
    print("=" * 60)
    print(f"  Total sessions: {total}")

    # ── 1. Quick Disconnect ───────────────────────────────────
    quick = [s for s in sessions if float(s.get("duration_sec", 0)) < 2]
    print(f"\n1. QUICK DISCONNECT (<2s)")
    print(f"   Count: {len(quick)} ({len(quick)/total*100:.1f}%)")
    if quick:
        # Breakdown by type
        quick_labels = Counter(s.get("label_rule", "UNKNOWN") for s in quick)
        for label, count in quick_labels.most_common():
            print(f"     {label}: {count}")

    # ── 2. Single-Packet Sessions ─────────────────────────────
    single_pkt = [s for s in sessions if int(s.get("packet_count", 0)) <= 1]
    print(f"\n2. SINGLE-PACKET SESSIONS")
    print(f"   Count: {len(single_pkt)} ({len(single_pkt)/total*100:.1f}%)")

    # ── 3. Scanner Dominance ──────────────────────────────────
    scanners = [s for s in sessions if s.get("label_rule") == "SCANNER"]
    engaged = [s for s in sessions if float(s.get("duration_sec", 0)) > 5 and int(s.get("packet_count", 0)) >= 2]
    print(f"\n3. SCANNER DOMINANCE")
    print(f"   Scanners:    {len(scanners)} ({len(scanners)/total*100:.1f}%)")
    print(f"   Engaged:     {len(engaged)} ({len(engaged)/total*100:.1f}%)")
    print(f"   →  Tier 2 rate: {len(engaged)/total*100:.1f}%")

    # ── 4. Deception Detected (Entropy Spike) ─────────────────
    # Sessions where entropy drops sharply in second half = attacker "caught on"
    deception_detected = 0
    for s in sessions:
        cmd_entropy = float(s.get("command_entropy", 0))
        state_changes = int(s.get("state_changes", 0))
        duration = float(s.get("duration_sec", 0))
        # Proxy: high entropy + sudden disconnect (short duration despite many msg types)
        if cmd_entropy > 1.5 and duration < 10 and int(s.get("unique_msg_ids", 0)) >= 3:
            deception_detected += 1

    print(f"\n4. POSSIBLE DECEPTION DETECTION")
    print(f"   Suspected: {deception_detected} ({deception_detected/total*100:.1f}%)")
    print(f"   (Sessions with high entropy but quick abort)")

    # ── 5. Single-Visit (No Return) ──────────────────────────
    ip_counts = Counter(s.get("ip", "") for s in sessions)
    single_visit = sum(1 for c in ip_counts.values() if c == 1)
    total_ips = len(ip_counts)
    print(f"\n5. SINGLE-VISIT (NO RETURN)")
    print(f"   Single-visit IPs: {single_visit} ({single_visit/total_ips*100:.1f}%)")
    print(f"   Returning IPs:    {total_ips - single_visit} ({(total_ips - single_visit)/total_ips*100:.1f}%)")

    # ── 6. Mode-Specific Failures ─────────────────────────────
    print(f"\n6. FAILURE BY MODE")
    for mode in ["adaptive", "static"]:
        mode_sessions = [s for s in sessions if s.get("mode", "adaptive") == mode]
        if mode_sessions:
            mode_quick = sum(1 for s in mode_sessions if float(s.get("duration_sec", 0)) < 2)
            mode_engaged = sum(1 for s in mode_sessions if float(s.get("duration_sec", 0)) > 5)
            print(f"   {mode.upper()}:")
            print(f"     Total: {len(mode_sessions)}, Quick-DC: {mode_quick} ({mode_quick/len(mode_sessions)*100:.0f}%), Engaged: {mode_engaged} ({mode_engaged/len(mode_sessions)*100:.0f}%)")

    # ── Summary Report ────────────────────────────────────────
    report = {
        "total_sessions": total,
        "failures": {
            "quick_disconnect_pct": round(len(quick) / total * 100, 1),
            "single_packet_pct": round(len(single_pkt) / total * 100, 1),
            "scanner_dominance_pct": round(len(scanners) / total * 100, 1),
            "deception_detected_pct": round(deception_detected / total * 100, 1),
            "single_visit_pct": round(single_visit / total_ips * 100, 1),
        },
        "tier2_engagement_rate": round(len(engaged) / total * 100, 1),
        "paper_statement": (
            f"Of {total} total sessions, {len(quick)} ({len(quick)/total*100:.1f}%) "
            f"resulted in immediate disconnection (<2s). {len(scanners)} ({len(scanners)/total*100:.1f}%) "
            f"were automated scanners with no meaningful engagement. "
            f"In {deception_detected} cases ({deception_detected/total*100:.1f}%), we observed behavioral "
            f"patterns suggesting the attacker may have detected the deception."
        ),
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Report saved → {output_path}")
    print(f"\n📝 Paper statement:")
    print(f'   "{report["paper_statement"]}"')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--labeled", default="analysis/labeled_sessions.csv")
    parser.add_argument("--output", default="analysis/failure_report.json")
    args = parser.parse_args()
    analyze_failures(args.labeled, args.output)
