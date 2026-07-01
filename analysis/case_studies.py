#!/usr/bin/env python3
"""
Case Study Selector — Automated Example Finding
==================================================

Finds the best case study examples from data for the paper:
- Same-IP sessions crossing ON/OFF boundaries
- Sessions showing adaptive vs static response differences
- Most interesting attack sequences

Usage::
    python analysis/case_studies.py --labeled analysis/labeled_sessions.csv
"""

import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def find_case_studies(labeled_path, output_path="analysis/case_studies.json"):
    """Find best case study examples."""
    with open(labeled_path, newline="") as f:
        sessions = list(csv.DictReader(f))

    if not sessions:
        print("No sessions found.")
        return

    print("=" * 60)
    print("  Case Study Selector")
    print("=" * 60)

    # Group by IP
    ip_sessions = defaultdict(list)
    for s in sessions:
        ip_sessions[s.get("ip", "unknown")].append(s)

    case_studies = []

    # ── 1. ON/OFF Boundary Crossers ──────────────────────────
    print("\n1. SAME-IP CROSSING ON/OFF BOUNDARY")
    boundary_crossers = {}
    for ip, slist in ip_sessions.items():
        modes = set(s.get("mode", "adaptive") for s in slist)
        if "adaptive" in modes and "static" in modes:
            adaptive_sessions = [s for s in slist if s.get("mode") == "adaptive"]
            static_sessions = [s for s in slist if s.get("mode") == "static"]
            boundary_crossers[ip] = {
                "adaptive": adaptive_sessions,
                "static": static_sessions,
            }

    if boundary_crossers:
        print(f"   Found {len(boundary_crossers)} IPs crossing ON/OFF boundary")
        for ip, data in list(boundary_crossers.items())[:3]:
            a_dur = [float(s.get("duration_sec", 0)) for s in data["adaptive"]]
            s_dur = [float(s.get("duration_sec", 0)) for s in data["static"]]
            a_ent = [float(s.get("command_entropy", 0)) for s in data["adaptive"]]
            s_ent = [float(s.get("command_entropy", 0)) for s in data["static"]]

            a_mean_dur = sum(a_dur) / len(a_dur) if a_dur else 0
            s_mean_dur = sum(s_dur) / len(s_dur) if s_dur else 0
            ratio = a_mean_dur / s_mean_dur if s_mean_dur > 0 else 0

            case = {
                "type": "on_off_crosser",
                "ip": ip,
                "adaptive_sessions": len(data["adaptive"]),
                "static_sessions": len(data["static"]),
                "adaptive_mean_duration": round(a_mean_dur, 1),
                "static_mean_duration": round(s_mean_dur, 1),
                "duration_ratio": round(ratio, 1),
                "adaptive_mean_entropy": round(sum(a_ent)/len(a_ent), 2) if a_ent else 0,
                "static_mean_entropy": round(sum(s_ent)/len(s_ent), 2) if s_ent else 0,
            }
            case_studies.append(case)
            print(f"\n   IP: {ip}")
            print(f"     Adaptive: {case['adaptive_sessions']} sessions, mean duration {case['adaptive_mean_duration']}s")
            print(f"     Static:   {case['static_sessions']} sessions, mean duration {case['static_mean_duration']}s")
            print(f"     Duration ratio: {case['duration_ratio']}x")
    else:
        print("   None found yet (need data from both ON and OFF periods)")

    # ── 2. Most Engaged Attacker ─────────────────────────────
    print("\n2. MOST ENGAGED ATTACKER (Longest session)")
    longest = max(sessions, key=lambda s: float(s.get("duration_sec", 0)))
    print(f"   IP: {longest.get('ip')}")
    print(f"   Duration: {longest.get('duration_sec')}s")
    print(f"   Packets: {longest.get('packet_count')}")
    print(f"   Entropy: {longest.get('command_entropy')}")
    print(f"   Label: {longest.get('label_rule')}")
    print(f"   Mode: {longest.get('mode')}")

    case_studies.append({
        "type": "longest_session",
        "ip": longest.get("ip"),
        "duration": float(longest.get("duration_sec", 0)),
        "packets": int(longest.get("packet_count", 0)),
        "entropy": float(longest.get("command_entropy", 0)),
        "label": longest.get("label_rule"),
    })

    # ── 3. Most Sophisticated (Highest Entropy) ──────────────
    print("\n3. MOST SOPHISTICATED ATTACKER (Highest entropy)")
    highest_ent = max(sessions, key=lambda s: float(s.get("command_entropy", 0)))
    print(f"   IP: {highest_ent.get('ip')}")
    print(f"   Command entropy: {highest_ent.get('command_entropy')}")
    print(f"   Sequence entropy: {highest_ent.get('sequence_entropy')}")
    print(f"   Unique msg_ids: {highest_ent.get('unique_msg_ids')}")
    print(f"   Label: {highest_ent.get('label_rule')}")

    case_studies.append({
        "type": "highest_entropy",
        "ip": highest_ent.get("ip"),
        "command_entropy": float(highest_ent.get("command_entropy", 0)),
        "sequence_entropy": float(highest_ent.get("sequence_entropy", 0)),
        "unique_msg_ids": int(highest_ent.get("unique_msg_ids", 0)),
        "label": highest_ent.get("label_rule"),
    })

    # ── 4. Escalating Attacker ────────────────────────────────
    print("\n4. ESCALATING ATTACKER (RECON → HIJACK)")
    escalators = [s for s in sessions if int(s.get("escalation_depth", 0)) >= 3]
    if escalators:
        best_esc = max(escalators, key=lambda s: int(s.get("escalation_depth", 0)))
        print(f"   IP: {best_esc.get('ip')}")
        print(f"   Escalation depth: {best_esc.get('escalation_depth')}")
        print(f"   Has RECON: {best_esc.get('has_recon')}")
        print(f"   Has CONTROL: {best_esc.get('has_control')}")
        print(f"   Has HIJACK: {best_esc.get('has_hijack')}")
        case_studies.append({
            "type": "escalating_attacker",
            "ip": best_esc.get("ip"),
            "escalation_depth": int(best_esc.get("escalation_depth", 0)),
        })
    else:
        print("   None found yet")

    # ── 5. Learning Attacker (Entropy increases over visits) ──
    print("\n5. LEARNING ATTACKER (entropy increases over visits)")
    for ip, slist in ip_sessions.items():
        if len(slist) >= 3:
            entropies = [float(s.get("command_entropy", 0)) for s in slist]
            if entropies[-1] > entropies[0] * 1.5:
                print(f"   IP: {ip}")
                print(f"   Visits: {len(slist)}")
                print(f"   Entropy: {entropies[0]:.2f} → {entropies[-1]:.2f} (↑{(entropies[-1]/max(entropies[0],0.01)-1)*100:.0f}%)")
                case_studies.append({
                    "type": "learning_attacker",
                    "ip": ip,
                    "visits": len(slist),
                    "first_entropy": entropies[0],
                    "last_entropy": entropies[-1],
                })
                break
    else:
        print("   None found yet (need returning attackers)")

    # Save
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(case_studies, f, indent=2)

    print(f"\n✅ {len(case_studies)} case studies saved → {output_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--labeled", default="analysis/labeled_sessions.csv")
    parser.add_argument("--output", default="analysis/case_studies.json")
    args = parser.parse_args()
    find_case_studies(args.labeled, args.output)
