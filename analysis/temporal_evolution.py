#!/usr/bin/env python3
"""
Temporal Evolution Analysis
============================

Analyzes how attacker behavior changes over the deployment period.

Analyses:
1. Day 1 vs Day 30 comparison
2. Returning attacker learning (entropy over visits)
3. Deception decay (effectiveness over time)
4. Traffic volume trend (post-Shodan indexing)
5. Entropy drift (weekly distributions)
6. ON/OFF mode comparison over time

Usage::
    python analysis/temporal_evolution.py --data datasets/ --labeled analysis/labeled_sessions.csv
"""

import csv
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_labeled(path):
    """Load labeled session features."""
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def parse_date(ts_str):
    """Parse timestamp string to date."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).date()
    except (ValueError, AttributeError):
        return None


def week_number(date, start_date):
    """Get week number relative to deployment start."""
    delta = (date - start_date).days
    return delta // 7 + 1


# ── Analysis Functions ────────────────────────────────────────

def traffic_volume_trend(sessions, start_date):
    """Analyze daily/weekly traffic volume."""
    daily = Counter()
    for s in sessions:
        # Use session_id timestamp or extract from data
        day = start_date  # placeholder, will use actual timestamps
        try:
            # Try to extract from session data if available
            ts_str = s.get("timestamp", s.get("session_id", ""))
            day = parse_date(ts_str) or start_date
        except Exception:
            pass
        daily[str(day)] += 1

    weekly = defaultdict(int)
    for s in sessions:
        try:
            day = parse_date(s.get("timestamp", "")) or start_date
            wk = week_number(day, start_date)
            weekly[wk] += 1
        except Exception:
            pass

    return dict(daily), dict(weekly)


def returning_attacker_analysis(sessions):
    """Track same-IP sessions over time. Check entropy evolution."""
    ip_sessions = defaultdict(list)
    for s in sessions:
        ip_sessions[s["ip"]].append(s)

    returning = {}
    for ip, slist in ip_sessions.items():
        if len(slist) < 2:
            continue

        # Sort by some time proxy (session count order)
        visit_entropies = [float(s.get("command_entropy", 0)) for s in slist]
        visit_durations = [float(s.get("duration_sec", 0)) for s in slist]
        visit_depths = [int(s.get("unique_msg_ids", 0)) for s in slist]

        # Calculate trend (simple slope)
        n = len(visit_entropies)
        if n >= 2:
            x_mean = (n - 1) / 2
            y_mean = sum(visit_entropies) / n
            numerator = sum((i - x_mean) * (visit_entropies[i] - y_mean) for i in range(n))
            denominator = sum((i - x_mean)**2 for i in range(n))
            slope = numerator / denominator if denominator != 0 else 0
        else:
            slope = 0

        returning[ip] = {
            "visits": n,
            "entropy_values": visit_entropies,
            "duration_values": visit_durations,
            "depth_values": visit_depths,
            "entropy_slope": round(slope, 4),
            "entropy_increasing": slope > 0.1,
            "first_entropy": visit_entropies[0],
            "last_entropy": visit_entropies[-1],
        }

    return returning


def on_off_comparison(sessions):
    """Compare metrics between adaptive ON and OFF periods."""
    on_sessions = [s for s in sessions if s.get("mode", "adaptive") == "adaptive"]
    off_sessions = [s for s in sessions if s.get("mode", "static") == "static"]

    def session_stats(slist):
        if not slist:
            return {"count": 0}
        durations = [float(s.get("duration_sec", 0)) for s in slist]
        entropies = [float(s.get("command_entropy", 0)) for s in slist]
        depths = [int(s.get("unique_msg_ids", 0)) for s in slist]
        return {
            "count": len(slist),
            "mean_duration": round(sum(durations) / len(durations), 2),
            "median_duration": round(sorted(durations)[len(durations)//2], 2),
            "mean_entropy": round(sum(entropies) / len(entropies), 3),
            "mean_depth": round(sum(depths) / len(depths), 2),
            "engaged_rate": round(sum(1 for d in durations if d > 5) / len(durations) * 100, 1),
        }

    return {
        "adaptive_on": session_stats(on_sessions),
        "adaptive_off": session_stats(off_sessions),
    }


def entropy_drift(sessions, start_date):
    """Track weekly entropy distribution changes."""
    weekly_entropies = defaultdict(list)
    for s in sessions:
        try:
            day = parse_date(s.get("timestamp", "")) or start_date
            wk = week_number(day, start_date)
            weekly_entropies[wk].append(float(s.get("command_entropy", 0)))
        except Exception:
            pass

    drift = {}
    for wk, entropies in sorted(weekly_entropies.items()):
        drift[wk] = {
            "count": len(entropies),
            "mean": round(sum(entropies) / len(entropies), 3),
            "max": round(max(entropies), 3),
            "min": round(min(entropies), 3),
        }

    return drift


def mann_kendall_trend(values):
    """Simple Mann-Kendall trend test."""
    n = len(values)
    if n < 4:
        return {"trend": "insufficient_data", "p": 1.0}

    s = 0
    for i in range(n):
        for j in range(i + 1, n):
            if values[j] > values[i]:
                s += 1
            elif values[j] < values[i]:
                s -= 1

    # Variance of S
    var_s = n * (n - 1) * (2 * n + 5) / 18

    if s > 0:
        z = (s - 1) / var_s**0.5
    elif s < 0:
        z = (s + 1) / var_s**0.5
    else:
        z = 0

    # Approximate p-value (standard normal)
    p = math.erfc(abs(z) / 2**0.5)

    trend = "increasing" if z > 1.96 else "decreasing" if z < -1.96 else "no_trend"

    return {"trend": trend, "z": round(z, 3), "p": round(p, 4), "s": s}


# ── Main ──────────────────────────────────────────────────────

def run_temporal(labeled_path, start_date_str="2026-04-16"):
    """Run full temporal evolution analysis."""
    print("=" * 60)
    print("  Temporal Evolution Analysis")
    print("=" * 60)

    sessions = load_labeled(labeled_path)
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()

    if not sessions:
        print("\n⚠️ No labeled sessions found. Run feature extractor + labeler first.")
        return

    print(f"  Loaded {len(sessions)} sessions")
    print(f"  Deployment start: {start_date_str}")

    # 1. Returning attacker analysis
    print("\n" + "─" * 40)
    print("1. RETURNING ATTACKER ANALYSIS")
    print("─" * 40)

    returning = returning_attacker_analysis(sessions)
    print(f"  Returning IPs: {len(returning)}")

    if returning:
        increasing = sum(1 for r in returning.values() if r["entropy_increasing"])
        print(f"  Entropy increasing: {increasing} ({increasing/len(returning)*100:.0f}%)")
        print(f"  Entropy stable/decreasing: {len(returning) - increasing}")

        for ip, data in sorted(returning.items(), key=lambda x: -x[1]["visits"])[:5]:
            trend = "📈" if data["entropy_increasing"] else "📉"
            print(f"\n  {ip} ({data['visits']} visits):")
            print(f"    Entropy: {data['first_entropy']:.2f} → {data['last_entropy']:.2f} {trend}")
            print(f"    Slope: {data['entropy_slope']}")

    # 2. ON/OFF comparison
    print("\n" + "─" * 40)
    print("2. ADAPTIVE ON vs OFF COMPARISON")
    print("─" * 40)

    comparison = on_off_comparison(sessions)
    for mode, stats in comparison.items():
        print(f"\n  {mode.upper()}:")
        for k, v in stats.items():
            print(f"    {k}: {v}")

    if comparison["adaptive_on"]["count"] > 5 and comparison["adaptive_off"]["count"] > 5:
        on_dur = comparison["adaptive_on"]["mean_duration"]
        off_dur = comparison["adaptive_off"]["mean_duration"]
        if off_dur > 0:
            improvement = ((on_dur - off_dur) / off_dur) * 100
            print(f"\n  📊 Duration improvement: {improvement:+.1f}%")

    # 3. Entropy drift
    print("\n" + "─" * 40)
    print("3. WEEKLY ENTROPY DRIFT")
    print("─" * 40)

    drift = entropy_drift(sessions, start_date)
    for wk, stats in sorted(drift.items()):
        print(f"  Week {wk}: mean={stats['mean']:.3f}, n={stats['count']}")

    if len(drift) >= 4:
        weekly_means = [drift[wk]["mean"] for wk in sorted(drift.keys())]
        mk = mann_kendall_trend(weekly_means)
        print(f"\n  Mann-Kendall trend: {mk['trend']} (z={mk['z']}, p={mk['p']})")

    # 4. Summary
    print("\n" + "=" * 60)
    print("  TEMPORAL SUMMARY")
    print("=" * 60)
    print(f"  Total sessions: {len(sessions)}")
    print(f"  Returning attackers: {len(returning)}")
    if returning:
        increasing = sum(1 for r in returning.values() if r["entropy_increasing"])
        print(f"  Learning attackers (entropy↑): {increasing}")
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--labeled", default="analysis/labeled_sessions.csv")
    parser.add_argument("--start-date", default="2026-04-16")
    args = parser.parse_args()
    run_temporal(args.labeled, args.start_date)
