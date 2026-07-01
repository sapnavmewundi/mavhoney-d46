#!/usr/bin/env python3
"""
Exploratory Data Analysis — Early Data Inspection
===================================================

Run after 1-2 weeks of data collection to:
- Plot basic distributions (msg types, session durations, countries)
- Compute initial entropy metrics
- Identify preliminary attacker clusters
- Validate data pipeline (no artifacts, duplicates)
- Calibrate entropy thresholds

Usage::
    python analysis/exploratory.py [--data-dir /path/to/datasets]
"""

import csv
import json
import os
import sys
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Helpers ───────────────────────────────────────────────────

def load_dataset(path):
    """Load CSV dataset, return list of row dicts."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("ip") and row.get("timestamp"):
                rows.append(row)
    return rows


def load_all_datasets(data_dir):
    """Load all CSV files from a directory."""
    all_rows = []
    for fname in os.listdir(data_dir):
        if fname.endswith(".csv"):
            path = os.path.join(data_dir, fname)
            rows = load_dataset(path)
            all_rows.extend(rows)
            print(f"  Loaded {len(rows):,} rows from {fname}")
    return all_rows


def compute_entropy(values):
    """Compute Shannon entropy of a list of values."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_bigram_entropy(values):
    """Compute entropy of 2-gram transitions."""
    if len(values) < 2:
        return 0.0
    bigrams = [(values[i], values[i+1]) for i in range(len(values) - 1)]
    return compute_entropy(bigrams)


# ── Session Extraction ────────────────────────────────────────

def extract_sessions(rows):
    """Group rows into sessions by session_id."""
    sessions = defaultdict(list)
    for row in rows:
        sid = row.get("session_id", "unknown")
        sessions[sid].append(row)
    return dict(sessions)


def compute_session_metrics(session_rows):
    """Compute metrics for a single session."""
    if not session_rows:
        return None

    timestamps = []
    msg_ids = []
    severities = []
    intents = []

    for row in session_rows:
        try:
            ts = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            timestamps.append(ts)
        except (ValueError, KeyError):
            pass
        msg_ids.append(row.get("msg_id", "0"))
        severities.append(int(row.get("severity", 0)))
        intents.append(row.get("intent", "UNKNOWN"))

    if len(timestamps) < 2:
        duration = 0.0
    else:
        duration = (max(timestamps) - min(timestamps)).total_seconds()

    return {
        "ip": session_rows[0].get("ip", "unknown"),
        "session_id": session_rows[0].get("session_id", "unknown"),
        "packet_count": len(session_rows),
        "duration_sec": round(duration, 2),
        "unique_msg_ids": len(set(msg_ids)),
        "max_severity": max(severities) if severities else 0,
        "mean_severity": round(sum(severities) / len(severities), 2) if severities else 0,
        "intents": list(set(intents)),
        "command_entropy": compute_entropy(msg_ids),
        "sequence_entropy": compute_bigram_entropy(msg_ids),
        "honeypot_state": session_rows[-1].get("honeypot_state", "NORMAL"),
        "mode": session_rows[0].get("mode", "adaptive"),
    }


# ── GeoIP (offline, no API) ──────────────────────────────────

def classify_ip_region(ip):
    """Simple region classification based on IP ranges (no API needed)."""
    first_octet = int(ip.split(".")[0])
    if first_octet in range(1, 60):
        return "North America"
    elif first_octet in range(60, 100):
        return "Europe"
    elif first_octet in range(100, 130):
        return "Asia"
    elif first_octet in range(130, 160):
        return "Asia-Pacific"
    elif first_octet in range(160, 200):
        return "Europe/Middle East"
    else:
        return "Other"


# ── Main Analysis ─────────────────────────────────────────────

def run_exploratory(data_dir):
    """Run full exploratory analysis."""
    print("=" * 60)
    print("  MAVLink Honeypot — Exploratory Data Analysis")
    print("=" * 60)

    # Load data
    print(f"\n📂 Loading data from: {data_dir}")
    rows = load_all_datasets(data_dir)

    if not rows:
        print("\n⚠️  No data found! Data collection may need more time.")
        print("   Honeypots are running. Check back in a few days.")
        return

    print(f"\n📊 Total events: {len(rows):,}")

    # ── 1. Basic Statistics ───────────────────────────────────
    print("\n" + "─" * 40)
    print("1. BASIC STATISTICS")
    print("─" * 40)

    unique_ips = set(row["ip"] for row in rows)
    print(f"   Unique IPs:        {len(unique_ips)}")

    sessions = extract_sessions(rows)
    print(f"   Total sessions:    {len(sessions)}")

    msg_id_dist = Counter(row.get("msg_id", "0") for row in rows)
    print(f"   Unique msg_ids:    {len(msg_id_dist)}")
    print(f"   Top 5 msg_ids:")
    for mid, count in msg_id_dist.most_common(5):
        name = rows[0].get("msg_name", mid) if mid == rows[0].get("msg_id") else f"MSG_{mid}"
        print(f"     {mid:>5}: {count:>6} ({count/len(rows)*100:.1f}%)")

    intent_dist = Counter(row.get("intent", "UNKNOWN") for row in rows)
    print(f"\n   Intent distribution:")
    for intent, count in intent_dist.most_common():
        print(f"     {intent:<20}: {count:>6} ({count/len(rows)*100:.1f}%)")

    severity_dist = Counter(row.get("severity", "0") for row in rows)
    print(f"\n   Severity distribution:")
    for sev, count in sorted(severity_dist.items()):
        bar = "█" * int(count / len(rows) * 50)
        print(f"     Severity {sev:>2}: {count:>6} {bar}")

    # ── 2. Session Analysis ───────────────────────────────────
    print("\n" + "─" * 40)
    print("2. SESSION ANALYSIS")
    print("─" * 40)

    session_metrics = []
    for sid, srows in sessions.items():
        m = compute_session_metrics(srows)
        if m:
            session_metrics.append(m)

    if session_metrics:
        durations = [m["duration_sec"] for m in session_metrics]
        depths = [m["unique_msg_ids"] for m in session_metrics]
        entropies = [m["command_entropy"] for m in session_metrics]
        seq_entropies = [m["sequence_entropy"] for m in session_metrics]

        print(f"   Sessions analyzed: {len(session_metrics)}")
        print(f"\n   Duration (seconds):")
        print(f"     Mean:   {sum(durations)/len(durations):.1f}")
        print(f"     Median: {sorted(durations)[len(durations)//2]:.1f}")
        print(f"     Max:    {max(durations):.1f}")
        print(f"     <2s:    {sum(1 for d in durations if d < 2)} ({sum(1 for d in durations if d < 2)/len(durations)*100:.0f}%)")
        print(f"     >30s:   {sum(1 for d in durations if d > 30)} ({sum(1 for d in durations if d > 30)/len(durations)*100:.0f}%)")

        print(f"\n   Interaction depth (unique msg_ids per session):")
        print(f"     Mean:   {sum(depths)/len(depths):.1f}")
        print(f"     Max:    {max(depths)}")

        print(f"\n   Command entropy:")
        print(f"     Mean:   {sum(entropies)/len(entropies):.3f}")
        print(f"     Max:    {max(entropies):.3f}")

        print(f"\n   Sequence entropy:")
        print(f"     Mean:   {sum(seq_entropies)/len(seq_entropies):.3f}")
        print(f"     Max:    {max(seq_entropies):.3f}")

    # ── 3. Tier 1 vs Tier 2 ───────────────────────────────────
    print("\n" + "─" * 40)
    print("3. TIER 1 vs TIER 2 TRAFFIC")
    print("─" * 40)

    tier1 = session_metrics
    tier2 = [m for m in session_metrics if m["packet_count"] >= 2 and m["duration_sec"] > 5]

    print(f"   Tier 1 (all sessions):     {len(tier1)}")
    print(f"   Tier 2 (engaged, >5s, ≥2pkt): {len(tier2)}")
    if tier1:
        print(f"   Engagement rate:           {len(tier2)/len(tier1)*100:.1f}%")

    # ── 4. Entropy Threshold Calibration ──────────────────────
    print("\n" + "─" * 40)
    print("4. ENTROPY THRESHOLD CALIBRATION")
    print("─" * 40)

    if entropies:
        bins = [
            ("H < 1.0 (SCANNER)", lambda h: h < 1.0),
            ("1.0 ≤ H < 2.0 (SCRIPT_KIDDIE)", lambda h: 1.0 <= h < 2.0),
            ("2.0 ≤ H < 3.0 (ADVANCED)", lambda h: 2.0 <= h < 3.0),
            ("H ≥ 3.0 (APT)", lambda h: h >= 3.0),
        ]
        for label, test in bins:
            count = sum(1 for h in entropies if test(h))
            pct = count / len(entropies) * 100
            print(f"   {label}: {count} ({pct:.0f}%)")

    # ── 5. Geographic Distribution ────────────────────────────
    print("\n" + "─" * 40)
    print("5. GEOGRAPHIC DISTRIBUTION (approximate)")
    print("─" * 40)

    regions = Counter(classify_ip_region(ip) for ip in unique_ips)
    for region, count in regions.most_common():
        print(f"   {region:<25}: {count}")

    # ── 6. Data Quality Checks ────────────────────────────────
    print("\n" + "─" * 40)
    print("6. DATA QUALITY")
    print("─" * 40)

    local_ips = sum(1 for ip in unique_ips if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."))
    print(f"   Local/private IPs: {local_ips} {'⚠️ REMOVE THESE' if local_ips > 0 else '✅ Clean'}")

    duplicates = len(rows) - len(set((row.get("timestamp",""), row.get("ip",""), row.get("msg_id","")) for row in rows))
    print(f"   Duplicate events:  {duplicates} {'⚠️ INVESTIGATE' if duplicates > 10 else '✅ Clean'}")

    empty_fields = sum(1 for row in rows if not row.get("msg_name") or not row.get("intent"))
    print(f"   Empty fields:      {empty_fields} {'⚠️ INVESTIGATE' if empty_fields > 0 else '✅ Clean'}")

    # ── 7. Returning Attackers ────────────────────────────────
    print("\n" + "─" * 40)
    print("7. RETURNING ATTACKERS")
    print("─" * 40)

    ip_sessions = defaultdict(list)
    for m in session_metrics:
        ip_sessions[m["ip"]].append(m)

    returning = {ip: slist for ip, slist in ip_sessions.items() if len(slist) > 1}
    print(f"   Total unique IPs:    {len(ip_sessions)}")
    print(f"   Returning IPs:       {len(returning)} ({len(returning)/max(len(ip_sessions),1)*100:.0f}%)")
    print(f"   Single-visit IPs:    {len(ip_sessions) - len(returning)}")

    if returning:
        print(f"\n   Top returning attackers:")
        for ip, slist in sorted(returning.items(), key=lambda x: -len(x[1]))[:5]:
            entrs = [s["command_entropy"] for s in slist]
            print(f"     {ip}: {len(slist)} sessions, mean entropy={sum(entrs)/len(entrs):.2f}")

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total events:         {len(rows):,}")
    print(f"  Unique attackers:     {len(unique_ips)}")
    print(f"  Sessions:             {len(sessions)}")
    print(f"  Tier 2 (engaged):     {len(tier2)}")
    if tier2:
        t2_dur = [m["duration_sec"] for m in tier2]
        print(f"  Mean engaged duration: {sum(t2_dur)/len(t2_dur):.1f}s")
    print(f"  Returning attackers:  {len(returning)}")
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Exploratory Data Analysis")
    parser.add_argument("--data-dir", default="datasets", help="Path to datasets directory")
    args = parser.parse_args()
    run_exploratory(args.data_dir)
