#!/usr/bin/env python3
"""
Feature Extractor — Behavioral Feature Engineering
====================================================

Extracts rich temporal and behavioral features from session data
for ML classification. Outputs a feature matrix (sessions × features).

Features:
- Timing: inter-packet delays, bursts
- Sequence: n-gram msg_id distributions
- Entropy: command, sequence, timing entropy
- Volume: packets/min, payload sizes
- MAVLink-specific: msg_id embeddings, protocol state

Usage::
    python -m honeypot.feature_extractor --data datasets/ --output features.csv
"""

import csv
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def compute_entropy(values):
    """Shannon entropy."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    return round(-sum((c/total) * math.log2(c/total) for c in counter.values() if c > 0), 4)


def compute_bigram_entropy(values):
    """Entropy of 2-gram transitions."""
    if len(values) < 2:
        return 0.0
    bigrams = [f"{values[i]}->{values[i+1]}" for i in range(len(values) - 1)]
    return compute_entropy(bigrams)


def extract_features(session_rows):
    """Extract full feature vector from a session."""
    if not session_rows or len(session_rows) < 1:
        return None

    # Parse timestamps
    timestamps = []
    for row in session_rows:
        try:
            ts = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            timestamps.append(ts)
        except (ValueError, KeyError):
            pass

    msg_ids = [str(row.get("msg_id", "0")) for row in session_rows]
    severities = [int(row.get("severity", 0)) for row in session_rows]
    intents = [row.get("intent", "UNKNOWN") for row in session_rows]
    states = [row.get("honeypot_state", "NORMAL") for row in session_rows]

    # Duration
    if len(timestamps) >= 2:
        duration = (max(timestamps) - min(timestamps)).total_seconds()
    else:
        duration = 0.0

    # Inter-packet delays
    delays = []
    if len(timestamps) >= 2:
        sorted_ts = sorted(timestamps)
        delays = [(sorted_ts[i+1] - sorted_ts[i]).total_seconds() for i in range(len(sorted_ts)-1)]

    delay_mean = sum(delays) / len(delays) if delays else 0.0
    delay_std = (sum((d - delay_mean)**2 for d in delays) / len(delays))**0.5 if delays else 0.0
    delay_min = min(delays) if delays else 0.0
    delay_max = max(delays) if delays else 0.0

    # Burst detection (>3 packets within 0.5s)
    burst_count = 0
    if delays:
        consecutive_fast = 0
        for d in delays:
            if d < 0.5:
                consecutive_fast += 1
                if consecutive_fast >= 3:
                    burst_count += 1
            else:
                consecutive_fast = 0

    # Packet rate
    packet_count = len(session_rows)
    packet_rate = packet_count / max(duration, 0.01)

    # Message diversity
    unique_msg_ids = len(set(msg_ids))
    command_diversity = unique_msg_ids / max(packet_count, 1)

    # Entropy features
    cmd_entropy = compute_entropy(msg_ids)
    seq_entropy = compute_bigram_entropy(msg_ids)
    timing_entropy = compute_entropy([round(d, 1) for d in delays]) if delays else 0.0
    intent_entropy = compute_entropy(intents)

    # Severity features
    max_severity = max(severities) if severities else 0
    mean_severity = sum(severities) / len(severities) if severities else 0
    severity_escalation = 1 if len(severities) >= 3 and severities[-1] > severities[0] else 0

    # State progression
    unique_states = len(set(states))
    state_changes = sum(1 for i in range(1, len(states)) if states[i] != states[i-1])

    # Intent progression
    intent_counts = Counter(intents)
    has_recon = 1 if intent_counts.get("RECON", 0) > 0 else 0
    has_control = 1 if intent_counts.get("CONTROL", 0) > 0 else 0
    has_hijack = 1 if intent_counts.get("HIJACK", 0) > 0 else 0
    has_mission = 1 if intent_counts.get("MISSION_INJECT", 0) > 0 else 0
    has_gps = 1 if intent_counts.get("GPS_SPOOF", 0) > 0 else 0
    escalation_depth = has_recon + has_control + has_hijack + has_mission + has_gps

    # MAVLink-specific
    first_msg = msg_ids[0] if msg_ids else "0"
    payload_sizes = [len(row.get("payload_hex", "")) // 2 for row in session_rows]
    mean_payload = sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0

    # N-gram features (top 3 bigrams)
    if len(msg_ids) >= 2:
        bigrams = Counter(f"{msg_ids[i]}->{msg_ids[i+1]}" for i in range(len(msg_ids)-1))
        top_bigrams = bigrams.most_common(3)
    else:
        top_bigrams = []

    return {
        # Session ID
        "session_id": session_rows[0].get("session_id", "unknown"),
        "ip": session_rows[0].get("ip", "unknown"),
        "mode": session_rows[0].get("mode", "adaptive"),

        # Timing
        "duration_sec": round(duration, 2),
        "delay_mean": round(delay_mean, 4),
        "delay_std": round(delay_std, 4),
        "delay_min": round(delay_min, 4),
        "delay_max": round(delay_max, 4),
        "burst_count": burst_count,

        # Volume
        "packet_count": packet_count,
        "packet_rate": round(packet_rate, 2),
        "mean_payload_bytes": round(mean_payload, 1),

        # Diversity
        "unique_msg_ids": unique_msg_ids,
        "command_diversity": round(command_diversity, 4),

        # Entropy
        "command_entropy": cmd_entropy,
        "sequence_entropy": seq_entropy,
        "timing_entropy": timing_entropy,
        "intent_entropy": intent_entropy,

        # Severity
        "max_severity": max_severity,
        "mean_severity": round(mean_severity, 2),
        "severity_escalation": severity_escalation,

        # State
        "unique_states": unique_states,
        "state_changes": state_changes,

        # Intent progression
        "has_recon": has_recon,
        "has_control": has_control,
        "has_hijack": has_hijack,
        "has_mission_inject": has_mission,
        "has_gps_spoof": has_gps,
        "escalation_depth": escalation_depth,

        # MAVLink-specific
        "first_msg_id": first_msg,
        "top_bigram_1": top_bigrams[0][0] if len(top_bigrams) > 0 else "",
        "top_bigram_2": top_bigrams[1][0] if len(top_bigrams) > 1 else "",
        "top_bigram_3": top_bigrams[2][0] if len(top_bigrams) > 2 else "",
    }


def extract_all(data_dir, output_path):
    """Extract features from all sessions in dataset directory."""
    from collections import defaultdict

    # Load all data
    all_rows = []
    for fname in os.listdir(data_dir):
        if fname.endswith(".csv"):
            with open(os.path.join(data_dir, fname), newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("ip") and row.get("timestamp"):
                        all_rows.append(row)

    print(f"Loaded {len(all_rows)} events")

    # Group by session
    sessions = defaultdict(list)
    for row in all_rows:
        sessions[row.get("session_id", "unknown")].append(row)

    print(f"Found {len(sessions)} sessions")

    # Extract features
    features = []
    for sid, srows in sessions.items():
        feat = extract_features(srows)
        if feat:
            features.append(feat)

    if not features:
        print("No features extracted. Need more data.")
        return

    # Write CSV
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=features[0].keys())
        writer.writeheader()
        writer.writerows(features)

    print(f"✅ Extracted {len(features)} feature vectors → {output_path}")
    print(f"   Features per session: {len(features[0])}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="datasets", help="Dataset directory")
    parser.add_argument("--output", default="analysis/features.csv", help="Output path")
    args = parser.parse_args()
    extract_all(args.data, args.output)
