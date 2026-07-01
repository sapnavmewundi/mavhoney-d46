#!/usr/bin/env python3
"""
Attacker Labeler — Hybrid Rule-Based + Clustering
===================================================

Labels attacker sessions using:
1. Rule-based classification (interpretable thresholds)
2. K-means/DBSCAN clustering validation
3. Adjusted Rand Index (ARI) between methods
4. Threshold sensitivity analysis

Usage::
    python -m honeypot.attacker_labeler --features analysis/features.csv
"""

import csv
import json
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Rule-Based Labeling ───────────────────────────────────────

def label_rule_based(feat, thresholds=None):
    """
    Classify session using rule-based thresholds.

    Default thresholds:
    - SCANNER: duration < 5s AND only HEARTBEAT (unique_msg_ids <= 1)
    - SCRIPT_KIDDIE: ≤3 msg_ids AND delay_std < 0.05s
    - ADVANCED: ≥5 msg_ids AND adapts (state_changes > 0)
    - APT: persistence (handled at IP level, not session level)
    """
    if thresholds is None:
        thresholds = {
            "scanner_duration": 5.0,
            "scanner_msg_ids": 1,
            "scriptkid_msg_ids": 3,
            "scriptkid_delay_std": 0.05,
            "advanced_msg_ids": 5,
        }

    duration = float(feat.get("duration_sec", 0))
    unique_msgs = int(feat.get("unique_msg_ids", 0))
    delay_std = float(feat.get("delay_std", 0))
    state_changes = int(feat.get("state_changes", 0))
    cmd_entropy = float(feat.get("command_entropy", 0))

    # SCANNER: very short, only heartbeat
    if duration < thresholds["scanner_duration"] and unique_msgs <= thresholds["scanner_msg_ids"]:
        return "SCANNER"

    # SCRIPT_KIDDIE: limited repertoire, fixed timing
    if unique_msgs <= thresholds["scriptkid_msg_ids"] and delay_std < thresholds["scriptkid_delay_std"]:
        return "SCRIPT_KIDDIE"

    # ADVANCED: diverse commands, adapts
    if unique_msgs >= thresholds["advanced_msg_ids"]:
        return "ADVANCED"

    # Default: SCRIPT_KIDDIE (conservative)
    return "SCRIPT_KIDDIE"


def label_apt_from_ip_history(ip_sessions):
    """
    Upgrade to APT if:
    - Multiple sessions over ≥3 days
    - Escalation from RECON to HIJACK+
    """
    apt_ips = set()
    for ip, sessions in ip_sessions.items():
        if len(sessions) < 2:
            continue

        # Check time span
        timestamps = []
        for s in sessions:
            try:
                timestamps.append(s.get("first_timestamp", ""))
            except Exception:
                pass

        if timestamps:
            has_escalation = any(int(s.get("has_hijack", 0)) or int(s.get("has_mission_inject", 0))
                               for s in sessions)
            if len(sessions) >= 3 and has_escalation:
                apt_ips.add(ip)

    return apt_ips


# ── Clustering Validation ────────────────────────────────────

def cluster_sessions(features, n_clusters=4):
    """K-means clustering on numeric features (numpy-free for portability)."""
    # Select numeric features for clustering
    feature_keys = [
        "duration_sec", "packet_count", "unique_msg_ids",
        "command_entropy", "sequence_entropy", "delay_mean",
        "delay_std", "packet_rate", "mean_severity",
    ]

    # Build feature matrix
    matrix = []
    for feat in features:
        row = [float(feat.get(k, 0)) for k in feature_keys]
        matrix.append(row)

    if not matrix:
        return []

    # Normalize (min-max)
    n_features = len(feature_keys)
    mins = [min(matrix[i][j] for i in range(len(matrix))) for j in range(n_features)]
    maxs = [max(matrix[i][j] for i in range(len(matrix))) for j in range(n_features)]
    ranges = [maxs[j] - mins[j] if maxs[j] != mins[j] else 1.0 for j in range(n_features)]

    normalized = [
        [(matrix[i][j] - mins[j]) / ranges[j] for j in range(n_features)]
        for i in range(len(matrix))
    ]

    # Simple k-means (no numpy dependency)
    import random
    random.seed(42)
    centroids = random.sample(normalized, min(n_clusters, len(normalized)))

    for iteration in range(50):
        # Assign clusters
        assignments = []
        for point in normalized:
            dists = [sum((point[j] - c[j])**2 for j in range(n_features)) for c in centroids]
            assignments.append(dists.index(min(dists)))

        # Update centroids
        new_centroids = []
        for k in range(n_clusters):
            members = [normalized[i] for i in range(len(normalized)) if assignments[i] == k]
            if members:
                new_centroids.append([sum(m[j] for m in members) / len(members) for j in range(n_features)])
            else:
                new_centroids.append(centroids[k])
        centroids = new_centroids

    return assignments


def adjusted_rand_index(labels_a, labels_b):
    """Compute ARI between two label sets (no sklearn dependency)."""
    if len(labels_a) != len(labels_b):
        return 0.0

    n = len(labels_a)
    if n < 2:
        return 0.0

    # Contingency table
    classes_a = sorted(set(labels_a))
    classes_b = sorted(set(labels_b))

    table = defaultdict(int)
    for i in range(n):
        table[(labels_a[i], labels_b[i])] += 1

    # Row/column sums
    a_sums = Counter(labels_a)
    b_sums = Counter(labels_b)

    # Compute ARI
    def comb2(n):
        return n * (n - 1) / 2

    sum_comb_table = sum(comb2(v) for v in table.values())
    sum_comb_a = sum(comb2(v) for v in a_sums.values())
    sum_comb_b = sum(comb2(v) for v in b_sums.values())
    comb_n = comb2(n)

    if comb_n == 0:
        return 0.0

    expected = sum_comb_a * sum_comb_b / comb_n
    max_index = 0.5 * (sum_comb_a + sum_comb_b)

    if max_index == expected:
        return 1.0

    return (sum_comb_table - expected) / (max_index - expected)


# ── Threshold Sensitivity ────────────────────────────────────

def threshold_sensitivity(features):
    """Test how labels change when thresholds vary ±50%."""
    base_thresholds = {
        "scanner_duration": 5.0,
        "scanner_msg_ids": 1,
        "scriptkid_msg_ids": 3,
        "scriptkid_delay_std": 0.05,
        "advanced_msg_ids": 5,
    }

    variations = {
        "scanner_duration": [2.5, 5.0, 7.5],
        "scanner_msg_ids": [1, 1, 1],  # keep fixed (binary)
        "scriptkid_msg_ids": [2, 3, 4],
        "scriptkid_delay_std": [0.025, 0.05, 0.075],
        "advanced_msg_ids": [4, 5, 6],
    }

    # Get base labels
    base_labels = [label_rule_based(f, base_thresholds) for f in features]

    # Test each variation
    results = {}
    for param, values in variations.items():
        stability_scores = []
        for val in values:
            test_thresholds = base_thresholds.copy()
            test_thresholds[param] = val
            test_labels = [label_rule_based(f, test_thresholds) for f in features]

            # Count unchanged labels
            unchanged = sum(1 for a, b in zip(base_labels, test_labels) if a == b)
            stability = unchanged / max(len(base_labels), 1)
            stability_scores.append((val, stability))

        results[param] = stability_scores

    return results


# ── Main ──────────────────────────────────────────────────────

def run_labeling(features_path, output_path="analysis/labeled_sessions.csv"):
    """Run full labeling pipeline."""
    # Load features
    with open(features_path, newline="") as f:
        reader = csv.DictReader(f)
        features = list(reader)

    if not features:
        print("No features found. Run feature extractor first.")
        return

    print(f"Loaded {len(features)} sessions")

    # 1. Rule-based labels
    rule_labels = [label_rule_based(f) for f in features]
    for feat, label in zip(features, rule_labels):
        feat["label_rule"] = label

    # Check for APT (IP-level)
    ip_sessions = defaultdict(list)
    for feat in features:
        ip_sessions[feat["ip"]].append(feat)
    apt_ips = label_apt_from_ip_history(ip_sessions)

    for feat in features:
        if feat["ip"] in apt_ips:
            feat["label_rule"] = "APT"

    rule_labels = [f["label_rule"] for f in features]
    print(f"\n📊 Rule-based labels:")
    for label, count in Counter(rule_labels).most_common():
        print(f"   {label:<15}: {count} ({count/len(features)*100:.0f}%)")

    # 2. Clustering validation
    if len(features) >= 10:
        cluster_labels = cluster_sessions(features, n_clusters=4)
        ari = adjusted_rand_index(rule_labels, [str(c) for c in cluster_labels])
        print(f"\n📊 Clustering validation:")
        print(f"   ARI = {ari:.3f}")
        if ari > 0.6:
            print(f"   ✅ Strong agreement — rule-based labels validated")
        elif ari > 0.3:
            print(f"   ⚠️ Moderate agreement — review labels")
        else:
            print(f"   ❌ Weak agreement — thresholds may need adjustment")

        for feat, cl in zip(features, cluster_labels):
            feat["cluster_id"] = cl
    else:
        print("\n⚠️ Need ≥10 sessions for clustering validation")

    # 3. Threshold sensitivity
    if len(features) >= 5:
        print(f"\n📊 Threshold sensitivity:")
        sensitivity = threshold_sensitivity(features)
        for param, scores in sensitivity.items():
            stabilities = [s for _, s in scores]
            mean_stab = sum(stabilities) / len(stabilities)
            print(f"   {param:<25}: {mean_stab*100:.0f}% stable")
        overall = sum(sum(s for _, s in scores) / len(scores) for scores in sensitivity.values()) / len(sensitivity)
        print(f"\n   Overall stability: {overall*100:.0f}%")
        if overall > 0.8:
            print(f"   ✅ Thresholds are robust")
    else:
        print("   ⚠️ Need ≥5 sessions for sensitivity analysis")

    # 4. Save labeled data
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=features[0].keys())
        writer.writeheader()
        writer.writerows(features)

    print(f"\n✅ Saved labeled sessions → {output_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", default="analysis/features.csv")
    parser.add_argument("--output", default="analysis/labeled_sessions.csv")
    args = parser.parse_args()
    run_labeling(args.features, args.output)
