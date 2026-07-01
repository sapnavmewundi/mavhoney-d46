#!/usr/bin/env python3
"""
Threshold Sensitivity Analysis
================================

Tests robustness of attacker classification thresholds by
varying each parameter ±50% and measuring label stability.

Outputs: sensitivity heatmap data + stability report.

Usage::
    python analysis/threshold_sensitivity.py --features analysis/features.csv
"""

import csv
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.attacker_labeler import label_rule_based


BASE_THRESHOLDS = {
    "scanner_duration": 5.0,
    "scanner_msg_ids": 1,
    "scriptkid_msg_ids": 3,
    "scriptkid_delay_std": 0.05,
    "advanced_msg_ids": 5,
}

VARIATIONS = {
    "scanner_duration": [2.5, 3.0, 4.0, 5.0, 6.0, 7.0, 7.5],
    "scriptkid_msg_ids": [2, 3, 4],
    "scriptkid_delay_std": [0.025, 0.035, 0.05, 0.065, 0.075],
    "advanced_msg_ids": [3, 4, 5, 6, 7],
}


def run_sensitivity(features_path, output_path="analysis/sensitivity_report.json"):
    """Run full sensitivity analysis."""
    with open(features_path, newline="") as f:
        features = list(csv.DictReader(f))

    if len(features) < 3:
        print("Need at least 3 sessions for sensitivity analysis.")
        return

    # Base labels
    base_labels = [label_rule_based(f, BASE_THRESHOLDS) for f in features]
    n = len(features)

    print("=" * 60)
    print("  Threshold Sensitivity Analysis")
    print("=" * 60)
    print(f"  Sessions: {n}")
    print(f"\n  Base distribution:")
    for label, count in Counter(base_labels).most_common():
        print(f"    {label:<15}: {count} ({count/n*100:.0f}%)")

    results = {}
    print(f"\n  Sensitivity by parameter:")
    print(f"  {'Parameter':<25} {'Value':>8} {'Stability':>10} {'Changes':>8}")
    print(f"  {'-'*55}")

    for param, values in VARIATIONS.items():
        param_results = []
        for val in values:
            test_thresh = BASE_THRESHOLDS.copy()
            test_thresh[param] = val
            test_labels = [label_rule_based(f, test_thresh) for f in features]

            unchanged = sum(1 for a, b in zip(base_labels, test_labels) if a == b)
            stability = unchanged / n
            changes = n - unchanged

            print(f"  {param:<25} {val:>8} {stability*100:>9.0f}% {changes:>8}")

            # Track which sessions changed
            changed_from = Counter()
            changed_to = Counter()
            for a, b in zip(base_labels, test_labels):
                if a != b:
                    changed_from[a] += 1
                    changed_to[b] += 1

            param_results.append({
                "value": val,
                "stability_pct": round(stability * 100, 1),
                "changes": changes,
                "changed_from": dict(changed_from),
                "changed_to": dict(changed_to),
            })

        results[param] = param_results
        print()

    # Overall stability
    all_stabilities = []
    for param, param_results in results.items():
        for r in param_results:
            all_stabilities.append(r["stability_pct"])

    overall = sum(all_stabilities) / len(all_stabilities)
    print(f"  Overall mean stability: {overall:.0f}%")
    if overall > 80:
        print(f"  ✅ Thresholds are ROBUST (>80%)")
    elif overall > 60:
        print(f"  ⚠️ Thresholds are MODERATE (60-80%)")
    else:
        print(f"  ❌ Thresholds are FRAGILE (<60%)")

    # Most sensitive parameter
    param_sensitivities = {}
    for param, param_results in results.items():
        mean_stab = sum(r["stability_pct"] for r in param_results) / len(param_results)
        param_sensitivities[param] = mean_stab

    most_sensitive = min(param_sensitivities, key=param_sensitivities.get)
    print(f"  Most sensitive: {most_sensitive} ({param_sensitivities[most_sensitive]:.0f}% stable)")

    # Save report
    report = {
        "base_thresholds": BASE_THRESHOLDS,
        "n_sessions": n,
        "overall_stability_pct": round(overall, 1),
        "robust": overall > 80,
        "most_sensitive_param": most_sensitive,
        "param_results": results,
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Saved → {output_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", default="analysis/features.csv")
    parser.add_argument("--output", default="analysis/sensitivity_report.json")
    args = parser.parse_args()
    run_sensitivity(args.features, args.output)
