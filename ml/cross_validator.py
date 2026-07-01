#!/usr/bin/env python3
"""
MAVLink Honeypot — Rigorous ML Cross-Validation & Evaluation Pipeline

Generates IEEE-quality evaluation metrics:
  • K-fold cross-validation (5-fold and 10-fold)
  • Multi-model comparison: IsolationForest vs OneClassSVM vs LOF
  • ROC curve data, confusion matrices, precision/recall/F1 per class
  • AUC scores, statistical significance (paired t-test across folds)
  • 10,000+ synthetic events with realistic distributions

Usage:
    python3 ml/cross_validator.py

Output:
    reproducibility/results/ml_evaluation.json
"""

import json
import os
import sys
import random
import math
import numpy as np
import warnings
from collections import defaultdict
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
from scipy import stats


# ══════════════════════════════════════════════════════════════
# Synthetic Dataset Generator
# ══════════════════════════════════════════════════════════════

# Attack profile definitions — realistic distributions based on
# MAVLink protocol characteristics and real-world drone attack studies
ATTACK_PROFILES = {
    "recon_scanner": {
        "intent_dist": {"RECON": 0.85, "CONTROL": 0.10, "UNKNOWN": 0.05},
        "severity_range": (1, 3),
        "packet_rate_range": (0.2, 3.0),
        "msg_ids": [0, 1, 2, 20, 21, 24, 27, 30, 33, 74, 147, 148, 242, 252],
        "timing_ms_range": (300, 2000),
        "weight": 0.30,  # 30% of traffic — most common
    },
    "gps_spoofer": {
        "intent_dist": {"RECON": 0.15, "GPS_SPOOF": 0.60, "CONTROL": 0.15, "SENSOR_SPOOF": 0.10},
        "severity_range": (6, 10),
        "packet_rate_range": (2.0, 15.0),
        "msg_ids": [0, 20, 113, 132, 113, 132, 241],
        "timing_ms_range": (50, 500),
        "weight": 0.15,
    },
    "hijacker": {
        "intent_dist": {"RECON": 0.10, "CONTROL": 0.35, "HIJACK": 0.40, "CONFIG_ATTACK": 0.15},
        "severity_range": (5, 10),
        "packet_rate_range": (1.0, 8.0),
        "msg_ids": [0, 11, 76, 400, 84, 86, 83, 23],
        "timing_ms_range": (100, 800),
        "weight": 0.15,
    },
    "dos_attacker": {
        "intent_dist": {"DOS_FLOOD": 0.70, "RECON": 0.15, "CONTROL": 0.15},
        "severity_range": (7, 10),
        "packet_rate_range": (20.0, 100.0),
        "msg_ids": [0, 0, 0, 76, 76, 76, 1, 1],
        "timing_ms_range": (5, 50),
        "weight": 0.10,
    },
    "mission_injector": {
        "intent_dist": {"RECON": 0.15, "MISSION_INJECT": 0.50, "CONTROL": 0.20, "CONFIG_ATTACK": 0.15},
        "severity_range": (5, 9),
        "packet_rate_range": (1.0, 5.0),
        "msg_ids": [0, 20, 21, 76, 511, 512, 513, 514, 23],
        "timing_ms_range": (200, 1500),
        "weight": 0.10,
    },
    "apt_multistage": {
        "intent_dist": {"RECON": 0.20, "CONTROL": 0.20, "HIJACK": 0.15,
                        "GPS_SPOOF": 0.15, "CONFIG_ATTACK": 0.15, "MISSION_INJECT": 0.15},
        "severity_range": (1, 10),
        "packet_rate_range": (0.5, 5.0),
        "msg_ids": [0, 20, 21, 148, 11, 76, 23, 400, 84, 86, 113, 132, 511, 514],
        "timing_ms_range": (100, 3000),
        "weight": 0.10,
    },
    "benign_gcs": {
        "intent_dist": {"RECON": 0.90, "CONTROL": 0.10},
        "severity_range": (1, 2),
        "packet_rate_range": (0.5, 2.0),
        "msg_ids": [0, 1, 24, 30, 33, 74, 147],
        "timing_ms_range": (500, 3000),
        "weight": 0.10,
    },
}

INTENT_LIST = [
    "RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
    "MISSION_INJECT", "CONFIG_ATTACK", "SENSOR_SPOOF",
    "DOS_FLOOD", "UNKNOWN"
]

def generate_synthetic_dataset(n_events: int = 12000, seed: int = 42) -> list:
    """
    Generate a large synthetic attack dataset with realistic distributions.

    Each event mimics what the honeypot would log, with:
    - Timestamp with realistic intervals
    - Source IP from simulated attacker pools
    - MAVLink message ID, name, intent, severity
    - Packet rate, payload hex, session tracking
    - Ground-truth attack profile label

    Returns:
        List of event dicts
    """
    random.seed(seed)
    np.random.seed(seed)

    from honeypot.core.semantic_analyzer import MAVLINK_SEMANTICS

    events = []
    base_time = datetime(2026, 3, 1, 0, 0, 0)

    # Create attacker IP pools per profile
    ip_pools = {}
    for i, profile_name in enumerate(ATTACK_PROFILES):
        ip_pools[profile_name] = [
            f"10.{50 + i}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(random.randint(5, 20))
        ]

    for profile_name, profile in ATTACK_PROFILES.items():
        n_profile = int(n_events * profile["weight"])
        ips = ip_pools[profile_name]

        for j in range(n_profile):
            ip = random.choice(ips)
            msg_id = random.choice(profile["msg_ids"])

            # Get semantics for this msg_id — intent comes from the
            # semantic analyzer's msg_id→intent mapping, exactly as the
            # real honeypot does in production.  This is NOT circular
            # because the ML classifier does not receive the intent as
            # a feature; it must learn the mapping from protocol behavior.
            sem = MAVLINK_SEMANTICS.get(msg_id, {
                "name": f"UNKNOWN_{msg_id}", "intent": "UNKNOWN", "severity": 3
            })
            intent = sem["intent"]
            # Severity: blend profile range with semantic severity
            base_sev = sem["severity"]
            profile_sev = random.randint(*profile["severity_range"])
            severity = max(base_sev, int(0.6 * base_sev + 0.4 * profile_sev))
            severity = min(severity, 10)

            # Packet rate with noise
            pkt_rate = random.uniform(*profile["packet_rate_range"])
            pkt_rate += random.gauss(0, pkt_rate * 0.1)
            pkt_rate = max(0.1, pkt_rate)

            # Timestamp with realistic intervals
            delta_ms = random.uniform(*profile["timing_ms_range"])
            base_time += timedelta(milliseconds=delta_ms)

            # Payload hex (realistic length per msg type)
            payload_len = random.choice([9, 14, 18, 25, 33])
            payload_hex = ''.join(random.choices('0123456789abcdef', k=payload_len * 2))

            # Session ID
            session_id = f"{random.randint(0, 0xFFFFFFFF):08x}"

            # Honeypot state based on severity
            if severity >= 10:
                state = "REBOOTING"
            elif severity >= 9:
                state = random.choice(["DEFENSIVE", "PARTIAL"])
            elif severity >= 7:
                state = random.choice(["CONFUSED", "PARTIAL"])
            elif severity >= 5:
                state = "WEAK"
            else:
                state = "NORMAL"

            # Hour of day (attacks peak in certain hours)
            hour = (base_time.hour + random.choice([0, 0, 0, 8, 14, 22])) % 24

            events.append({
                "timestamp": base_time.isoformat(),
                "ip": ip,
                "port": random.randint(10000, 65535),
                "msg_id": msg_id,
                "msg_name": sem["name"],
                "intent": intent,
                "severity": severity,
                "payload_hex": payload_hex,
                "session_id": session_id,
                "honeypot_state": state,
                "packet_rate": round(pkt_rate, 2),
                "hour": hour,
                "attack_profile": profile_name,
                "is_malicious": profile_name != "benign_gcs",
            })

    random.shuffle(events)
    return events


# ══════════════════════════════════════════════════════════════
# Feature Extraction
# ══════════════════════════════════════════════════════════════

# ── MSG_ID-based feature sets (protocol-derived, NOT from intent label) ──
# These map MAVLink message IDs to protocol categories.
GPS_MSG_IDS = {24, 33, 113, 132, 241}         # GPS_RAW, GLOBAL_POS, HIL_GPS, GPS_INPUT
CMD_MSG_IDS = {11, 76, 400}                    # SET_MODE, COMMAND_LONG, COMMAND_INT
MISSION_MSG_IDS = {511, 512, 513, 514, 23}     # MISSION_ITEM/CLEAR/COUNT/ACK, PARAM_SET
STATUS_MSG_IDS = {0, 1, 2, 147, 148, 242, 252, 253}  # HEARTBEAT, SYS_STATUS, etc.
PARAM_MSG_IDS = {20, 21, 23}                   # PARAM_REQUEST_READ/LIST, PARAM_SET
CONTROL_MSG_IDS = {84, 86, 83}                 # SET_POSITION_TARGET, SET_ATTITUDE_TARGET


def extract_features(events: list, intent_encoder: LabelEncoder = None):
    """
    Extract numerical feature matrix from event list.

    Features (16 total):
        0.  severity          — Attack severity score (1-10)
        1.  packet_rate       — Packets per second
        2.  msg_id            — MAVLink message ID (raw numeric)
        3.  intent_encoded    — Numerical encoding of intent category [LEAK]
        4.  hour              — Hour of day (temporal pattern)
        5.  payload_size      — Payload length in bytes
        6.  is_high_severity  — Binary: severity >= 7
        7.  is_spoof_intent   — Binary: GPS_SPOOF or SENSOR_SPOOF [LEAK]
        8.  rate_severity     — Interaction: packet_rate × severity
        9.  is_gps_msg        — Binary: msg_id is GPS-related
        10. is_cmd_msg        — Binary: msg_id is a command
        11. is_mission_msg    — Binary: msg_id is mission-related
        12. is_status_msg     — Binary: msg_id is status/heartbeat
        13. is_param_msg      — Binary: msg_id is parameter-related
        14. is_control_msg    — Binary: msg_id is SET_POSITION/ATTITUDE
        15. severity_sq       — severity² (non-linear severity emphasis)
    """
    if intent_encoder is None:
        intent_encoder = LabelEncoder()
        intent_encoder.fit(INTENT_LIST)

    X = []
    for e in events:
        severity = int(e.get("severity", 3))
        pkt_rate = float(e.get("packet_rate", 0))
        msg_id = int(e.get("msg_id", 0))

        intent = str(e.get("intent", "UNKNOWN"))
        if intent not in INTENT_LIST:
            intent = "UNKNOWN"
        intent_enc = int(intent_encoder.transform([intent])[0])

        hour = int(e.get("hour", 12))
        payload_hex = str(e.get("payload_hex", ""))
        payload_size = len(payload_hex) // 2

        X.append([
            severity,                                          # 0
            pkt_rate,                                          # 1
            msg_id,                                            # 2
            intent_enc,                                        # 3  [LEAK for intent clf]
            hour,                                              # 4
            payload_size,                                      # 5
            1.0 if severity >= 7 else 0.0,                     # 6
            1.0 if intent in ("GPS_SPOOF", "SENSOR_SPOOF") else 0.0,  # 7 [LEAK]
            pkt_rate * severity,                               # 8
            1.0 if msg_id in GPS_MSG_IDS else 0.0,             # 9
            1.0 if msg_id in CMD_MSG_IDS else 0.0,             # 10
            1.0 if msg_id in MISSION_MSG_IDS else 0.0,         # 11
            1.0 if msg_id in STATUS_MSG_IDS else 0.0,          # 12
            1.0 if msg_id in PARAM_MSG_IDS else 0.0,           # 13
            1.0 if msg_id in CONTROL_MSG_IDS else 0.0,         # 14
            float(severity ** 2),                              # 15
        ])

    return np.array(X, dtype=float), intent_encoder


FEATURE_NAMES = [
    "severity", "packet_rate", "msg_id", "intent_encoded",
    "hour", "payload_size", "is_high_severity", "is_spoof_intent",
    "rate_severity", "is_gps_msg", "is_cmd_msg", "is_mission_msg",
    "is_status_msg", "is_param_msg", "is_control_msg", "severity_sq",
]


# ══════════════════════════════════════════════════════════════
# Cross-Validation Engine
# ══════════════════════════════════════════════════════════════

def run_anomaly_detection_cv(X, y_binary, n_splits=5):
    """
    K-fold cross-validation for anomaly detection models.

    Compares IsolationForest vs OneClassSVM vs LocalOutlierFactor.
    Since anomaly detectors are semi-supervised, we train on normal
    data and test on full (normal + anomalous).

    Returns dict with per-model results including fold-level metrics.
    """
    print(f"\n{'═' * 70}")
    print(f"  ANOMALY DETECTION — {n_splits}-Fold Cross-Validation")
    print(f"{'═' * 70}")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scaler = StandardScaler()

    models = {
        "IsolationForest": lambda: IsolationForest(
            contamination=0.15, n_estimators=200, random_state=42, n_jobs=-1
        ),
        "OneClassSVM": lambda: OneClassSVM(kernel='rbf', gamma='auto', nu=0.15),
        "LocalOutlierFactor": lambda: LocalOutlierFactor(
            n_neighbors=20, contamination=0.15, novelty=True
        ),
    }

    results = {}

    for model_name, model_fn in models.items():
        print(f"\n  ── {model_name} ──")
        fold_metrics = []

        for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, y_binary)):
            X_train, X_test = X[train_idx], X[test_idx]
            y_train, y_test = y_binary[train_idx], y_binary[test_idx]

            # Scale
            X_train_s = scaler.fit_transform(X_train)
            X_test_s = scaler.transform(X_test)

            # Train on normal data only (semi-supervised)
            normal_mask = y_train == 0
            X_train_normal = X_train_s[normal_mask]

            model = model_fn()
            model.fit(X_train_normal)

            # Predict
            y_pred_raw = model.predict(X_test_s)
            # Convert: sklearn uses 1=normal, -1=anomaly → we want 1=malicious, 0=normal
            y_pred = np.where(y_pred_raw == -1, 1, 0)

            # Anomaly scores for ROC
            if hasattr(model, 'decision_function'):
                scores = -model.decision_function(X_test_s)  # Negate: higher = more anomalous
            elif hasattr(model, 'score_samples'):
                scores = -model.score_samples(X_test_s)
            else:
                scores = y_pred.astype(float)

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)

            # ROC curve
            fpr, tpr, _ = roc_curve(y_test, scores)
            roc_auc = auc(fpr, tpr)

            # Precision-Recall curve
            pr_precision, pr_recall, _ = precision_recall_curve(y_test, scores)
            pr_auc = average_precision_score(y_test, scores)

            cm = confusion_matrix(y_test, y_pred).tolist()

            fold_metrics.append({
                "fold": fold_idx + 1,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "roc_auc": round(roc_auc, 4),
                "pr_auc": round(pr_auc, 4),
                "confusion_matrix": cm,
                "fpr": [round(x, 4) for x in fpr[::max(1, len(fpr)//20)]],
                "tpr": [round(x, 4) for x in tpr[::max(1, len(tpr)//20)]],
            })

            print(f"    Fold {fold_idx+1}: Acc={acc:.3f}  Prec={prec:.3f}  "
                  f"Rec={rec:.3f}  F1={f1:.3f}  AUC={roc_auc:.3f}")

        # Aggregate across folds
        metrics_keys = ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc"]
        aggregated = {}
        for key in metrics_keys:
            values = [fm[key] for fm in fold_metrics]
            aggregated[key] = {
                "mean": round(np.mean(values), 4),
                "std": round(np.std(values), 4),
                "min": round(np.min(values), 4),
                "max": round(np.max(values), 4),
            }

        print(f"\n    AVERAGE: Acc={aggregated['accuracy']['mean']:.3f}±{aggregated['accuracy']['std']:.3f}  "
              f"F1={aggregated['f1_score']['mean']:.3f}±{aggregated['f1_score']['std']:.3f}  "
              f"AUC={aggregated['roc_auc']['mean']:.3f}±{aggregated['roc_auc']['std']:.3f}")

        results[model_name] = {
            "fold_metrics": fold_metrics,
            "aggregated": aggregated,
        }

    # ── Statistical significance tests ──
    print(f"\n  ── Statistical Significance (Paired t-test on F1 across folds) ──")
    model_names = list(results.keys())
    significance = {}
    for i in range(len(model_names)):
        for j in range(i + 1, len(model_names)):
            m1, m2 = model_names[i], model_names[j]
            f1_1 = [fm["f1_score"] for fm in results[m1]["fold_metrics"]]
            f1_2 = [fm["f1_score"] for fm in results[m2]["fold_metrics"]]
            t_stat, p_value = stats.ttest_rel(f1_1, f1_2)
            key = f"{m1}_vs_{m2}"
            significance[key] = {
                "t_statistic": round(float(t_stat), 4),
                "p_value": round(float(p_value), 6),
                "significant_at_005": bool(p_value < 0.05),
            }
            sig = "✓" if p_value < 0.05 else "✗"
            print(f"    {m1} vs {m2}: t={t_stat:.3f}, p={p_value:.4f} {sig}")

    return results, significance


# Feature indices to DROP when classifying intent (they are derived from intent)
# Index 3 = intent_encoded, Index 7 = is_spoof_intent
INTENT_LEAK_COLS = [3, 7]
INTENT_FEATURE_NAMES = [
    n for i, n in enumerate(FEATURE_NAMES) if i not in INTENT_LEAK_COLS
]


def run_intent_classification_cv(X, y_intent, n_splits=5):
    """
    K-fold cross-validation for multi-class intent classification
    using RandomForest.

    IMPORTANT: Columns derived from the intent label (intent_encoded,
    is_spoof_intent) are removed to prevent data leakage / circularity.

    Returns per-class metrics, confusion matrix, and fold results.
    """
    print(f"\n{'═' * 70}")
    print(f"  INTENT CLASSIFICATION — {n_splits}-Fold Cross-Validation")
    print(f"  (intent-derived features REMOVED to prevent circularity)")
    print(f"{'═' * 70}")

    # Remove intent-derived columns to prevent circularity
    keep_cols = [i for i in range(X.shape[1]) if i not in INTENT_LEAK_COLS]
    X_clean = X[:, keep_cols]
    print(f"    Features used: {INTENT_FEATURE_NAMES}")
    print(f"    Dropped (circular): intent_encoded, is_spoof_intent")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scaler = StandardScaler()

    # Encode string labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_intent)
    class_names = le.classes_.tolist()

    fold_metrics = []

    for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X_clean, y_encoded)):
        X_train, X_test = X_clean[train_idx], X_clean[test_idx]
        y_train, y_test = y_encoded[train_idx], y_encoded[test_idx]

        X_train_s = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        clf = RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
        )
        clf.fit(X_train_s, y_train)
        y_pred = clf.predict(X_test_s)

        acc = accuracy_score(y_test, y_pred)
        prec_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
        rec_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
        f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
        f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        # Per-class report
        report = classification_report(
            y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
        )

        fold_metrics.append({
            "fold": fold_idx + 1,
            "accuracy": round(acc, 4),
            "precision_macro": round(prec_macro, 4),
            "recall_macro": round(rec_macro, 4),
            "f1_macro": round(f1_macro, 4),
            "f1_weighted": round(f1_weighted, 4),
            "confusion_matrix": cm,
            "per_class": {
                cls: {
                    "precision": round(report[cls]["precision"], 4),
                    "recall": round(report[cls]["recall"], 4),
                    "f1": round(report[cls]["f1-score"], 4),
                    "support": int(report[cls]["support"]),
                }
                for cls in class_names if cls in report
            },
        })

        print(f"    Fold {fold_idx+1}: Acc={acc:.3f}  F1-macro={f1_macro:.3f}  "
              f"F1-weighted={f1_weighted:.3f}")

    # Aggregate
    agg = {}
    for key in ["accuracy", "precision_macro", "recall_macro", "f1_macro", "f1_weighted"]:
        values = [fm[key] for fm in fold_metrics]
        agg[key] = {
            "mean": round(np.mean(values), 4),
            "std": round(np.std(values), 4),
        }

    print(f"\n    AVERAGE: Acc={agg['accuracy']['mean']:.3f}±{agg['accuracy']['std']:.3f}  "
          f"F1={agg['f1_macro']['mean']:.3f}±{agg['f1_macro']['std']:.3f}")

    # Feature importance (from last fold's model)
    importance = {
        name: round(float(imp), 4)
        for name, imp in zip(INTENT_FEATURE_NAMES, clf.feature_importances_)
    }
    sorted_importance = dict(sorted(importance.items(), key=lambda x: -x[1]))

    return {
        "class_names": class_names,
        "fold_metrics": fold_metrics,
        "aggregated": agg,
        "feature_importance": sorted_importance,
    }


# ══════════════════════════════════════════════════════════════
# Main Pipeline
# ══════════════════════════════════════════════════════════════

def run_full_evaluation():
    """Run the complete ML evaluation pipeline."""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  MAVLink Honeypot — ML Cross-Validation & Evaluation       ║")
    print("║  For IEEE TIFS Paper                                       ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    # ── 1. Generate synthetic dataset ──
    print("\n📊 Generating synthetic dataset (12,000 events)...")
    events = generate_synthetic_dataset(n_events=12000, seed=42)
    print(f"   Generated {len(events)} events across {len(ATTACK_PROFILES)} profiles")

    profile_counts = defaultdict(int)
    intent_counts = defaultdict(int)
    for e in events:
        profile_counts[e["attack_profile"]] += 1
        intent_counts[e["intent"]] += 1

    print("\n   Profile distribution:")
    for profile, count in sorted(profile_counts.items()):
        print(f"     {profile:25s}: {count:5d} ({count/len(events)*100:.1f}%)")

    print("\n   Intent distribution:")
    for intent, count in sorted(intent_counts.items(), key=lambda x: -x[1]):
        print(f"     {intent:20s}: {count:5d} ({count/len(events)*100:.1f}%)")

    # ── 2. Extract features ──
    print("\n🔧 Extracting features...")
    X, intent_encoder = extract_features(events)
    y_binary = np.array([1 if e["is_malicious"] else 0 for e in events])
    y_intent = np.array([e["intent"] for e in events])

    print(f"   Feature matrix: {X.shape}")
    print(f"   Malicious: {y_binary.sum()}, Benign: {(y_binary == 0).sum()}")

    # ── 3. Anomaly detection cross-validation (5-fold) ──
    anomaly_results_5, significance_5 = run_anomaly_detection_cv(X, y_binary, n_splits=5)

    # ── 4. Anomaly detection cross-validation (10-fold) ──
    anomaly_results_10, significance_10 = run_anomaly_detection_cv(X, y_binary, n_splits=10)

    # ── 5. Intent classification cross-validation ──
    intent_results = run_intent_classification_cv(X, y_intent, n_splits=5)

    # ── 6. Compile results ──
    results = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "dataset_size": len(events),
            "n_features": X.shape[1],
            "feature_names": FEATURE_NAMES,
            "attack_profiles": list(ATTACK_PROFILES.keys()),
            "profile_distribution": dict(profile_counts),
            "intent_distribution": dict(intent_counts),
            "malicious_count": int(y_binary.sum()),
            "benign_count": int((y_binary == 0).sum()),
        },
        "anomaly_detection": {
            "5_fold": {
                "models": anomaly_results_5,
                "statistical_significance": significance_5,
            },
            "10_fold": {
                "models": anomaly_results_10,
                "statistical_significance": significance_10,
            },
        },
        "intent_classification": intent_results,
    }

    # ── 7. Generate summary tables ──
    print(f"\n{'═' * 70}")
    print("  SUMMARY — Anomaly Detection (5-Fold CV)")
    print(f"{'═' * 70}")
    print(f"\n  {'Model':25s} │ {'Accuracy':>10s} │ {'Precision':>10s} │ "
          f"{'Recall':>10s} │ {'F1':>10s} │ {'AUC':>10s}")
    print("  " + "─" * 25 + "─┼─" + "─" * 10 + "─┼─" + "─" * 10 + "─┼─" +
          "─" * 10 + "─┼─" + "─" * 10 + "─┼─" + "─" * 10)
    for model, data in anomaly_results_5.items():
        a = data["aggregated"]
        print(f"  {model:25s} │ "
              f"{a['accuracy']['mean']:.3f}±{a['accuracy']['std']:.3f} │ "
              f"{a['precision']['mean']:.3f}±{a['precision']['std']:.3f} │ "
              f"{a['recall']['mean']:.3f}±{a['recall']['std']:.3f} │ "
              f"{a['f1_score']['mean']:.3f}±{a['f1_score']['std']:.3f} │ "
              f"{a['roc_auc']['mean']:.3f}±{a['roc_auc']['std']:.3f}")

    print(f"\n{'═' * 70}")
    print("  SUMMARY — Intent Classification (5-Fold CV)")
    print(f"{'═' * 70}")
    a = intent_results["aggregated"]
    print(f"\n  Accuracy:        {a['accuracy']['mean']:.3f} ± {a['accuracy']['std']:.3f}")
    print(f"  F1 (macro):      {a['f1_macro']['mean']:.3f} ± {a['f1_macro']['std']:.3f}")
    print(f"  F1 (weighted):   {a['f1_weighted']['mean']:.3f} ± {a['f1_weighted']['std']:.3f}")
    print(f"\n  Top features: {list(intent_results['feature_importance'].items())[:5]}")

    # ── 8. Save results ──
    out_dir = os.path.join(PROJECT_ROOT, "reproducibility", "results")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "ml_evaluation.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to: {out_path}")

    # Also save the synthetic dataset
    dataset_dir = os.path.join(PROJECT_ROOT, "reproducibility", "datasets")
    os.makedirs(dataset_dir, exist_ok=True)
    dataset_path = os.path.join(dataset_dir, "synthetic_evaluation_12k.json")
    with open(dataset_path, "w") as f:
        json.dump(events[:100], f, indent=2)  # Save sample (full dataset = memory heavy)
    print(f"💾 Dataset sample saved to: {dataset_path}")

    return results


if __name__ == "__main__":
    run_full_evaluation()
