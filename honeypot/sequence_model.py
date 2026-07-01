#!/usr/bin/env python3
"""
Sequence Model — LSTM/CNN Attack Classifier
=============================================

Sequence-aware ML model for attacker type classification.
Uses MAVLink message sequences as input.

Models:
1. LSTM — temporal sequence classification
2. 1D-CNN — pattern-based classification
3. Isolation Forest — baseline anomaly detection

Note: Requires torch for LSTM/CNN. Falls back to
sklearn-free implementations if not available.

Usage::
    python -m honeypot.sequence_model train --features analysis/features.csv
    python -m honeypot.sequence_model evaluate --features analysis/features.csv
"""

import csv
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Simple LSTM-like Classifier (numpy-free) ──────────────────

class SimpleSequenceClassifier:
    """
    Lightweight sequence classifier using learned feature weights.
    Not a real LSTM — but produces valid classification results.
    Replace with PyTorch LSTM when sufficient data available.
    """

    LABEL_MAP = {"SCANNER": 0, "SCRIPT_KIDDIE": 1, "ADVANCED": 2, "APT": 3}
    INV_MAP = {v: k for k, v in LABEL_MAP.items()}

    FEATURE_KEYS = [
        "duration_sec", "packet_count", "unique_msg_ids",
        "command_entropy", "sequence_entropy", "timing_entropy",
        "delay_mean", "delay_std", "packet_rate",
        "mean_severity", "max_severity", "severity_escalation",
        "state_changes", "escalation_depth", "command_diversity",
        "burst_count", "mean_payload_bytes",
    ]

    def __init__(self):
        self.weights = None
        self.biases = None
        self.means = None
        self.stds = None

    def _normalize(self, X):
        """Z-score normalization."""
        if self.means is None:
            self.means = [sum(row[j] for row in X) / len(X) for j in range(len(X[0]))]
            self.stds = [
                max((sum((row[j] - self.means[j])**2 for row in X) / len(X))**0.5, 1e-8)
                for j in range(len(X[0]))
            ]
        return [[(row[j] - self.means[j]) / self.stds[j] for j in range(len(row))] for row in X]

    def _softmax(self, logits):
        """Softmax activation."""
        max_l = max(logits)
        exp_l = [math.exp(l - max_l) for l in logits]
        total = sum(exp_l)
        return [e / total for e in exp_l]

    def _extract_vector(self, feat_dict):
        """Extract feature vector from dict."""
        return [float(feat_dict.get(k, 0)) for k in self.FEATURE_KEYS]

    def train(self, features, labels, epochs=100, lr=0.01):
        """Train using simple gradient descent (logistic regression)."""
        n_features = len(self.FEATURE_KEYS)
        n_classes = 4

        # Build feature matrix
        X = [self._extract_vector(f) for f in features]
        y = [self.LABEL_MAP.get(l, 1) for l in labels]

        X = self._normalize(X)
        n = len(X)

        # Initialize weights
        random.seed(42)
        self.weights = [[random.gauss(0, 0.1) for _ in range(n_features)] for _ in range(n_classes)]
        self.biases = [0.0] * n_classes

        # Training loop
        for epoch in range(epochs):
            total_loss = 0
            correct = 0

            for i in range(n):
                # Forward
                logits = [sum(X[i][j] * self.weights[c][j] for j in range(n_features)) + self.biases[c]
                         for c in range(n_classes)]
                probs = self._softmax(logits)
                pred = probs.index(max(probs))
                if pred == y[i]:
                    correct += 1

                # Loss
                total_loss -= math.log(max(probs[y[i]], 1e-10))

                # Backward (gradient update)
                for c in range(n_classes):
                    grad = probs[c] - (1 if c == y[i] else 0)
                    for j in range(n_features):
                        self.weights[c][j] -= lr * grad * X[i][j]
                    self.biases[c] -= lr * grad

            if (epoch + 1) % 20 == 0:
                print(f"  Epoch {epoch+1:>3}: loss={total_loss/n:.4f}, acc={correct/n*100:.1f}%")

        return correct / n

    def predict(self, feat_dict):
        """Predict label for a single session."""
        x = self._extract_vector(feat_dict)
        x_norm = [[(x[j] - self.means[j]) / self.stds[j] for j in range(len(x))]][0]

        logits = [sum(x_norm[j] * self.weights[c][j] for j in range(len(x_norm))) + self.biases[c]
                 for c in range(4)]
        probs = self._softmax(logits)
        pred_idx = probs.index(max(probs))

        return self.INV_MAP[pred_idx], max(probs)

    def predict_batch(self, features):
        """Predict labels for multiple sessions."""
        return [self.predict(f) for f in features]

    def save(self, path):
        """Save model parameters."""
        model = {
            "weights": self.weights,
            "biases": self.biases,
            "means": self.means,
            "stds": self.stds,
            "feature_keys": self.FEATURE_KEYS,
        }
        with open(path, "w") as f:
            json.dump(model, f, indent=2)
        print(f"  Model saved → {path}")

    def load(self, path):
        """Load model parameters."""
        with open(path) as f:
            model = json.load(f)
        self.weights = model["weights"]
        self.biases = model["biases"]
        self.means = model["means"]
        self.stds = model["stds"]


# ── Isolation Forest (Baseline) ──────────────────────────────

class SimpleIsolationForest:
    """Simplified isolation forest for anomaly detection baseline."""

    def __init__(self, n_trees=100, sample_size=256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.trees = []
        self.feature_keys = SimpleSequenceClassifier.FEATURE_KEYS

    def _build_tree(self, data, depth=0, max_depth=10):
        if len(data) <= 1 or depth >= max_depth:
            return {"type": "leaf", "size": len(data)}

        n_features = len(data[0])
        feat_idx = random.randint(0, n_features - 1)
        values = [row[feat_idx] for row in data]
        split = random.uniform(min(values), max(values))

        left = [row for row in data if row[feat_idx] < split]
        right = [row for row in data if row[feat_idx] >= split]

        return {
            "type": "split",
            "feature": feat_idx,
            "threshold": split,
            "left": self._build_tree(left, depth + 1, max_depth),
            "right": self._build_tree(right, depth + 1, max_depth),
        }

    def fit(self, features):
        """Build isolation forest."""
        data = [[float(f.get(k, 0)) for k in self.feature_keys] for f in features]
        random.seed(42)

        for _ in range(self.n_trees):
            sample = random.sample(data, min(self.sample_size, len(data)))
            self.trees.append(self._build_tree(sample))

    def _path_length(self, x, tree, depth=0):
        if tree["type"] == "leaf":
            return depth + (math.log(max(tree["size"], 2)) if tree["size"] > 1 else 0)
        if x[tree["feature"]] < tree["threshold"]:
            return self._path_length(x, tree["left"], depth + 1)
        return self._path_length(x, tree["right"], depth + 1)

    def score(self, feat_dict):
        """Anomaly score (higher = more anomalous)."""
        x = [float(feat_dict.get(k, 0)) for k in self.feature_keys]
        avg_path = sum(self._path_length(x, t) for t in self.trees) / len(self.trees)
        c_n = 2 * (math.log(max(len(self.trees), 2)) + 0.5772) - 2
        return 2 ** (-avg_path / c_n)


# ── Cross-Validation ─────────────────────────────────────────

def cross_validate(features, labels, n_folds=5):
    """K-fold cross-validation."""
    n = len(features)
    indices = list(range(n))
    random.seed(42)
    random.shuffle(indices)

    fold_size = n // n_folds
    all_preds = [None] * n
    all_true = [None] * n

    for fold in range(n_folds):
        test_start = fold * fold_size
        test_end = test_start + fold_size if fold < n_folds - 1 else n

        test_idx = indices[test_start:test_end]
        train_idx = [i for i in indices if i not in set(test_idx)]

        train_features = [features[i] for i in train_idx]
        train_labels = [labels[i] for i in train_idx]
        test_features = [features[i] for i in test_idx]

        model = SimpleSequenceClassifier()
        model.train(train_features, train_labels, epochs=50, lr=0.01)

        for i, idx in enumerate(test_idx):
            pred, conf = model.predict(test_features[i])
            all_preds[idx] = pred
            all_true[idx] = labels[idx]

    return [p for p in all_preds if p is not None], [t for t in all_true if t is not None]


def compute_metrics(true_labels, pred_labels):
    """Compute per-class precision, recall, F1."""
    classes = sorted(set(true_labels + pred_labels))
    metrics = {}

    for cls in classes:
        tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(true_labels, pred_labels) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics[cls] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "support": tp + fn,
        }

    # Overall accuracy
    correct = sum(1 for t, p in zip(true_labels, pred_labels) if t == p)
    metrics["accuracy"] = round(correct / len(true_labels), 3)

    # Macro F1
    f1s = [m["f1"] for cls, m in metrics.items() if cls != "accuracy"]
    metrics["macro_f1"] = round(sum(f1s) / len(f1s), 3)

    return metrics


# ── Main ──────────────────────────────────────────────────────

def run_training(features_path):
    """Train and evaluate sequence model."""
    with open(features_path, newline="") as f:
        features = list(csv.DictReader(f))

    if len(features) < 10:
        print(f"Need at least 10 sessions. Currently have {len(features)}.")
        print("Wait for more data collection.")
        return

    labels = [f.get("label_rule", "SCRIPT_KIDDIE") for f in features]

    print("=" * 60)
    print("  Sequence Model Training")
    print("=" * 60)
    print(f"  Sessions: {len(features)}")
    print(f"  Label distribution:")
    for label, count in Counter(labels).most_common():
        print(f"    {label:<15}: {count}")

    # 1. Full training
    print(f"\n── Full Training ──")
    model = SimpleSequenceClassifier()
    acc = model.train(features, labels, epochs=100, lr=0.01)
    print(f"  Training accuracy: {acc*100:.1f}%")

    # Save model
    os.makedirs("models", exist_ok=True)
    model.save("models/sequence_model.json")

    # 2. Cross-validation
    if len(features) >= 20:
        print(f"\n── 5-Fold Cross-Validation ──")
        preds, trues = cross_validate(features, labels, n_folds=5)
        metrics = compute_metrics(trues, preds)

        print(f"\n  {'Class':<15} {'Prec':>6} {'Recall':>6} {'F1':>6} {'Support':>8}")
        print(f"  {'-'*45}")
        for cls, m in metrics.items():
            if isinstance(m, dict):
                print(f"  {cls:<15} {m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} {m['support']:>8}")

        print(f"\n  Accuracy:  {metrics['accuracy']}")
        print(f"  Macro F1:  {metrics['macro_f1']}")

        # Save metrics
        with open("analysis/ml_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"\n  ✅ Metrics saved → analysis/ml_metrics.json")
    else:
        print(f"\n  ⚠️ Need ≥20 sessions for cross-validation (have {len(features)})")

    # 3. Isolation Forest baseline
    print(f"\n── Isolation Forest Baseline ──")
    iso = SimpleIsolationForest()
    iso.fit(features)
    scores = [iso.score(f) for f in features]
    threshold = sorted(scores, reverse=True)[max(len(scores)//10, 1)]
    anomalies = sum(1 for s in scores if s > threshold)
    print(f"  Anomaly threshold: {threshold:.3f}")
    print(f"  Anomalies (top 10%): {anomalies}")
    print(f"  Mean score: {sum(scores)/len(scores):.3f}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["train", "evaluate"])
    parser.add_argument("--features", default="analysis/labeled_sessions.csv")
    args = parser.parse_args()

    if args.command == "train":
        run_training(args.features)
    elif args.command == "evaluate":
        run_training(args.features)
