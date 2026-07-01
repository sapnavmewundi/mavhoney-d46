#!/usr/bin/env python3
"""
MAVLink Honeypot — ML-Powered Attacker Skill Classifier
Uses Random Forest to classify attackers based on behavioral features.
"""

import os
import json
import numpy as np
from datetime import datetime

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import pickle
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'skill_model.pkl')

# ── Synthetic training data for bootstrap ──
# Format: [timing_avg_ms, timing_variance, unique_attacks, session_count,
#          total_cmds, sequence_entropy, sophistication_avg, ip_count]
BOOTSTRAP_DATA = {
    "SCRIPT_KIDDIE": [
        [8000, 5000, 1, 1, 2, 0.0, 1.0, 1],
        [6000, 4000, 1, 1, 3, 0.0, 1.5, 1],
        [10000, 8000, 2, 1, 4, 0.5, 2.0, 1],
        [12000, 6000, 1, 2, 5, 0.0, 1.0, 1],
        [7000, 3500, 2, 1, 3, 0.6, 1.5, 1],
        [15000, 10000, 1, 1, 1, 0.0, 1.0, 1],
        [9000, 7000, 1, 1, 2, 0.0, 2.0, 1],
        [5000, 4000, 2, 1, 6, 0.3, 1.2, 1],
    ],
    "INTERMEDIATE": [
        [2000, 1500, 3, 2, 10, 1.2, 3.0, 1],
        [3000, 2000, 3, 3, 12, 1.4, 3.5, 1],
        [1500, 1000, 4, 2, 15, 1.5, 3.2, 2],
        [2500, 1800, 3, 2, 8, 1.1, 2.8, 1],
        [4000, 2500, 3, 3, 11, 1.3, 3.0, 2],
        [1800, 1200, 4, 2, 14, 1.6, 3.4, 1],
        [3500, 2200, 3, 4, 9, 1.0, 2.5, 1],
        [2200, 1400, 4, 3, 18, 1.7, 3.8, 2],
    ],
    "ADVANCED": [
        [500, 200, 5, 5, 25, 2.0, 4.5, 2],
        [800, 400, 5, 4, 20, 1.9, 4.0, 3],
        [300, 150, 6, 6, 30, 2.2, 4.8, 2],
        [600, 300, 5, 5, 22, 2.1, 4.2, 2],
        [400, 180, 6, 4, 28, 2.3, 5.0, 3],
        [700, 350, 5, 7, 35, 2.0, 4.3, 2],
        [1000, 600, 4, 5, 18, 1.8, 4.0, 3],
        [250, 100, 7, 5, 32, 2.4, 5.2, 2],
    ],
    "APT": [
        [150, 50, 7, 10, 50, 2.5, 5.0, 4],
        [100, 30, 8, 12, 60, 2.6, 5.5, 5],
        [200, 80, 7, 8, 45, 2.4, 5.2, 4],
        [120, 40, 8, 15, 70, 2.7, 5.8, 6],
        [80, 25, 8, 10, 55, 2.5, 5.3, 5],
        [180, 70, 7, 12, 48, 2.4, 5.0, 4],
        [250, 100, 6, 20, 80, 2.3, 4.8, 7],
        [130, 45, 8, 11, 65, 2.6, 5.6, 5],
    ],
}

SKILL_LABELS = ["SCRIPT_KIDDIE", "INTERMEDIATE", "ADVANCED", "APT"]
FEATURE_NAMES = [
    "timing_avg_ms", "timing_variance", "unique_attacks", "session_count",
    "total_commands", "sequence_entropy", "sophistication_avg", "ip_count"
]


class SkillClassifier:
    """Random Forest classifier for attacker skill levels."""

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=8, random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._try_load()

    def _try_load(self):
        """Load a previously trained model if available."""
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_trained = True
            except Exception:
                self._bootstrap_train()
        else:
            self._bootstrap_train()

    def _bootstrap_train(self):
        """Train on synthetic bootstrap data."""
        if not ML_AVAILABLE:
            return

        X, y = [], []
        for label, samples in BOOTSTRAP_DATA.items():
            for sample in samples:
                X.append(sample)
                y.append(label)

        X = np.array(X, dtype=float)
        y = np.array(y)

        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True
        self.save()

    def predict(self, features: dict) -> dict:
        """
        Predict attacker skill level from behavioral features.

        Args:
            features: dict with keys from FEATURE_NAMES

        Returns:
            {"skill_level": str, "confidence": float, "probabilities": dict}
        """
        if not self.is_trained or not ML_AVAILABLE:
            return {
                "skill_level": "UNKNOWN",
                "confidence": 0.0,
                "probabilities": {}
            }

        row = [features.get(f, 0) for f in FEATURE_NAMES]
        X = np.array([row], dtype=float)
        X_scaled = self.scaler.transform(X)

        prediction = self.model.predict(X_scaled)[0]
        probabilities = self.model.predict_proba(X_scaled)[0]
        class_names = self.model.classes_

        prob_dict = {
            str(cls): round(float(prob), 3)
            for cls, prob in zip(class_names, probabilities)
        }
        confidence = round(float(max(probabilities)), 3)

        return {
            "skill_level": str(prediction),
            "confidence": confidence,
            "probabilities": prob_dict
        }

    def retrain(self, training_data: list):
        """
        Retrain with real observed data.

        Args:
            training_data: list of dicts with FEATURE_NAMES keys + "label"
        """
        if not ML_AVAILABLE:
            return

        # Start with bootstrap data
        X, y = [], []
        for label, samples in BOOTSTRAP_DATA.items():
            for sample in samples:
                X.append(sample)
                y.append(label)

        # Add real data
        for entry in training_data:
            row = [entry.get(f, 0) for f in FEATURE_NAMES]
            X.append(row)
            y.append(entry["label"])

        X = np.array(X, dtype=float)
        y = np.array(y)

        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled, y)
        self.is_trained = True
        self.save()

    def save(self):
        """Save model to disk."""
        try:
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                }, f)
        except Exception:
            pass

    @staticmethod
    def extract_features_from_fingerprint(fp_dict: dict) -> dict:
        """
        Extract classifier features from a BehaviorSignature dict.
        Compatible with fingerprint.get_all_fingerprints() output.
        """
        attacks = fp_dict.get("preferred_attacks", {})
        total = sum(attacks.values()) if attacks else 0
        unique = len(attacks)

        # Sequence entropy approximation
        entropy = 0.0
        if total > 0:
            for count in attacks.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)

        # Sophistication weights
        SOPH = {
            "RECON": 1, "CONTROL": 3, "HIJACK": 5, "GPS_SPOOF": 5,
            "MISSION_INJECT": 6, "CONFIG_ATTACK": 4, "SENSOR_SPOOF": 5,
            "DOS_FLOOD": 2, "UNKNOWN": 1
        }
        soph_avg = 0
        if total > 0:
            soph_avg = sum(SOPH.get(a, 1) * c for a, c in attacks.items()) / total

        return {
            "timing_avg_ms": fp_dict.get("avg_inter_action_ms", 0),
            "timing_variance": fp_dict.get("avg_inter_action_ms", 0) * 0.5,
            "unique_attacks": unique,
            "session_count": fp_dict.get("sessions", 1),
            "total_commands": total,
            "sequence_entropy": round(entropy, 3),
            "sophistication_avg": round(soph_avg, 2),
            "ip_count": len(fp_dict.get("ips_used", [1])),
        }


if __name__ == "__main__":
    print("🧠 Skill Classifier — Standalone Test")

    classifier = SkillClassifier()

    test_cases = [
        {"name": "Newbie", "timing_avg_ms": 8000, "timing_variance": 5000,
         "unique_attacks": 1, "session_count": 1, "total_commands": 2,
         "sequence_entropy": 0.0, "sophistication_avg": 1.0, "ip_count": 1},
        {"name": "Script Kiddie", "timing_avg_ms": 5000, "timing_variance": 3000,
         "unique_attacks": 2, "session_count": 1, "total_commands": 5,
         "sequence_entropy": 0.5, "sophistication_avg": 2.0, "ip_count": 1},
        {"name": "Intermediate", "timing_avg_ms": 2000, "timing_variance": 1500,
         "unique_attacks": 3, "session_count": 3, "total_commands": 12,
         "sequence_entropy": 1.4, "sophistication_avg": 3.5, "ip_count": 2},
        {"name": "Advanced", "timing_avg_ms": 500, "timing_variance": 200,
         "unique_attacks": 5, "session_count": 5, "total_commands": 25,
         "sequence_entropy": 2.0, "sophistication_avg": 4.5, "ip_count": 3},
        {"name": "APT", "timing_avg_ms": 100, "timing_variance": 30,
         "unique_attacks": 8, "session_count": 12, "total_commands": 60,
         "sequence_entropy": 2.6, "sophistication_avg": 5.5, "ip_count": 5},
    ]

    for tc in test_cases:
        name = tc.pop("name")
        result = classifier.predict(tc)
        print(f"\n  {name}:")
        print(f"    Prediction: {result['skill_level']}")
        print(f"    Confidence: {result['confidence']:.1%}")
        print(f"    Probabilities: {result['probabilities']}")
