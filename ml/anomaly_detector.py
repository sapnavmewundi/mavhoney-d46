#!/usr/bin/env python3
"""
MAVLink Honeypot — Anomaly Detection Module
Uses IsolationForest to detect novel attack patterns that rule-based
semantic analysis might miss.
"""

import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


class AnomalyDetector:
    """
    IsolationForest-based anomaly detector for MAVLink attack traffic.
    Trains on historical CSV datasets and flags novel/unusual attack patterns.
    """

    INTENT_CATEGORIES = [
        "RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
        "MISSION_INJECT", "CONFIG_ATTACK", "SENSOR_SPOOF",
        "DOS_FLOOD", "UNKNOWN"
    ]

    def __init__(self, contamination=0.1, n_estimators=200, random_state=42):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1
        )
        self.intent_encoder = LabelEncoder()
        self.intent_encoder.fit(self.INTENT_CATEGORIES)
        self.is_trained = False
        self.feature_names = []

    # MSG_ID category sets — same as cross_validator.py
    GPS_MSG_IDS = {24, 33, 113, 132, 241}
    CMD_MSG_IDS = {11, 76, 400}
    MISSION_MSG_IDS = {511, 512, 513, 514, 23}
    STATUS_MSG_IDS = {0, 1, 2, 147, 148, 242, 252, 253}
    PARAM_MSG_IDS = {20, 21, 23}
    CONTROL_MSG_IDS = {84, 86, 83}

    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract 16 numerical features matching cross_validator.py feature set."""
        features = pd.DataFrame()

        # 0. Severity
        features['severity'] = pd.to_numeric(
            df.get('severity', 3), errors='coerce'
        ).fillna(3)

        # 1. Packet rate
        features['packet_rate'] = pd.to_numeric(
            df.get('packet_rate', 0), errors='coerce'
        ).fillna(0)

        # 2. Message ID (raw)
        msg_ids = pd.to_numeric(df.get('msg_id', 0), errors='coerce').fillna(0)
        features['msg_id'] = msg_ids

        # 3. Intent (encoded)
        if 'intent' in df.columns:
            intent_values = df['intent'].fillna('UNKNOWN').astype(str)
            known_mask = intent_values.isin(self.INTENT_CATEGORIES)
            intent_values = intent_values.where(known_mask, 'UNKNOWN')
            features['intent_encoded'] = self.intent_encoder.transform(intent_values)
        else:
            features['intent_encoded'] = 0

        # 4. Hour of day
        if 'timestamp' in df.columns:
            try:
                features['hour'] = pd.to_datetime(
                    df['timestamp'], errors='coerce'
                ).dt.hour.fillna(12)
            except Exception:
                features['hour'] = 12
        elif 'hour' in df.columns:
            features['hour'] = pd.to_numeric(df['hour'], errors='coerce').fillna(12)
        else:
            features['hour'] = 12

        # 5. Payload size
        if 'payload_hex' in df.columns:
            features['payload_size'] = df['payload_hex'].fillna('').str.len() // 2
        else:
            features['payload_size'] = 0

        # 6. High-severity indicator
        features['is_high_severity'] = (features['severity'] >= 7).astype(float)

        # 7. Spoof-intent indicator
        if 'intent' in df.columns:
            features['is_spoof_intent'] = df['intent'].isin(
                ['GPS_SPOOF', 'SENSOR_SPOOF']
            ).astype(float)
        else:
            features['is_spoof_intent'] = 0.0

        # 8. Rate × severity interaction
        features['rate_severity'] = features['packet_rate'] * features['severity']

        # 9-14. Protocol-derived MSG_ID binary features
        features['is_gps_msg'] = msg_ids.isin(self.GPS_MSG_IDS).astype(float)
        features['is_cmd_msg'] = msg_ids.isin(self.CMD_MSG_IDS).astype(float)
        features['is_mission_msg'] = msg_ids.isin(self.MISSION_MSG_IDS).astype(float)
        features['is_status_msg'] = msg_ids.isin(self.STATUS_MSG_IDS).astype(float)
        features['is_param_msg'] = msg_ids.isin(self.PARAM_MSG_IDS).astype(float)
        features['is_control_msg'] = msg_ids.isin(self.CONTROL_MSG_IDS).astype(float)

        # 15. Severity squared
        features['severity_sq'] = features['severity'] ** 2

        self.feature_names = list(features.columns)
        return features.values.astype(float)

    def train(self, csv_path: str) -> dict:
        """
        Train on a CSV attack dataset.
        Returns training stats.
        """
        print(f"📊 Loading dataset: {csv_path}")
        df = pd.read_csv(csv_path)

        if len(df) < 10:
            raise ValueError(f"Dataset too small ({len(df)} rows). Need at least 10 rows.")

        print(f"   Rows: {len(df)}, Columns: {list(df.columns)}")

        X = self._extract_features(df)
        print(f"   Features extracted: {self.feature_names}")

        print(f"🧠 Training IsolationForest (n_estimators={self.model.n_estimators})...")
        self.model.fit(X)
        self.is_trained = True

        # Get training anomaly scores
        scores = self.model.decision_function(X)
        predictions = self.model.predict(X)
        n_anomalies = (predictions == -1).sum()

        stats = {
            "rows_trained": len(df),
            "features": self.feature_names,
            "anomalies_found": int(n_anomalies),
            "anomaly_rate": round(n_anomalies / len(df) * 100, 2),
            "mean_score": round(float(scores.mean()), 4),
            "min_score": round(float(scores.min()), 4),
            "trained_at": datetime.now().isoformat()
        }

        print(f"✅ Training complete!")
        print(f"   Anomalies detected in training data: {n_anomalies}/{len(df)} ({stats['anomaly_rate']}%)")
        return stats

    def predict(self, features_dict: dict) -> tuple:
        """
        Predict whether a single attack event is anomalous.

        Args:
            features_dict: dict with keys matching feature names
                           (severity, packet_rate, msg_id, intent, timestamp, payload_hex)

        Returns:
            (is_anomaly: bool, anomaly_score: float)
            score < 0 means anomaly, score > 0 means normal
        """
        if not self.is_trained:
            return False, 0.0

        severity = float(features_dict.get('severity', 3))
        packet_rate = float(features_dict.get('packet_rate', 0))
        msg_id = float(features_dict.get('msg_id', 0))

        intent = str(features_dict.get('intent', 'UNKNOWN'))
        if intent not in self.INTENT_CATEGORIES:
            intent = 'UNKNOWN'
        intent_encoded = float(self.intent_encoder.transform([intent])[0])

        timestamp = features_dict.get('timestamp', '')
        try:
            hour = float(pd.to_datetime(timestamp).hour)
        except Exception:
            hour = float(datetime.now().hour)

        payload_hex = str(features_dict.get('payload_hex', ''))
        payload_size = float(len(payload_hex) // 2)

        # Derived features
        is_high_severity = 1.0 if severity >= 7 else 0.0
        is_spoof_intent = 1.0 if intent in ('GPS_SPOOF', 'SENSOR_SPOOF') else 0.0
        rate_severity = packet_rate * severity
        is_gps_msg = 1.0 if int(msg_id) in self.GPS_MSG_IDS else 0.0
        is_cmd_msg = 1.0 if int(msg_id) in self.CMD_MSG_IDS else 0.0
        is_mission_msg = 1.0 if int(msg_id) in self.MISSION_MSG_IDS else 0.0
        is_status_msg = 1.0 if int(msg_id) in self.STATUS_MSG_IDS else 0.0
        is_param_msg = 1.0 if int(msg_id) in self.PARAM_MSG_IDS else 0.0
        is_control_msg = 1.0 if int(msg_id) in self.CONTROL_MSG_IDS else 0.0
        severity_sq = severity ** 2

        row = {
            'severity': severity, 'packet_rate': packet_rate, 'msg_id': msg_id,
            'intent_encoded': intent_encoded, 'hour': hour,
            'payload_size': payload_size, 'is_high_severity': is_high_severity,
            'is_spoof_intent': is_spoof_intent, 'rate_severity': rate_severity,
            'is_gps_msg': is_gps_msg, 'is_cmd_msg': is_cmd_msg,
            'is_mission_msg': is_mission_msg, 'is_status_msg': is_status_msg,
            'is_param_msg': is_param_msg, 'is_control_msg': is_control_msg,
            'severity_sq': severity_sq,
        }

        X = np.array([[row[f] for f in self.feature_names]])

        score = float(self.model.decision_function(X)[0])
        prediction = int(self.model.predict(X)[0])

        is_anomaly = prediction == -1
        return is_anomaly, round(score, 4)

    def save_model(self, path: str):
        """Save trained model to pickle file."""
        model_data = {
            'model': self.model,
            'intent_encoder': self.intent_encoder,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
        }
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"💾 Model saved to {path}")

    def load_model(self, path: str) -> bool:
        """Load a previously trained model. Returns True if successful."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
            self.model = model_data['model']
            self.intent_encoder = model_data['intent_encoder']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            print(f"✅ Model loaded from {path}")
            return True
        except Exception as e:
            print(f"⚠️  Failed to load model: {e}")
            return False


if __name__ == "__main__":
    print("🧪 Anomaly Detector — Standalone Test")
    detector = AnomalyDetector()

    # Test with sample data
    test_event = {
        'severity': 9,
        'packet_rate': 45.0,
        'msg_id': 113,
        'intent': 'GPS_SPOOF',
        'timestamp': datetime.now().isoformat(),
        'payload_hex': 'fe0a00ff00' * 5
    }

    print(f"\nTest event: {test_event}")
    is_anomaly, score = detector.predict(test_event)
    print(f"Result: anomaly={is_anomaly}, score={score}")
    print("(Model not trained — returns defaults)")
