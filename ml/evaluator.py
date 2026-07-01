#!/usr/bin/env python3
"""
MAVLink Honeypot — ML Evaluation Module
Evaluates ML detection models using accuracy, precision, recall, F1-score.
Compares rule-based vs ML-based detection and generates performance reports.
"""

import os
import json
import csv
import numpy as np
from datetime import datetime
from collections import defaultdict

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, classification_report
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')
REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')
ML_DIR = os.path.join(PROJECT_ROOT, 'ml')


class MLEvaluator:
    """Evaluate ML detection models and compare with rule-based detection."""

    # Rule-based severity thresholds
    RULE_SEVERITY_THRESHOLD = 5
    RULE_HIGH_THREAT_INTENTS = {
        'HIJACK', 'GPS_SPOOF', 'MISSION_INJECT', 'DOS_FLOOD'
    }

    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def load_dataset(self, csv_path: str = None) -> list:
        """Load attack dataset for evaluation."""
        if csv_path is None:
            # Find latest dataset
            csvs = sorted(
                [f for f in os.listdir(DATASETS_DIR) if f.endswith('.csv')],
                reverse=True
            )
            if not csvs:
                return []
            csv_path = os.path.join(DATASETS_DIR, csvs[0])

        events = []
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)
        return events

    def rule_based_predict(self, event: dict) -> dict:
        """Apply rule-based detection to an event."""
        severity = int(event.get('severity', 0))
        intent = event.get('intent', 'UNKNOWN')

        is_threat = (
            severity >= self.RULE_SEVERITY_THRESHOLD or
            intent in self.RULE_HIGH_THREAT_INTENTS
        )

        confidence = min(severity / 10.0, 1.0)
        if intent in self.RULE_HIGH_THREAT_INTENTS:
            confidence = max(confidence, 0.7)

        return {
            'is_threat': is_threat,
            'confidence': round(confidence, 3),
            'method': 'RULE_BASED',
        }

    def ml_predict(self, event: dict) -> dict:
        """Apply ML-based detection to an event."""
        try:
            from ml.anomaly_detector import AnomalyDetector
            detector = AnomalyDetector()
            model_path = os.path.join(ML_DIR, 'trained_model.pkl')
            if not detector.load_model(model_path):
                return {'is_threat': False, 'confidence': 0.0, 'method': 'ML_NO_MODEL'}

            is_anomaly, score = detector.predict(event)
            return {
                'is_threat': is_anomaly,
                'confidence': round(abs(score), 3),
                'method': 'ML_ISOLATION_FOREST',
            }
        except Exception as ex:
            return {'is_threat': False, 'confidence': 0.0, 'method': f'ML_ERROR: {ex}'}

    def evaluate(self, events: list = None) -> dict:
        """
        Run full evaluation comparing rule-based vs ML detection.

        Returns:
            dict with metrics for both approaches, confusion matrices, and comparison
        """
        if events is None:
            events = self.load_dataset()

        if not events:
            return {'error': 'No events to evaluate'}

        # Generate ground truth labels: events with severity >= 7 or
        # high-threat intents are considered true threats
        y_true = []
        rule_preds = []
        ml_preds = []

        for event in events:
            severity = int(event.get('severity', 0))
            intent = event.get('intent', 'UNKNOWN')

            # Ground truth: severity >= 7 or critical intent
            is_true_threat = (
                severity >= 7 or
                intent in {'HIJACK', 'GPS_SPOOF', 'MISSION_INJECT'}
            )
            y_true.append(1 if is_true_threat else 0)

            # Rule-based prediction
            rule_result = self.rule_based_predict(event)
            rule_preds.append(1 if rule_result['is_threat'] else 0)

            # ML prediction
            ml_result = self.ml_predict(event)
            ml_preds.append(1 if ml_result['is_threat'] else 0)

        y_true = np.array(y_true)
        rule_preds = np.array(rule_preds)
        ml_preds = np.array(ml_preds)

        results = {
            'total_events': len(events),
            'true_threats': int(y_true.sum()),
            'evaluated_at': datetime.now().isoformat(),
        }

        if SKLEARN_AVAILABLE:
            # Rule-based metrics
            results['rule_based'] = {
                'accuracy': round(accuracy_score(y_true, rule_preds), 4),
                'precision': round(precision_score(y_true, rule_preds, zero_division=0), 4),
                'recall': round(recall_score(y_true, rule_preds, zero_division=0), 4),
                'f1_score': round(f1_score(y_true, rule_preds, zero_division=0), 4),
                'confusion_matrix': confusion_matrix(y_true, rule_preds).tolist(),
                'predicted_threats': int(rule_preds.sum()),
            }

            # ML metrics
            results['ml_based'] = {
                'accuracy': round(accuracy_score(y_true, ml_preds), 4),
                'precision': round(precision_score(y_true, ml_preds, zero_division=0), 4),
                'recall': round(recall_score(y_true, ml_preds, zero_division=0), 4),
                'f1_score': round(f1_score(y_true, ml_preds, zero_division=0), 4),
                'confusion_matrix': confusion_matrix(y_true, ml_preds).tolist(),
                'predicted_threats': int(ml_preds.sum()),
            }

            # Comparison
            rule_f1 = results['rule_based']['f1_score']
            ml_f1 = results['ml_based']['f1_score']
            results['comparison'] = {
                'f1_improvement': round(ml_f1 - rule_f1, 4),
                'better_method': 'ML' if ml_f1 > rule_f1 else 'RULE',
                'agreement_rate': round(
                    np.mean(rule_preds == ml_preds), 4
                ),
            }
        else:
            results['error'] = 'scikit-learn not available for metrics'

        return results

    def generate_report(self, results: dict = None) -> str:
        """Generate evaluation report as Markdown."""
        if results is None:
            results = self.evaluate()

        report = [
            "# ML Detection Evaluation Report",
            f"\n**Generated**: {results.get('evaluated_at', 'N/A')}",
            f"**Total Events**: {results.get('total_events', 0)}",
            f"**True Threats**: {results.get('true_threats', 0)}",
            "\n## Detection Metrics Comparison",
            "\n| Metric | Rule-Based | ML-Based |",
            "|--------|-----------|----------|",
        ]

        rb = results.get('rule_based', {})
        ml = results.get('ml_based', {})

        for metric in ['accuracy', 'precision', 'recall', 'f1_score']:
            report.append(
                f"| {metric.replace('_', ' ').title()} | "
                f"{rb.get(metric, 'N/A')} | {ml.get(metric, 'N/A')} |"
            )

        comp = results.get('comparison', {})
        if comp:
            report.append(f"\n## Comparison")
            report.append(f"- **Better Method**: {comp.get('better_method', 'N/A')}")
            report.append(f"- **F1 Improvement**: {comp.get('f1_improvement', 0):+.4f}")
            report.append(f"- **Agreement Rate**: {comp.get('agreement_rate', 0):.1%}")

        report_text = '\n'.join(report)

        # Save report
        report_path = os.path.join(REPORTS_DIR, 'ml_evaluation.md')
        with open(report_path, 'w') as f:
            f.write(report_text)

        # Save raw JSON
        json_path = os.path.join(REPORTS_DIR, 'ml_evaluation.json')
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)

        return report_path


if __name__ == "__main__":
    print("ML Evaluator — Test")
    evaluator = MLEvaluator()

    events = evaluator.load_dataset()
    print(f"  Loaded {len(events)} events")

    if events:
        results = evaluator.evaluate(events)
        path = evaluator.generate_report(results)
        print(f"  Report saved to: {path}")
        for method in ['rule_based', 'ml_based']:
            m = results.get(method, {})
            print(f"  {method}: F1={m.get('f1_score', 'N/A')}, "
                  f"Precision={m.get('precision', 'N/A')}, "
                  f"Recall={m.get('recall', 'N/A')}")
    else:
        print("  No datasets found — skipping evaluation")
