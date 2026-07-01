#!/usr/bin/env python3
"""
MAVLink Honeypot — Threat Prediction Engine
Predicts attacker's next actions using Markov chains, estimates
time-to-critical, and flags deviations from expected behavior.
"""

import os
import json
import math
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field


PREDICTION_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'threat_predictions.json'
)


# Kill chain stages with severity escalation
KILL_CHAIN = {
    "RECON":           {"stage": 1, "severity": "LOW",      "label": "Reconnaissance"},
    "DOS_FLOOD":       {"stage": 2, "severity": "MEDIUM",   "label": "Disruption"},
    "CONTROL":         {"stage": 3, "severity": "HIGH",     "label": "Control Attempt"},
    "CONFIG_ATTACK":   {"stage": 4, "severity": "HIGH",     "label": "Configuration Tampering"},
    "SENSOR_SPOOF":    {"stage": 4, "severity": "HIGH",     "label": "Sensor Falsification"},
    "MISSION_INJECT":  {"stage": 5, "severity": "CRITICAL", "label": "Mission Injection"},
    "HIJACK":          {"stage": 6, "severity": "CRITICAL", "label": "Full Hijack"},
    "GPS_SPOOF":       {"stage": 7, "severity": "CRITICAL", "label": "GPS Spoofing"},
}


@dataclass
class AttackerPrediction:
    """Current prediction state for an attacker."""
    attacker_ip: str
    current_intent: str = "UNKNOWN"
    current_stage: int = 0
    predicted_next: str = ""
    prediction_confidence: float = 0.0
    predicted_alternatives: Dict[str, float] = field(default_factory=dict)
    time_to_critical_sec: float = -1      # Estimated seconds until critical attack
    kill_chain_progress: float = 0.0      # 0-100%
    is_deviating: bool = False            # Deviated from predicted pattern
    deviation_count: int = 0
    total_predictions: int = 0
    correct_predictions: int = 0
    prediction_accuracy: float = 0.0
    sequence_length: int = 0
    last_updated: str = ""


class ThreatPredictor:
    """
    Predicts attacker behavior using Markov chain transition matrices.

    Features:
    1. Next-action prediction with confidence scores
    2. Kill chain stage estimation
    3. Time-to-critical prediction
    4. Anomaly detection when attacker deviates from predicted pattern
    5. Preemptive response suggestion
    """

    # Minimum observations before making predictions
    MIN_OBSERVATIONS = 3
    # Critical intent types
    CRITICAL_INTENTS = {"HIJACK", "GPS_SPOOF", "MISSION_INJECT"}

    def __init__(self):
        # Global transition matrix: intent -> {next_intent -> count}
        self.transitions: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # Per-attacker sequences
        self.sequences: Dict[str, List[str]] = defaultdict(list)
        # Per-attacker timing between intents
        self.timing: Dict[str, List[float]] = defaultdict(list)
        self.last_event_time: Dict[str, float] = {}
        # Predictions
        self.predictions: Dict[str, AttackerPrediction] = {}
        self._load()

    def _load(self):
        if os.path.exists(PREDICTION_FILE):
            try:
                with open(PREDICTION_FILE, 'r') as f:
                    data = json.load(f)
                self.transitions = defaultdict(
                    lambda: defaultdict(int),
                    {k: defaultdict(int, v) for k, v in data.get("transitions", {}).items()}
                )
                for ip, pdata in data.get("predictions", {}).items():
                    self.predictions[ip] = AttackerPrediction(**pdata)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(PREDICTION_FILE), exist_ok=True)
            with open(PREDICTION_FILE, 'w') as f:
                json.dump({
                    "transitions": {k: dict(v) for k, v in self.transitions.items()},
                    "predictions": {k: asdict(v) for k, v in self.predictions.items()},
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    # ── Core Prediction ──

    def observe(self, attacker_ip: str, intent: str) -> dict:
        """
        Observe an attack event and update predictions.

        Args:
            attacker_ip: Attacker IP
            intent: Attack intent (RECON, CONTROL, HIJACK, etc.)

        Returns:
            Prediction result with next-action forecast
        """
        now = time.time()
        seq = self.sequences[attacker_ip]

        # Track timing
        if attacker_ip in self.last_event_time:
            delta = now - self.last_event_time[attacker_ip]
            self.timing[attacker_ip].append(delta)
        self.last_event_time[attacker_ip] = now

        # Check if previous prediction was correct
        pred = self.predictions.get(attacker_ip)
        if pred and pred.predicted_next:
            pred.total_predictions += 1
            if pred.predicted_next == intent:
                pred.correct_predictions += 1
            elif pred.prediction_confidence > 0.5:
                pred.is_deviating = True
                pred.deviation_count += 1
            else:
                pred.is_deviating = False

            if pred.total_predictions > 0:
                pred.prediction_accuracy = round(
                    pred.correct_predictions / pred.total_predictions, 3
                )

        # Update transition matrix
        if seq:
            prev = seq[-1]
            self.transitions[prev][intent] += 1

        seq.append(intent)

        # Make new prediction
        result = self._predict_next(attacker_ip, intent)

        # Estimate time-to-critical
        ttc = self._estimate_time_to_critical(attacker_ip, intent)

        # Update prediction record
        if attacker_ip not in self.predictions:
            self.predictions[attacker_ip] = AttackerPrediction(
                attacker_ip=attacker_ip
            )

        pred = self.predictions[attacker_ip]
        pred.current_intent = intent
        pred.current_stage = KILL_CHAIN.get(intent, {}).get("stage", 0)
        pred.predicted_next = result["predicted_next"]
        pred.prediction_confidence = result["confidence"]
        pred.predicted_alternatives = result["alternatives"]
        pred.time_to_critical_sec = ttc
        pred.kill_chain_progress = self._calc_progress(attacker_ip)
        pred.sequence_length = len(seq)
        pred.last_updated = datetime.now().isoformat()

        # Periodic save
        if len(seq) % 5 == 0:
            self._save()

        return {
            "current": intent,
            "predicted_next": result["predicted_next"],
            "confidence": result["confidence"],
            "alternatives": result["alternatives"],
            "kill_chain_stage": pred.current_stage,
            "kill_chain_progress": pred.kill_chain_progress,
            "time_to_critical_sec": ttc,
            "is_deviating": pred.is_deviating,
            "prediction_accuracy": pred.prediction_accuracy,
            "preemptive_action": self._suggest_preemptive(result["predicted_next"]),
        }

    def _predict_next(self, ip: str, current: str) -> dict:
        """Predict next action using Markov transition probabilities."""
        trans = self.transitions.get(current, {})
        total = sum(trans.values())

        if total < self.MIN_OBSERVATIONS:
            # Fall back to global patterns
            all_trans = defaultdict(int)
            for src_trans in self.transitions.values():
                for dst, cnt in src_trans.items():
                    all_trans[dst] += cnt
            trans = all_trans
            total = sum(trans.values())

        if total == 0:
            return {
                "predicted_next": "RECON",
                "confidence": 0.0,
                "alternatives": {},
            }

        # Calculate probabilities
        probs = {
            intent: round(count / total, 3)
            for intent, count in sorted(
                trans.items(), key=lambda x: -x[1]
            )
        }

        predicted = max(probs, key=probs.get) if probs else "RECON"
        confidence = probs.get(predicted, 0.0)

        return {
            "predicted_next": predicted,
            "confidence": confidence,
            "alternatives": dict(list(probs.items())[:5]),
        }

    def _estimate_time_to_critical(self, ip: str, current: str) -> float:
        """
        Estimate time until attacker reaches a critical action.
        Uses average transition timing and shortest path to critical intent.
        """
        current_stage = KILL_CHAIN.get(current, {}).get("stage", 0)

        if current in self.CRITICAL_INTENTS:
            return 0.0  # Already critical

        # Average time between actions for this attacker
        timings = self.timing.get(ip, [])
        avg_interval = sum(timings) / len(timings) if timings else 30

        # Estimate steps to critical (using kill chain progression)
        max_stage = max(
            v["stage"] for v in KILL_CHAIN.values()
            if v["stage"] > current_stage
        ) if current_stage < 7 else 7

        steps_remaining = max_stage - current_stage
        if steps_remaining <= 0:
            return 0.0

        # Check if attacker shows signs of fast progression
        seq = self.sequences.get(ip, [])
        if len(seq) >= 3:
            stages = [KILL_CHAIN.get(s, {}).get("stage", 0) for s in seq[-5:]]
            if all(stages[i] <= stages[i+1] for i in range(len(stages)-1)):
                # Monotonically increasing = fast escalation
                avg_interval *= 0.5

        estimated_seconds = round(steps_remaining * avg_interval, 1)
        return max(0, estimated_seconds)

    def _calc_progress(self, ip: str) -> float:
        """Calculate kill chain progress percentage."""
        seq = self.sequences.get(ip, [])
        if not seq:
            return 0.0

        max_stage = max(
            KILL_CHAIN.get(intent, {}).get("stage", 0) for intent in seq
        )
        total_stages = max(v["stage"] for v in KILL_CHAIN.values())
        return round(max_stage / total_stages * 100, 1)

    @staticmethod
    def _suggest_preemptive(predicted_next: str) -> str:
        """Suggest a preemptive honeypot response based on prediction."""
        suggestions = {
            "RECON": "Serve extended fake telemetry to encourage engagement",
            "CONTROL": "Prepare fake mode-change acknowledgement",
            "HIJACK": "Switch to WASTING strategy, inject GPS drift",
            "GPS_SPOOF": "Pre-position canary coordinates, enable GPS trap",
            "MISSION_INJECT": "Prepare fake mission acceptance with canary waypoints",
            "CONFIG_ATTACK": "Serve infinite fake parameters via tarpit",
            "SENSOR_SPOOF": "Acknowledge sensor data, serve fake feedback",
            "DOS_FLOOD": "Activate rate limiting, prepare degraded-mode responses",
        }
        return suggestions.get(predicted_next, "Monitor and record")

    # ── Dashboard Data ──

    def get_all_predictions(self) -> List[dict]:
        """Get predictions for all active attackers."""
        return [asdict(p) for p in sorted(
            self.predictions.values(),
            key=lambda p: p.kill_chain_progress,
            reverse=True,
        )]

    def get_prediction(self, ip: str) -> Optional[dict]:
        """Get prediction for a specific attacker."""
        if ip in self.predictions:
            return asdict(self.predictions[ip])
        return None

    def get_transition_matrix(self) -> dict:
        """Get global transition matrix for visualization."""
        intents = sorted(set(
            list(self.transitions.keys()) +
            [k for v in self.transitions.values() for k in v.keys()]
        ))

        matrix = {}
        for src in intents:
            total = sum(self.transitions[src].values())
            matrix[src] = {}
            for dst in intents:
                count = self.transitions[src].get(dst, 0)
                matrix[src][dst] = round(count / total, 3) if total else 0

        return {"intents": intents, "matrix": matrix}

    def get_stats(self) -> dict:
        """Overall prediction engine statistics."""
        total_pred = sum(p.total_predictions for p in self.predictions.values())
        correct = sum(p.correct_predictions for p in self.predictions.values())
        deviating = sum(1 for p in self.predictions.values() if p.is_deviating)
        critical = sum(
            1 for p in self.predictions.values()
            if p.time_to_critical_sec >= 0 and p.time_to_critical_sec < 60
        )

        return {
            "total_predictions": total_pred,
            "correct_predictions": correct,
            "overall_accuracy": round(correct / total_pred, 3) if total_pred else 0,
            "active_attackers": len(self.predictions),
            "deviating_attackers": deviating,
            "near_critical": critical,
            "transition_pairs": sum(
                len(v) for v in self.transitions.values()
            ),
        }


if __name__ == "__main__":
    print("🔮 Threat Predictor — Test")

    predictor = ThreatPredictor()

    # Simulate an attack progression
    attacker = "10.0.0.1"
    sequence = ["RECON", "RECON", "RECON", "CONTROL", "CONTROL",
                "HIJACK", "GPS_SPOOF"]

    for intent in sequence:
        result = predictor.observe(attacker, intent)
        print(f"  {intent}: predicted_next={result['predicted_next']} "
              f"(conf={result['confidence']:.0%}), "
              f"progress={result['kill_chain_progress']:.0f}%, "
              f"TTC={result['time_to_critical_sec']:.0f}s")

    # Another attacker with different pattern
    for intent in ["RECON", "DOS_FLOOD", "DOS_FLOOD", "RECON", "RECON"]:
        predictor.observe("10.0.0.2", intent)

    stats = predictor.get_stats()
    print(f"\n  Accuracy: {stats['overall_accuracy']:.0%}")
    print(f"  Active: {stats['active_attackers']}")
    print(f"  Near critical: {stats['near_critical']}")

    matrix = predictor.get_transition_matrix()
    print(f"  Transition pairs: {len(matrix['intents'])} intents")
