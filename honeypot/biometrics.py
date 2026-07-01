#!/usr/bin/env python3
"""
MAVLink Honeypot — Behavioral Biometrics Engine
Identifies individual human operators behind attacks through
interaction timing patterns, command vocabulary, and session rhythm.
"""

import os
import json
import math
import hashlib
import time
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field


BIOMETRICS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'biometrics.json'
)


@dataclass
class OperatorProfile:
    """Biometric profile for an individual human operator."""
    operator_id: str                 # Unique biometric ID
    confidence: float = 0.0          # 0-1 confidence this is a real individual
    associated_ips: List[str] = field(default_factory=list)

    # Timing biometrics
    avg_inter_cmd_ms: float = 0      # Average time between commands
    inter_cmd_variance: float = 0    # Variance in command timing
    timing_signature: List[float] = field(default_factory=list)  # Timing pattern
    pause_frequency: float = 0       # How often they pause > 3s
    burst_frequency: float = 0       # How often they send rapid bursts

    # Command vocabulary
    preferred_commands: Dict[str, int] = field(default_factory=dict)
    command_diversity: float = 0.0   # Shannon entropy of command usage
    unique_commands: int = 0
    total_commands: int = 0

    # Session rhythm
    avg_session_duration_sec: float = 0
    session_count: int = 0
    preferred_hours: List[int] = field(default_factory=list)  # Hour-of-day pattern
    avg_cmds_per_session: float = 0

    # Transition patterns
    transition_matrix: Dict[str, Dict[str, int]] = field(default_factory=dict)
    favorite_transitions: List[str] = field(default_factory=list)

    # Metadata
    first_seen: str = ""
    last_seen: str = ""
    is_automated: bool = False       # Suspected bot vs human


class BiometricsEngine:
    """
    Behavioral biometrics analysis to identify individual operators.

    Uses multiple signals:
    1. Inter-keystroke timing — unique rhythm between commands
    2. Command vocabulary — which commands each person prefers
    3. Session rhythm — time-of-day patterns, session durations
    4. Transition patterns — how they sequence attack phases
    5. Pause analysis — thinking pauses vs. automated responses
    """

    # Similarity thresholds
    TIMING_SIMILARITY_THRESHOLD = 0.75   # Match if > 75% timing similarity
    VOCAB_SIMILARITY_THRESHOLD = 0.70
    OVERALL_MATCH_THRESHOLD = 0.65
    MIN_COMMANDS_FOR_PROFILE = 8         # Need at least 8 commands
    PAUSE_THRESHOLD_MS = 3000            # > 3s = thinking pause
    BURST_THRESHOLD_MS = 200             # < 200ms = automated burst

    def __init__(self):
        self.operators: Dict[str, OperatorProfile] = {}
        self.ip_to_operator: Dict[str, str] = {}
        self.active_sessions: Dict[str, dict] = {}  # session tracking
        self._load()

    def _load(self):
        if os.path.exists(BIOMETRICS_FILE):
            try:
                with open(BIOMETRICS_FILE, 'r') as f:
                    data = json.load(f)
                for oid, odata in data.get("operators", {}).items():
                    self.operators[oid] = OperatorProfile(**odata)
                self.ip_to_operator = data.get("ip_mapping", {})
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(BIOMETRICS_FILE), exist_ok=True)
            with open(BIOMETRICS_FILE, 'w') as f:
                json.dump({
                    "operators": {k: asdict(v) for k, v in self.operators.items()},
                    "ip_mapping": self.ip_to_operator,
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    # ── Session Management ──

    def on_session_start(self, session_id: str, ip: str):
        """Begin biometric tracking for a new session."""
        self.active_sessions[session_id] = {
            "ip": ip,
            "start_time": time.time(),
            "cmd_timestamps": [],
            "commands": [],
            "hour": datetime.now().hour,
        }

    def on_command(self, session_id: str, ip: str, intent: str,
                   msg_name: str = ""):
        """Record a command for biometric analysis."""
        now = time.time()

        if session_id not in self.active_sessions:
            self.on_session_start(session_id, ip)

        session = self.active_sessions[session_id]
        session["cmd_timestamps"].append(now)
        session["commands"].append(intent)

    def on_session_end(self, session_id: str, ip: str) -> Optional[dict]:
        """
        End a session and update/create operator profile.
        Returns match result if a known operator is identified.
        """
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions.pop(session_id)
        timestamps = session["cmd_timestamps"]
        commands = session["commands"]

        if len(commands) < self.MIN_COMMANDS_FOR_PROFILE:
            return None

        # Extract features
        features = self._extract_features(timestamps, commands, session)

        # Try to match against existing operators
        match = self._find_matching_operator(features, ip)

        if match:
            # Update existing operator
            self._update_operator(match["operator_id"], features, ip)
            result = {
                "matched": True,
                "operator_id": match["operator_id"],
                "similarity": match["similarity"],
                "cross_ip": ip not in self.operators[match["operator_id"]].associated_ips,
            }
        else:
            # Create new operator profile
            op_id = self._create_operator(features, ip)
            result = {
                "matched": False,
                "operator_id": op_id,
                "similarity": 1.0,
                "cross_ip": False,
            }

        self.ip_to_operator[ip] = result["operator_id"]
        self._save()
        return result

    # ── Feature Extraction ──

    def _extract_features(self, timestamps: List[float],
                          commands: List[str], session: dict) -> dict:
        """Extract biometric features from session data."""
        # Inter-command timing
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]) * 1000  # ms
            intervals.append(delta)

        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        variance = (sum((x - avg_interval) ** 2 for x in intervals) /
                    len(intervals)) if len(intervals) > 1 else 0

        # Pause and burst analysis
        pauses = sum(1 for i in intervals if i > self.PAUSE_THRESHOLD_MS)
        bursts = sum(1 for i in intervals if i < self.BURST_THRESHOLD_MS)
        pause_freq = pauses / len(intervals) if intervals else 0
        burst_freq = bursts / len(intervals) if intervals else 0

        # Command vocabulary
        cmd_counts = Counter(commands)
        total_cmds = len(commands)
        unique_cmds = len(cmd_counts)
        diversity = self._shannon_entropy(list(cmd_counts.values()))

        # Transition matrix
        transitions = defaultdict(lambda: defaultdict(int))
        for i in range(len(commands) - 1):
            transitions[commands[i]][commands[i+1]] += 1

        # Session info
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

        # Timing signature (normalized intervals)
        max_interval = max(intervals) if intervals else 1
        timing_sig = [round(i / max_interval, 2) for i in intervals[:20]]

        return {
            "avg_interval_ms": round(avg_interval, 1),
            "interval_variance": round(variance, 1),
            "timing_signature": timing_sig,
            "pause_frequency": round(pause_freq, 3),
            "burst_frequency": round(burst_freq, 3),
            "command_counts": dict(cmd_counts),
            "command_diversity": round(diversity, 3),
            "unique_commands": unique_cmds,
            "total_commands": total_cmds,
            "transitions": {k: dict(v) for k, v in transitions.items()},
            "session_duration_sec": round(duration, 1),
            "hour": session.get("hour", 0),
            "is_automated": burst_freq > 0.7 and pause_freq < 0.05,
        }

    @staticmethod
    def _shannon_entropy(values: list) -> float:
        """Shannon entropy of a frequency distribution."""
        total = sum(values)
        if total == 0:
            return 0.0
        entropy = 0.0
        for v in values:
            if v > 0:
                p = v / total
                entropy -= p * math.log2(p)
        return entropy

    # ── Operator Matching ──

    def _find_matching_operator(self, features: dict,
                                ip: str) -> Optional[dict]:
        """Find a matching operator based on behavioral similarity."""
        best_match = None
        best_score = 0.0

        for op_id, operator in self.operators.items():
            score = self._calculate_similarity(features, operator)
            if score > best_score:
                best_score = score
                best_match = {"operator_id": op_id, "similarity": round(score, 3)}

        if best_match and best_score >= self.OVERALL_MATCH_THRESHOLD:
            return best_match
        return None

    def _calculate_similarity(self, features: dict,
                              operator: OperatorProfile) -> float:
        """
        Calculate behavioral similarity between features and an operator profile.
        Weighted combination of timing, vocabulary, and session features.
        """
        score = 0.0
        weights_total = 0.0

        # 1. Timing similarity (weight: 0.35)
        timing_score = self._timing_similarity(
            features["avg_interval_ms"],
            features["interval_variance"],
            operator.avg_inter_cmd_ms,
            operator.inter_cmd_variance,
        )
        score += timing_score * 0.35
        weights_total += 0.35

        # 2. Vocabulary similarity (weight: 0.30)
        vocab_score = self._vocabulary_similarity(
            features["command_counts"],
            operator.preferred_commands,
        )
        score += vocab_score * 0.30
        weights_total += 0.30

        # 3. Pause/burst pattern similarity (weight: 0.15)
        pause_diff = abs(features["pause_frequency"] - operator.pause_frequency)
        burst_diff = abs(features["burst_frequency"] - operator.burst_frequency)
        pattern_score = max(0, 1.0 - pause_diff - burst_diff)
        score += pattern_score * 0.15
        weights_total += 0.15

        # 4. Session rhythm similarity (weight: 0.10)
        if operator.preferred_hours:
            hour_match = 1.0 if features["hour"] in operator.preferred_hours else 0.3
            score += hour_match * 0.10
            weights_total += 0.10

        # 5. Automation flag match (weight: 0.10)
        auto_match = 1.0 if features["is_automated"] == operator.is_automated else 0.2
        score += auto_match * 0.10
        weights_total += 0.10

        return score / weights_total if weights_total > 0 else 0

    @staticmethod
    def _timing_similarity(avg1, var1, avg2, var2) -> float:
        """Compare timing distributions using normalized distance."""
        if avg1 == 0 or avg2 == 0:
            return 0.0

        # Ratio similarity (1.0 = identical)
        ratio = min(avg1, avg2) / max(avg1, avg2)

        # Variance similarity
        max_var = max(var1, var2, 1)
        var_ratio = 1.0 - abs(var1 - var2) / max_var

        return (ratio * 0.6 + max(0, var_ratio) * 0.4)

    @staticmethod
    def _vocabulary_similarity(counts1: dict, counts2: dict) -> float:
        """Cosine similarity between command frequency vectors."""
        all_cmds = set(list(counts1.keys()) + list(counts2.keys()))
        if not all_cmds:
            return 0.0

        dot = sum(counts1.get(c, 0) * counts2.get(c, 0) for c in all_cmds)
        mag1 = math.sqrt(sum(v**2 for v in counts1.values()))
        mag2 = math.sqrt(sum(v**2 for v in counts2.values()))

        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    # ── Profile Management ──

    def _create_operator(self, features: dict, ip: str) -> str:
        """Create a new operator profile from features."""
        op_id = f"OP-{hashlib.md5(f'{ip}:{time.time()}'.encode()).hexdigest()[:8].upper()}"

        operator = OperatorProfile(
            operator_id=op_id,
            confidence=0.3,
            associated_ips=[ip],
            avg_inter_cmd_ms=features["avg_interval_ms"],
            inter_cmd_variance=features["interval_variance"],
            timing_signature=features["timing_signature"],
            pause_frequency=features["pause_frequency"],
            burst_frequency=features["burst_frequency"],
            preferred_commands=features["command_counts"],
            command_diversity=features["command_diversity"],
            unique_commands=features["unique_commands"],
            total_commands=features["total_commands"],
            avg_session_duration_sec=features["session_duration_sec"],
            session_count=1,
            preferred_hours=[features["hour"]],
            avg_cmds_per_session=features["total_commands"],
            transition_matrix=features["transitions"],
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            is_automated=features["is_automated"],
        )

        self.operators[op_id] = operator
        return op_id

    def _update_operator(self, op_id: str, features: dict, ip: str):
        """Update existing operator profile with new session data."""
        op = self.operators[op_id]
        op.session_count += 1
        op.last_seen = datetime.now().isoformat()

        if ip not in op.associated_ips:
            op.associated_ips.append(ip)

        # Rolling average for timing
        n = op.session_count
        op.avg_inter_cmd_ms = round(
            (op.avg_inter_cmd_ms * (n-1) + features["avg_interval_ms"]) / n, 1
        )
        op.inter_cmd_variance = round(
            (op.inter_cmd_variance * (n-1) + features["interval_variance"]) / n, 1
        )
        op.pause_frequency = round(
            (op.pause_frequency * (n-1) + features["pause_frequency"]) / n, 3
        )
        op.burst_frequency = round(
            (op.burst_frequency * (n-1) + features["burst_frequency"]) / n, 3
        )

        # Merge command vocabulary
        for cmd, count in features["command_counts"].items():
            op.preferred_commands[cmd] = op.preferred_commands.get(cmd, 0) + count
        op.total_commands += features["total_commands"]
        op.unique_commands = len(op.preferred_commands)

        # Update session rhythm
        hour = features["hour"]
        if hour not in op.preferred_hours:
            op.preferred_hours.append(hour)
        op.avg_session_duration_sec = round(
            (op.avg_session_duration_sec * (n-1) + features["session_duration_sec"]) / n, 1
        )
        op.avg_cmds_per_session = round(op.total_commands / n, 1)

        # Increase confidence with more data
        op.confidence = min(0.95, 0.3 + op.session_count * 0.1 +
                           len(op.associated_ips) * 0.15)

    # ── Dashboard Data ──

    def get_all_operators(self) -> List[dict]:
        """Get all operator profiles."""
        return [asdict(op) for op in sorted(
            self.operators.values(),
            key=lambda o: o.session_count,
            reverse=True,
        )]

    def get_cross_ip_links(self) -> List[dict]:
        """Get operators linked across multiple IPs."""
        return [
            {
                "operator_id": op.operator_id,
                "ips": op.associated_ips,
                "ip_count": len(op.associated_ips),
                "confidence": op.confidence,
                "sessions": op.session_count,
                "is_automated": op.is_automated,
            }
            for op in self.operators.values()
            if len(op.associated_ips) > 1
        ]

    def get_stats(self) -> dict:
        """Biometric engine statistics."""
        total = len(self.operators)
        multi_ip = sum(1 for o in self.operators.values() if len(o.associated_ips) > 1)
        automated = sum(1 for o in self.operators.values() if o.is_automated)

        return {
            "total_operators": total,
            "multi_ip_operators": multi_ip,
            "automated_operators": automated,
            "human_operators": total - automated,
            "total_ips_tracked": len(self.ip_to_operator),
            "avg_confidence": round(
                sum(o.confidence for o in self.operators.values()) / total, 2
            ) if total else 0,
        }


if __name__ == "__main__":
    print("🧬 Behavioral Biometrics — Test")

    engine = BiometricsEngine()

    # Simulate a session from attacker 1
    engine.on_session_start("sess1", "10.0.0.1")
    commands = ["RECON", "RECON", "CONTROL", "RECON", "HIJACK",
                "GPS_SPOOF", "CONTROL", "HIJACK", "CONTROL", "RECON"]
    for i, cmd in enumerate(commands):
        time.sleep(0.05 + 0.02 * (i % 3))  # Variable timing
        engine.on_command("sess1", "10.0.0.1", cmd)

    result1 = engine.on_session_end("sess1", "10.0.0.1")
    print(f"  Session 1: operator={result1['operator_id']}, matched={result1['matched']}")

    # Simulate same person from different IP (similar pattern)
    engine.on_session_start("sess2", "10.0.0.99")
    for i, cmd in enumerate(commands):
        time.sleep(0.05 + 0.02 * (i % 3))
        engine.on_command("sess2", "10.0.0.99", cmd)

    result2 = engine.on_session_end("sess2", "10.0.0.99")
    print(f"  Session 2: operator={result2['operator_id']}, matched={result2['matched']}, "
          f"cross_ip={result2['cross_ip']}, similarity={result2['similarity']}")

    stats = engine.get_stats()
    print(f"\n  Operators: {stats['total_operators']}")
    print(f"  Multi-IP: {stats['multi_ip_operators']}")

    links = engine.get_cross_ip_links()
    for link in links:
        print(f"  Cross-IP link: {link['operator_id']} → {link['ips']}")
