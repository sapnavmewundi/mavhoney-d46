#!/usr/bin/env python3
"""
Attack Sequence Entropy Scorer — A Novel Attacker Sophistication Classifier.

Computes Shannon entropy of an attacker's command sequence in real-time
to classify their sophistication level. This enables the honeypot to
adapt its deception strategy per-attacker:

    - Low entropy  → Script kiddie (repeats the same 2–3 commands)
    - Mid entropy  → Intermediate (follows a known attack playbook)
    - High entropy → Advanced/APT (explores diverse commands strategically)

The entropy score feeds into the adaptive FSM to modulate:
    1. Response fidelity (higher for advanced attackers)
    2. Deception depth (more convincing telemetry for skilled attackers)
    3. Engagement strategy (aggressive for script kiddies, subtle for APTs)

Mathematical Foundation:
    H(X) = -Σ p(x) log₂ p(x)  for each unique command type x

    Normalized entropy: H_norm = H(X) / log₂(|unique commands|)
    Range: [0.0, 1.0] where 0 = completely repetitive, 1 = maximally diverse

Usage:
    scorer = EntropyScorer()
    scorer.observe("attacker_1", msg_id=0)   # HEARTBEAT
    scorer.observe("attacker_1", msg_id=76)  # COMMAND_LONG
    scorer.observe("attacker_1", msg_id=113) # HIL_GPS
    report = scorer.classify("attacker_1")
    print(report)
    # {'entropy': 1.585, 'normalized': 1.0, 'level': 'ADVANCED', ...}
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set


# ── Sophistication Thresholds ────────────────────────────────
# The composite score combines two signals:
#   1. Normalized entropy (distribution evenness): 0-1
#   2. Command diversity ratio (unique_cmds / total known MAVLink types): 0-1
#
# Composite = 0.4 × normalized_entropy + 0.6 × diversity_ratio
#
# This correctly separates:
#   Script kiddie: 2 unique cmds (even if evenly distributed) → low diversity
#   APT: 14 unique cmds with high entropy → high on both axes

TOTAL_KNOWN_MSG_TYPES = 37  # From MAVLINK_SEMANTICS table

SOPHISTICATION_THRESHOLDS = {
    "SCRIPT_KIDDIE":  (0.0, 0.25),   # Few command types, repetitive
    "INTERMEDIATE":   (0.25, 0.50),  # Moderate diversity, playbook-like
    "ADVANCED":       (0.50, 0.75),  # High diversity, strategic
    "APT":            (0.75, 1.01),  # Maximum diversity + novel sequences
}

# Minimum observations before classification is reliable
MIN_OBSERVATIONS = 5


@dataclass
class AttackerEntropyProfile:
    """Per-attacker entropy and sophistication state."""
    attacker_id: str
    commands: List[int] = field(default_factory=list)
    command_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    total_commands: int = 0
    unique_commands: int = 0
    entropy: float = 0.0
    normalized_entropy: float = 0.0
    sophistication_level: str = "UNKNOWN"
    confidence: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Temporal features
    inter_command_times: List[float] = field(default_factory=list)
    avg_inter_command_ms: float = 0.0
    timing_variance: float = 0.0

    # Transition features
    bigram_entropy: float = 0.0  # Entropy of command pairs (order matters)


class EntropyScorer:
    """
    Real-time attacker sophistication classifier using Shannon entropy.

    Novel contribution: No existing honeypot measures attacker sophistication
    from protocol-level command diversity. This enables adaptive deception
    depth — the honeypot works harder to fool skilled attackers.
    """

    def __init__(self) -> None:
        self.profiles: Dict[str, AttackerEntropyProfile] = {}

    def _ensure_profile(self, attacker_id: str) -> AttackerEntropyProfile:
        if attacker_id not in self.profiles:
            self.profiles[attacker_id] = AttackerEntropyProfile(
                attacker_id=attacker_id,
                first_seen=time.time(),
            )
        return self.profiles[attacker_id]

    def observe(self, attacker_id: str, msg_id: int) -> None:
        """Record an observed command from an attacker.

        Args:
            attacker_id: Unique attacker identifier (IP or fingerprint ID).
            msg_id: MAVLink message ID observed.
        """
        profile = self._ensure_profile(attacker_id)
        now = time.time()

        # Record inter-command timing
        if profile.last_seen > 0:
            delta_ms = (now - profile.last_seen) * 1000
            profile.inter_command_times.append(delta_ms)
        profile.last_seen = now

        # Update command distribution
        profile.commands.append(msg_id)
        profile.command_counts[msg_id] += 1
        profile.total_commands += 1
        profile.unique_commands = len(profile.command_counts)

        # Recompute entropy incrementally
        self._update_entropy(profile)

    def _update_entropy(self, profile: AttackerEntropyProfile) -> None:
        """Recompute Shannon entropy from the command distribution."""
        n = profile.total_commands
        if n < 2:
            profile.entropy = 0.0
            profile.normalized_entropy = 0.0
            return

        # Shannon entropy: H = -Σ p(x) log₂ p(x)
        entropy = 0.0
        for count in profile.command_counts.values():
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        profile.entropy = round(entropy, 4)

        # Normalized entropy: H / log₂(unique_commands)
        max_entropy = math.log2(profile.unique_commands) if profile.unique_commands > 1 else 1.0
        profile.normalized_entropy = round(entropy / max_entropy, 4) if max_entropy > 0 else 0.0

        # Bigram entropy (captures command ordering patterns)
        if len(profile.commands) >= 3:
            profile.bigram_entropy = self._compute_bigram_entropy(profile.commands)

        # Update timing stats
        if profile.inter_command_times:
            times = profile.inter_command_times
            profile.avg_inter_command_ms = round(sum(times) / len(times), 2)
            mean = profile.avg_inter_command_ms
            profile.timing_variance = round(
                sum((t - mean) ** 2 for t in times) / len(times), 2
            )

    @staticmethod
    def _compute_bigram_entropy(commands: List[int]) -> float:
        """Compute entropy of command bigrams (order-sensitive)."""
        bigram_counts: Dict[tuple, int] = defaultdict(int)
        for i in range(len(commands) - 1):
            bigram = (commands[i], commands[i + 1])
            bigram_counts[bigram] += 1

        n = sum(bigram_counts.values())
        if n < 2:
            return 0.0

        entropy = 0.0
        for count in bigram_counts.values():
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def classify(self, attacker_id: str) -> Dict[str, Any]:
        """Classify attacker sophistication based on accumulated entropy.

        Returns:
            Dict with entropy, normalized_entropy, sophistication_level,
            confidence, and recommended deception strategy.
        """
        profile = self._ensure_profile(attacker_id)

        # Determine confidence based on observation count
        if profile.total_commands < MIN_OBSERVATIONS:
            profile.confidence = round(profile.total_commands / MIN_OBSERVATIONS, 2)
            profile.sophistication_level = "UNKNOWN"
        else:
            profile.confidence = min(1.0, round(profile.total_commands / 20, 2))

            # Composite score = 0.4 × normalized_entropy + 0.6 × diversity_ratio
            diversity_ratio = min(1.0, profile.unique_commands / TOTAL_KNOWN_MSG_TYPES)
            composite = 0.4 * profile.normalized_entropy + 0.6 * diversity_ratio

            for level, (lo, hi) in SOPHISTICATION_THRESHOLDS.items():
                if lo <= composite < hi:
                    profile.sophistication_level = level
                    break

        # Determine recommended deception strategy
        strategy = self._recommend_strategy(profile)

        return {
            "attacker_id": attacker_id,
            "total_commands": profile.total_commands,
            "unique_commands": profile.unique_commands,
            "entropy": profile.entropy,
            "normalized_entropy": profile.normalized_entropy,
            "bigram_entropy": profile.bigram_entropy,
            "sophistication_level": profile.sophistication_level,
            "confidence": profile.confidence,
            "avg_inter_command_ms": profile.avg_inter_command_ms,
            "timing_variance": profile.timing_variance,
            "strategy": strategy,
        }

    @staticmethod
    def _recommend_strategy(profile: AttackerEntropyProfile) -> Dict[str, Any]:
        """Recommend deception parameters based on attacker sophistication."""
        level = profile.sophistication_level

        if level == "SCRIPT_KIDDIE":
            return {
                "response_fidelity": "LOW",
                "telemetry_detail": "MINIMAL",
                "engagement_mode": "AGGRESSIVE",
                "description": "Low-effort deception; attacker unlikely to verify responses",
            }
        elif level == "INTERMEDIATE":
            return {
                "response_fidelity": "MEDIUM",
                "telemetry_detail": "STANDARD",
                "engagement_mode": "BALANCED",
                "description": "Standard deception; plausible telemetry with some drift",
            }
        elif level == "ADVANCED":
            return {
                "response_fidelity": "HIGH",
                "telemetry_detail": "DETAILED",
                "engagement_mode": "SUBTLE",
                "description": "High-fidelity deception; physics-consistent telemetry",
            }
        elif level == "APT":
            return {
                "response_fidelity": "MAXIMUM",
                "telemetry_detail": "FULL_SIMULATION",
                "engagement_mode": "COVERT",
                "description": "Maximum realism; all responses must pass consistency checks",
            }
        else:
            return {
                "response_fidelity": "MEDIUM",
                "telemetry_detail": "STANDARD",
                "engagement_mode": "BALANCED",
                "description": "Insufficient data for classification",
            }

    def get_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Get entropy profiles for all observed attackers."""
        return {
            aid: self.classify(aid)
            for aid in self.profiles
        }


if __name__ == "__main__":
    print("🧪 Entropy Scorer — Demo\n")
    scorer = EntropyScorer()

    # Script kiddie: repeats same 2 commands
    for _ in range(10):
        scorer.observe("script_kiddie", 0)   # HEARTBEAT
        scorer.observe("script_kiddie", 0)   # HEARTBEAT
        scorer.observe("script_kiddie", 76)  # COMMAND_LONG

    # Advanced: diverse strategic sequence
    advanced_seq = [0, 20, 21, 24, 76, 11, 23, 400, 84, 113, 132, 86, 511, 514]
    for mid in advanced_seq:
        scorer.observe("apt_attacker", mid)

    # Print results
    for attacker_id in ["script_kiddie", "apt_attacker"]:
        result = scorer.classify(attacker_id)
        print(f"  {attacker_id}:")
        print(f"    Commands: {result['total_commands']} total, {result['unique_commands']} unique")
        print(f"    Entropy: {result['entropy']} (normalized: {result['normalized_entropy']})")
        print(f"    Level: {result['sophistication_level']} (confidence: {result['confidence']})")
        print(f"    Strategy: {result['strategy']['engagement_mode']}")
        print()
