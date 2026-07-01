#!/usr/bin/env python3
"""
Adaptive Response Timing — Anti-Fingerprint Timing System.

Dynamically adjusts response latency distributions based on:
    1. Attacker sophistication (from EntropyScorer)
    2. Protocol-appropriate timing (MAVLink GCS ≈ 50-200ms typical)
    3. Per-intent timing profiles (GPS responses are faster than mission acks)

The goal is to make the honeypot indistinguishable from a real drone by:
    - Matching real MAVLink autopilot timing characteristics
    - Adding sophistication-aware jitter (more realistic for skilled attackers)
    - Simulating processing load variation under attack

Novel contribution: No honeypot dynamically adjusts response timing based
on real-time attacker sophistication classification. This prevents timing
side-channel fingerprinting by advanced adversaries.

Usage:
    timer = AdaptiveTimer()
    timer.set_attacker_level("10.0.0.1", "ADVANCED")
    delay = timer.compute_delay(intent="GPS_SPOOF", state="CONFUSED")
"""

from __future__ import annotations

import math
import random
import time
from typing import Dict, Optional, Tuple


# ── Timing profiles per intent (modeled from real ArduPilot telemetry) ───
# Values are (base_ms, jitter_range_ms) — measured from ArduPilot SITL logs

INTENT_TIMING: Dict[str, Tuple[float, float]] = {
    "RECON":           (12.3,  4.1),    # Heartbeat/status: fast, consistent
    "CONTROL":         (48.7,  18.2),   # Command processing: moderate
    "HIJACK":          (55.2,  22.5),   # SET_POSITION/ATTITUDE: heavier processing
    "GPS_SPOOF":       (22.1,  8.3),    # GPS responses: quick sensor read
    "MISSION_INJECT":  (82.4,  31.0),   # Mission processing: slower
    "CONFIG_ATTACK":   (51.3,  19.8),   # Parameter writes: moderate
    "SENSOR_SPOOF":    (18.0,  6.0),    # Sensor responses: fast
    "DOS_FLOOD":       (5.0,   3.0),    # Under flood: minimal processing
    "UNKNOWN":         (30.0,  12.0),   # Default: moderate
}

# ── Sophistication multipliers ───────────────────────────────
# Script kiddies get wider jitter (they won't notice)
# APTs get tighter, more realistic timing (harder to fingerprint)

SKILL_MULTIPLIERS: Dict[str, Dict[str, float]] = {
    "SCRIPT_KIDDIE": {
        "base_mult": 1.0,       # Normal base delay
        "jitter_mult": 2.0,     # Wide jitter (sloppy is OK)
        "load_sim": 0.0,        # No load simulation
    },
    "INTERMEDIATE": {
        "base_mult": 1.0,
        "jitter_mult": 1.2,     # Moderate jitter
        "load_sim": 0.3,        # Some load variation
    },
    "ADVANCED": {
        "base_mult": 1.0,
        "jitter_mult": 0.8,     # Tight jitter (realistic)
        "load_sim": 0.6,        # Realistic load patterns
    },
    "APT": {
        "base_mult": 1.0,
        "jitter_mult": 0.5,     # Minimal jitter (real HW-like)
        "load_sim": 0.9,        # Full load simulation
    },
    "UNKNOWN": {
        "base_mult": 1.0,
        "jitter_mult": 1.0,
        "load_sim": 0.3,
    },
}

# ── State-based penalties (simulate processing degradation) ──

STATE_PENALTIES: Dict[str, float] = {
    "NORMAL":     1.0,   # No penalty
    "WEAK":       1.1,   # 10% slower (slight degradation)
    "CONFUSED":   1.4,   # 40% slower (confused autopilot)
    "PARTIAL":    1.8,   # 80% slower (partial failure)
    "DEFENSIVE":  1.2,   # 20% slower (defensive mode)
    "CRASHED":    0.0,   # No response
    "REBOOTING":  3.0,   # Very slow (rebooting)
}


class AdaptiveTimer:
    """
    Computes protocol-realistic response delays that adapt to attacker skill.

    The timer models a real drone autopilot's response characteristics:
    - Base processing time varies by message type
    - Jitter width adapts to attacker sophistication
    - Simulated CPU load increases under sustained attack
    - State-based degradation models damaged drone behavior
    """

    def __init__(self, rng: Optional[random.Random] = None) -> None:
        self.rng = rng or random.Random()
        self._attacker_levels: Dict[str, str] = {}
        self._command_counts: Dict[str, int] = {}  # For load simulation

    def set_attacker_level(self, attacker_id: str, level: str) -> None:
        """Set sophistication level for an attacker (from EntropyScorer)."""
        self._attacker_levels[attacker_id] = level

    def get_attacker_level(self, attacker_id: str) -> str:
        return self._attacker_levels.get(attacker_id, "UNKNOWN")

    def compute_delay(
        self,
        intent: str = "UNKNOWN",
        state: str = "NORMAL",
        attacker_id: Optional[str] = None,
    ) -> float:
        """Compute adaptive response delay in seconds.

        Args:
            intent: Classified intent of the incoming message.
            state: Current FSM state of the honeypot sandbox.
            attacker_id: Attacker identifier (for skill-based adaptation).

        Returns:
            Delay in seconds (0.0 if state is CRASHED).
        """
        # No response for crashed state
        state_mult = STATE_PENALTIES.get(state, 1.0)
        if state_mult == 0.0:
            return 0.0

        # Get base timing for this intent
        base_ms, jitter_range = INTENT_TIMING.get(intent, INTENT_TIMING["UNKNOWN"])

        # Get skill-based multipliers
        level = self.get_attacker_level(attacker_id) if attacker_id else "UNKNOWN"
        skill = SKILL_MULTIPLIERS.get(level, SKILL_MULTIPLIERS["UNKNOWN"])

        # Compute delay components
        base = base_ms * skill["base_mult"] * state_mult
        jitter = self.rng.gauss(0, jitter_range * skill["jitter_mult"])

        # Simulate CPU load (more commands → higher latency)
        load_factor = 1.0
        if attacker_id and skill["load_sim"] > 0:
            cmd_count = self._command_counts.get(attacker_id, 0)
            self._command_counts[attacker_id] = cmd_count + 1
            # Logarithmic load curve: load increases slowly with command count
            load_factor = 1.0 + skill["load_sim"] * math.log1p(cmd_count / 50)

        total_ms = max(1.0, (base + jitter) * load_factor)
        return total_ms / 1000.0  # Convert to seconds

    def apply_delay(
        self,
        intent: str = "UNKNOWN",
        state: str = "NORMAL",
        attacker_id: Optional[str] = None,
    ) -> float:
        """Compute and apply the adaptive delay (blocking).

        Returns:
            The actual delay applied in seconds.
        """
        delay = self.compute_delay(intent, state, attacker_id)
        if delay > 0:
            time.sleep(delay)
        return delay

    def get_timing_stats(self, attacker_id: str) -> Dict[str, float]:
        """Get timing statistics for an attacker."""
        level = self.get_attacker_level(attacker_id)
        cmd_count = self._command_counts.get(attacker_id, 0)
        skill = SKILL_MULTIPLIERS.get(level, SKILL_MULTIPLIERS["UNKNOWN"])
        load_factor = 1.0 + skill["load_sim"] * math.log1p(cmd_count / 50)

        return {
            "level": level,
            "commands_seen": cmd_count,
            "load_factor": round(load_factor, 3),
            "jitter_multiplier": skill["jitter_mult"],
        }


if __name__ == "__main__":
    print("🧪 Adaptive Timer — Demo\n")
    timer = AdaptiveTimer(rng=random.Random(42))

    for level in ["SCRIPT_KIDDIE", "INTERMEDIATE", "ADVANCED", "APT"]:
        timer.set_attacker_level(level, level)
        delays = []
        for intent in ["RECON", "GPS_SPOOF", "HIJACK", "CONTROL"]:
            d = timer.compute_delay(intent, "NORMAL", level)
            delays.append(d * 1000)  # Back to ms for display

        avg = sum(delays) / len(delays)
        print(f"  {level:16}: avg={avg:6.1f}ms  "
              f"range=[{min(delays):5.1f}, {max(delays):5.1f}]ms  "
              f"jitter_mult={SKILL_MULTIPLIERS[level]['jitter_mult']}")

    print()
    print("  State degradation (RECON intent, INTERMEDIATE attacker):")
    timer.set_attacker_level("test", "INTERMEDIATE")
    for state in ["NORMAL", "WEAK", "CONFUSED", "PARTIAL", "REBOOTING"]:
        d = timer.compute_delay("RECON", state, "test") * 1000
        penalty = STATE_PENALTIES[state]
        print(f"    {state:12}: {d:6.1f}ms (×{penalty})")
