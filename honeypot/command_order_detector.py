#!/usr/bin/env python3
"""
MAVLink Honeypot — Command Order & Injection Detector
Detects abnormal MAVLink command ordering and high-frequency injection attempts.

Detection methods:
1. Command order validation against expected MAVLink sequences
2. High-frequency burst detection with sliding window
3. Protocol state violation detection
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.logger import get_logger

logger = get_logger("command_order")


# ── Expected MAVLink Command Sequences ──────────────────
# Normal drone interactions follow predictable patterns
EXPECTED_SEQUENCES = {
    'NORMAL_STARTUP': ['HEARTBEAT', 'PARAM_REQUEST_LIST', 'REQUEST_DATA_STREAM'],
    'ARM_SEQUENCE': ['HEARTBEAT', 'SET_MODE', 'COMMAND_LONG'],  # ARM
    'MISSION_UPLOAD': ['MISSION_COUNT', 'MISSION_ITEM', 'MISSION_ACK'],
    'GUIDED_FLIGHT': ['SET_MODE', 'SET_POSITION_TARGET_GLOBAL_INT'],
    'PARAM_CHANGE': ['PARAM_REQUEST_READ', 'PARAM_SET'],
}

# Commands that should NOT appear without prerequisites
PREREQUISITE_MAP = {
    'COMMAND_LONG': {'HEARTBEAT'},     # Must see heartbeat first
    'MISSION_ITEM': {'MISSION_COUNT'}, # Must send count before items
    'SET_POSITION_TARGET_GLOBAL_INT': {'HEARTBEAT', 'SET_MODE'},
    'SET_POSITION_TARGET_LOCAL_NED': {'HEARTBEAT', 'SET_MODE'},
    'PARAM_SET': {'HEARTBEAT'},
}

# High-severity commands that indicate aggressive attack
AGGRESSIVE_COMMANDS = {
    'COMMAND_LONG', 'SET_MODE', 'SET_POSITION_TARGET_GLOBAL_INT',
    'SET_POSITION_TARGET_LOCAL_NED', 'MISSION_ITEM', 'PARAM_SET',
    'SET_HOME_POSITION', 'GPS_INPUT', 'HIL_GPS',
}


@dataclass
class AttackerCommandProfile:
    """Track command ordering per attacker."""
    command_history: List[str] = field(default_factory=list)
    command_timestamps: List[float] = field(default_factory=list)
    seen_commands: set = field(default_factory=set)
    order_violations: int = 0
    burst_violations: int = 0
    total_commands: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


class CommandOrderDetector:
    """
    Detects abnormal MAVLink command ordering and injection attempts.

    Features:
    - Validates commands have required prerequisites
    - Detects high-frequency injection bursts
    - Flags protocol state violations
    - Tracks per-attacker command ordering profiles
    """

    def __init__(
        self,
        burst_window_sec: float = 2.0,
        burst_threshold: int = 20,
        max_history: int = 100,
    ):
        self.burst_window = burst_window_sec
        self.burst_threshold = burst_threshold
        self.max_history = max_history

        # Per-attacker profiles
        self._profiles: Dict[str, AttackerCommandProfile] = defaultdict(
            AttackerCommandProfile
        )

        # Sliding window for burst detection: {ip: deque of timestamps}
        self._burst_windows: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )

        # Detection results
        self._detections: list = []

    def check_command(
        self,
        attacker_ip: str,
        msg_name: str,
        msg_id: int = 0,
    ) -> dict:
        """
        Check a command for ordering violations or injection patterns.

        Returns:
            dict with keys:
                is_anomalous: bool
                anomaly_types: list of str
                severity: int (1-10)
                details: str
        """
        now = time.time()
        profile = self._profiles[attacker_ip]

        if profile.first_seen == 0:
            profile.first_seen = now
        profile.last_seen = now
        profile.total_commands += 1

        anomaly_types = []
        details = []
        severity = 0

        # ── 1. Prerequisite check ──
        if msg_name in PREREQUISITE_MAP:
            required = PREREQUISITE_MAP[msg_name]
            missing = required - profile.seen_commands
            if missing:
                anomaly_types.append('MISSING_PREREQUISITE')
                profile.order_violations += 1
                severity = max(severity, 6)
                details.append(
                    f"{msg_name} sent without prerequisites: "
                    f"{', '.join(sorted(missing))}"
                )

        # ── 2. Burst detection (sliding window) ──
        window = self._burst_windows[attacker_ip]
        window.append(now)

        # Count commands in the burst window
        cutoff = now - self.burst_window
        recent = sum(1 for t in window if t > cutoff)

        if recent >= self.burst_threshold:
            anomaly_types.append('HIGH_FREQUENCY_INJECTION')
            profile.burst_violations += 1
            rate = recent / self.burst_window
            severity = max(severity, 8)
            details.append(
                f"High-frequency burst: {recent} commands in "
                f"{self.burst_window}s ({rate:.0f}/s)"
            )

        # ── 3. Aggressive command without recon ──
        if msg_name in AGGRESSIVE_COMMANDS and profile.total_commands <= 3:
            if 'HEARTBEAT' not in profile.seen_commands:
                anomaly_types.append('AGGRESSIVE_NO_RECON')
                severity = max(severity, 7)
                details.append(
                    f"Aggressive command {msg_name} sent as command "
                    f"#{profile.total_commands} without any recon"
                )

        # ── 4. Rapid command type switching ──
        if len(profile.command_history) >= 5:
            recent_cmds = profile.command_history[-5:]
            unique_recent = len(set(recent_cmds))
            if unique_recent >= 5:
                anomaly_types.append('RAPID_TYPE_SWITCHING')
                severity = max(severity, 5)
                details.append(
                    f"5 different command types in last 5 commands: "
                    f"{', '.join(recent_cmds)}"
                )

        # ── Update profile ──
        profile.seen_commands.add(msg_name)
        profile.command_history.append(msg_name)
        if len(profile.command_history) > self.max_history:
            profile.command_history = profile.command_history[-self.max_history:]
            profile.command_timestamps = profile.command_timestamps[-self.max_history:]
        profile.command_timestamps.append(now)

        # ── Record detection ──
        is_anomalous = len(anomaly_types) > 0
        if is_anomalous:
            detection = {
                'timestamp': now,
                'attacker_ip': attacker_ip,
                'msg_name': msg_name,
                'anomaly_types': anomaly_types,
                'severity': severity,
                'details': '; '.join(details),
            }
            self._detections.append(detection)
            if len(self._detections) > 1000:
                self._detections = self._detections[-500:]

            logger.warning(
                "COMMAND ORDER ANOMALY from %s: %s — %s (severity=%d)",
                attacker_ip, ', '.join(anomaly_types),
                '; '.join(details), severity
            )

        return {
            'is_anomalous': is_anomalous,
            'anomaly_types': anomaly_types,
            'severity': severity,
            'details': '; '.join(details) if details else 'Normal',
        }

    def get_profile(self, attacker_ip: str) -> dict:
        """Get command ordering profile for an attacker."""
        p = self._profiles.get(attacker_ip)
        if not p:
            return {}

        # Calculate command diversity
        cmd_counts = defaultdict(int)
        for cmd in p.command_history:
            cmd_counts[cmd] += 1

        return {
            'ip': attacker_ip,
            'total_commands': p.total_commands,
            'unique_commands': len(p.seen_commands),
            'order_violations': p.order_violations,
            'burst_violations': p.burst_violations,
            'command_distribution': dict(cmd_counts),
            'session_duration_sec': round(p.last_seen - p.first_seen, 1),
            'anomaly_rate': round(
                (p.order_violations + p.burst_violations) /
                max(p.total_commands, 1) * 100, 2
            ),
        }

    def get_stats(self) -> dict:
        """Get overall detection statistics."""
        return {
            'total_attackers': len(self._profiles),
            'total_violations': sum(
                p.order_violations + p.burst_violations
                for p in self._profiles.values()
            ),
            'total_detections': len(self._detections),
            'per_attacker': {
                ip: {
                    'violations': p.order_violations + p.burst_violations,
                    'commands': p.total_commands,
                }
                for ip, p in self._profiles.items()
            },
        }

    def get_recent_detections(self, limit: int = 20) -> list:
        """Get recent command order detections."""
        return self._detections[-limit:]


if __name__ == "__main__":
    print("Command Order Detector — Test")

    cod = CommandOrderDetector(burst_window_sec=2.0, burst_threshold=5)

    # Normal: heartbeat first
    r = cod.check_command("10.0.0.1", "HEARTBEAT")
    print(f"  HEARTBEAT: anomalous={r['is_anomalous']}")

    r = cod.check_command("10.0.0.1", "PARAM_REQUEST_LIST")
    print(f"  PARAM_REQ: anomalous={r['is_anomalous']}")

    # Violation: SET_MODE without heartbeat
    r = cod.check_command("10.0.0.2", "SET_MODE")
    print(f"  SET_MODE (no HB): anomalous={r['is_anomalous']} — {r['details']}")

    # Violation: COMMAND_LONG without heartbeat
    r = cod.check_command("10.0.0.3", "COMMAND_LONG")
    print(f"  CMD_LONG (no HB): anomalous={r['is_anomalous']} — {r['details']}")

    # Burst: many rapid commands
    for i in range(10):
        r = cod.check_command("10.0.0.4", "HEARTBEAT")
    print(f"  Burst (10 rapid): anomalous={r['is_anomalous']} — {r['details']}")

    print(f"\n  Stats: {cod.get_stats()}")
