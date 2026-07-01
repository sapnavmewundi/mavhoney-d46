"""
Semantic Analyzer — MAVLink message intent classification and attack-pattern detection.

Maps every known MAVLink message ID to a threat intent and severity level,
then detects multi-message attack patterns in real time.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set


# ── MAVLink Semantics Table ──────────────────────────────────

#: Mapping of MAVLink message ID → ``{name, intent, severity}``.
#: Severity is rated 1–10 (1 = benign info, 10 = critical attack).
MAVLINK_SEMANTICS: Dict[int, Dict[str, Any]] = {
    # ── Reconnaissance Messages ──
    0:   {"name": "HEARTBEAT",              "intent": "RECON",          "severity": 1},
    1:   {"name": "SYS_STATUS",             "intent": "RECON",          "severity": 1},
    2:   {"name": "SYSTEM_TIME",            "intent": "RECON",          "severity": 1},
    20:  {"name": "PARAM_REQUEST_LIST",     "intent": "RECON",          "severity": 2},
    21:  {"name": "PARAM_REQUEST_READ",     "intent": "RECON",          "severity": 2},
    24:  {"name": "GPS_RAW_INT",            "intent": "RECON",          "severity": 1},
    27:  {"name": "RAW_IMU",               "intent": "RECON",          "severity": 2},
    30:  {"name": "ATTITUDE",              "intent": "RECON",          "severity": 1},
    33:  {"name": "GLOBAL_POSITION_INT",   "intent": "RECON",          "severity": 2},
    36:  {"name": "SERVO_OUTPUT_RAW",      "intent": "RECON",          "severity": 2},
    42:  {"name": "MISSION_CURRENT",       "intent": "RECON",          "severity": 2},
    62:  {"name": "NAV_CONTROLLER_OUTPUT", "intent": "RECON",          "severity": 2},
    74:  {"name": "VFR_HUD",              "intent": "RECON",          "severity": 1},
    147: {"name": "BATTERY_STATUS",        "intent": "RECON",          "severity": 1},
    148: {"name": "AUTOPILOT_VERSION",     "intent": "RECON",          "severity": 3},
    242: {"name": "HOME_POSITION",         "intent": "RECON",          "severity": 3},
    245: {"name": "EXTENDED_SYS_STATE",    "intent": "RECON",          "severity": 2},
    252: {"name": "STATUSTEXT",            "intent": "RECON",          "severity": 1},
    253: {"name": "DEBUG",                 "intent": "RECON",          "severity": 1},

    # ── Control / Command Messages ──
    11:  {"name": "SET_MODE",              "intent": "CONTROL",        "severity": 5},
    76:  {"name": "COMMAND_LONG",          "intent": "CONTROL",        "severity": 6},
    176: {"name": "COMMAND_INT",           "intent": "CONTROL",        "severity": 6},
    223: {"name": "MANUAL_CONTROL",        "intent": "CONTROL",        "severity": 7},
    243: {"name": "SET_HOME_POSITION",     "intent": "CONTROL",        "severity": 7},
    397: {"name": "CAMERA_TRIGGER",        "intent": "CONTROL",        "severity": 5},
    400: {"name": "ARM_DISARM",            "intent": "CONTROL",        "severity": 8},

    # ── Configuration / Tampering ──
    23:  {"name": "PARAM_SET",             "intent": "CONFIG_ATTACK",  "severity": 7},

    # ── Hijack Messages ──
    83:  {"name": "ATTITUDE_TARGET",                 "intent": "HIJACK", "severity": 8},
    84:  {"name": "SET_POSITION_TARGET_LOCAL_NED",   "intent": "HIJACK", "severity": 9},
    86:  {"name": "SET_POSITION_TARGET_GLOBAL_INT",  "intent": "HIJACK", "severity": 9},

    # ── GPS Spoofing ──
    113: {"name": "HIL_GPS",               "intent": "GPS_SPOOF",      "severity": 10},
    132: {"name": "GPS_INPUT",             "intent": "GPS_SPOOF",      "severity": 9},

    # ── Mission Injection ──
    511: {"name": "MISSION_ITEM",          "intent": "MISSION_INJECT", "severity": 7},
    512: {"name": "MISSION_REQUEST",       "intent": "MISSION_INJECT", "severity": 6},
    513: {"name": "MISSION_SET_CURRENT",   "intent": "MISSION_INJECT", "severity": 7},
    514: {"name": "MISSION_CLEAR_ALL",     "intent": "MISSION_INJECT", "severity": 8},

    # ── Sensor Spoofing ──
    241: {"name": "VIBRATION",             "intent": "SENSOR_SPOOF",   "severity": 4},
}

#: Known multi-message attack patterns.
ATTACK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "DOS":              {"threshold": 50, "window": 5},
    "GPS_SPOOF":        {"msgs": [113, 132]},
    "HIJACK_SEQUENCE":  {"msgs": [400, 76, 84, 86]},
    "RECON_SWEEP":      {"msgs": [0, 20, 21], "count": 10},
}

#: All valid intent categories used across the honeypot.
VALID_INTENTS: Set[str] = {
    "RECON", "CONTROL", "HIJACK", "GPS_SPOOF",
    "MISSION_INJECT", "CONFIG_ATTACK", "SENSOR_SPOOF",
    "DOS_FLOOD", "UNKNOWN",
}


class SemanticAnalyzer:
    """Classifies MAVLink messages by intent and detects attack patterns.

    Maintains per-session message history so it can recognise multi-step
    attack sequences (e.g. ARM → COMMAND_LONG → SET_POSITION = hijack).

    Example:
        >>> sa = SemanticAnalyzer()
        >>> result = sa.analyze_intent(0, ("192.168.1.1", 12345))
        >>> print(result["intent"])
        'RECON'
    """

    def __init__(self) -> None:
        #: Per-session message-ID history (keyed by ``"ip:port"``).
        self.session_data: Dict[str, List[int]] = defaultdict(list)
        #: Per-session packet timestamps for DoS detection.
        self.msg_timestamps: Dict[str, List[float]] = defaultdict(list)

    def analyze_intent(
        self,
        msg_id: int,
        addr: tuple,
    ) -> Dict[str, Any]:
        """Classify a single MAVLink message and check for attack patterns.

        Args:
            msg_id: MAVLink message ID (0–65535).
            addr: ``(ip, port)`` tuple identifying the session.

        Returns:
            A dict containing at least ``name``, ``intent``, and
            ``severity``.  If an attack pattern is detected, an
            additional ``detected_pattern`` key is present and severity
            is elevated to at least 9.
        """
        semantics = MAVLINK_SEMANTICS.get(msg_id, {
            "name": f"UNKNOWN_{msg_id}",
            "intent": "UNKNOWN",
            "severity": 3,
        })

        session_key = f"{addr[0]}:{addr[1]}"
        self.session_data[session_key].append(msg_id)

        pattern = self.detect_pattern(session_key, msg_id)
        if pattern:
            semantics = dict(semantics)  # avoid mutating the global dict
            semantics["detected_pattern"] = pattern
            semantics["severity"] = max(semantics["severity"], 9)

        return semantics

    def detect_pattern(
        self,
        session_key: str,
        msg_id: int,
    ) -> Optional[str]:
        """Detect multi-message attack patterns in the recent history.

        Checks for:
          - **DOS_FLOOD**: >50 messages within 5 seconds.
          - **GPS_SPOOF_ATTEMPT**: HIL_GPS or GPS_INPUT message.
          - **HIJACK_SEQUENCE**: ARM → COMMAND_LONG → SET_POSITION sequence.
          - **RECON_SWEEP**: >10 recon messages in the last 20.
          - **PARAM_EXTRACTION**: >5 param-read requests.
          - **CONFIG_TAMPERING**: ≥3 PARAM_SET messages.
          - **KILL_SEQUENCE**: rapid COMMAND_LONG + SET_MODE combination.

        Args:
            session_key: ``"ip:port"`` session identifier.
            msg_id: The latest message ID received.

        Returns:
            The name of the detected pattern, or ``None``.
        """
        recent = self.session_data[session_key][-20:]

        # DoS flood detection (rate-based)
        current_time = time.time()
        self.msg_timestamps[session_key].append(current_time)
        self.msg_timestamps[session_key] = [
            t for t in self.msg_timestamps[session_key]
            if current_time - t < 5
        ]
        if len(self.msg_timestamps[session_key]) > 50:
            return "DOS_FLOOD"

        # GPS spoofing
        if msg_id in (113, 132):
            return "GPS_SPOOF_ATTEMPT"

        # Hijack sequence
        hijack_seq = [400, 76, 84]
        if len(recent) >= 3 and recent[-3:] == hijack_seq:
            return "HIJACK_SEQUENCE"

        # Recon sweep
        recon_msgs = {0, 20, 21}
        if sum(1 for m in recent if m in recon_msgs) > 10:
            return "RECON_SWEEP"

        # Param extraction
        if sum(1 for m in recent if m in (20, 21)) > 5:
            return "PARAM_EXTRACTION"

        # Config tampering
        if sum(1 for m in recent if m == 23) >= 3:
            return "CONFIG_TAMPERING"

        # Kill sequence
        kill_cmds = sum(1 for m in recent if m in (76, 11))
        if kill_cmds >= 4 and 11 in recent:
            return "KILL_SEQUENCE"

        return None

    def get_packet_rate(self, session_key: str) -> float:
        """Return the current packets-per-second for *session_key*.

        Args:
            session_key: ``"ip:port"`` session identifier.

        Returns:
            Estimated packets per second over the last 5-second window.
        """
        timestamps = self.msg_timestamps.get(session_key, [])
        return len(timestamps) / 5.0
