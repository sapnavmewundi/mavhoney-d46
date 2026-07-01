#!/usr/bin/env python3
"""
MAVLink Honeypot — Attacker Interaction Tarpit
Wastes attacker time with adaptive delays, fake processing states,
infinite parameter lists, and state machine traps.
"""

import os
import json
import time
import math
import random
from datetime import datetime
from collections import defaultdict
from typing import Dict, List
from dataclasses import dataclass, asdict, field


TARPIT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'tarpit_stats.json'
)


# Fake parameters to serve during PARAM_REQUEST_LIST attacks
FAKE_PARAMS = [
    ("BATT_CAPACITY", 3300, "mAh"), ("BATT2_CAPACITY", 2600, "mAh"),
    ("BATT_LOW_VOLT", 4.2, "V"), ("BATT_CRT_VOLT", 3.5, "V"),
    ("WPNAV_SPEED", 500, "cm/s"), ("WPNAV_RADIUS", 200, "cm"),
    ("WPNAV_SPEED_UP", 250, "cm/s"), ("WPNAV_SPEED_DN", 150, "cm/s"),
    ("INS_ACCOFFS_X", 0.012, "m/s²"), ("INS_ACCOFFS_Y", -0.008, "m/s²"),
    ("INS_ACCOFFS_Z", 0.034, "m/s²"), ("INS_GYROFFS_X", 0.001, "rad/s"),
    ("INS_GYROFFS_Y", -0.002, "rad/s"), ("INS_GYROFFS_Z", 0.003, "rad/s"),
    ("COMPASS_OFS_X", 23.5, "mGauss"), ("COMPASS_OFS_Y", -12.8, "mGauss"),
    ("COMPASS_OFS_Z", 45.2, "mGauss"), ("COMPASS_DEC", 0.21, "rad"),
    ("SERIAL0_BAUD", 115, "kbps"), ("SERIAL1_BAUD", 57, "kbps"),
    ("SERIAL2_BAUD", 921, "kbps"), ("SERIAL0_PROTOCOL", 2, ""),
    ("ATC_RAT_RLL_P", 0.135, ""), ("ATC_RAT_RLL_I", 0.135, ""),
    ("ATC_RAT_RLL_D", 0.004, ""), ("ATC_RAT_PIT_P", 0.135, ""),
    ("ATC_RAT_PIT_I", 0.135, ""), ("ATC_RAT_PIT_D", 0.004, ""),
    ("ATC_RAT_YAW_P", 0.200, ""), ("ATC_RAT_YAW_I", 0.020, ""),
    ("GPS_TYPE", 1, ""), ("GPS_TYPE2", 0, ""),
    ("GPS_NAVFILTER", 8, ""), ("GPS_RATE_MS", 200, "ms"),
    ("FENCE_ENABLE", 1, ""), ("FENCE_TYPE", 7, ""),
    ("FENCE_ALT_MAX", 100, "m"), ("FENCE_RADIUS", 300, "m"),
    ("ARMING_CHECK", 1, ""), ("ARMING_REQUIRE", 1, ""),
    ("FS_THR_ENABLE", 1, ""), ("FS_THR_VALUE", 975, "pwm"),
    ("FS_BATT_ENABLE", 2, ""), ("FS_BATT_VOLTAGE", 10.5, "V"),
    ("FS_GCS_ENABLE", 1, ""), ("FS_EKF_ACTION", 1, ""),
    ("LOG_BACKEND_TYPE", 1, ""), ("LOG_BITMASK", 65535, ""),
    ("LOG_FILE_DSRMROT", 1, ""), ("LOG_FILE_BUFSIZE", 50, "KB"),
    ("RC1_MIN", 1100, "pwm"), ("RC1_MAX", 1900, "pwm"),
    ("RC1_TRIM", 1500, "pwm"), ("RC1_REVERSED", 0, ""),
    ("RC2_MIN", 1100, "pwm"), ("RC2_MAX", 1900, "pwm"),
    ("RC3_MIN", 1100, "pwm"), ("RC3_MAX", 1900, "pwm"),
    ("EK2_GPS_TYPE", 0, ""), ("EK2_POSNE_M_NSE", 0.5, "m"),
    ("EK2_ALT_M_NSE", 2.0, "m"), ("EK2_MAG_M_NSE", 0.05, "Gauss"),
    ("PILOT_SPEED_UP", 250, "cm/s"), ("PILOT_SPEED_DN", 150, "cm/s"),
    ("PILOT_ACCEL_Z", 250, "cm/s²"), ("PILOT_THR_FILT", 0.0, ""),
    ("MOT_BAT_VOLT_MAX", 12.6, "V"), ("MOT_BAT_VOLT_MIN", 10.0, "V"),
    ("MOT_SPIN_ARM", 0.10, ""), ("MOT_SPIN_MIN", 0.15, ""),
    ("MOT_THST_EXPO", 0.65, ""), ("MOT_THST_HOVER", 0.35, ""),
    ("RELAY_PIN", 54, ""), ("RELAY_PIN2", -1, ""),
    ("TERRAIN_ENABLE", 1, ""), ("TERRAIN_FOLLOW", 0, ""),
    ("FLOW_ENABLE", 0, ""), ("RNGFND_TYPE", 0, ""),
    ("OSD_TYPE", 1, ""), ("OSD_CHAN", 0, ""),
    ("NTF_LED_BRIGHT", 3, ""), ("NTF_LED_TYPES", 231, ""),
    ("AHRS_EKF_TYPE", 3, ""), ("AHRS_ORIENTATION", 0, ""),
    ("MIS_TOTAL", 5, ""), ("MIS_RESTART", 0, ""),
    ("CAN_D1_PROTOCOL", 1, ""), ("CAN_P1_DRIVER", 1, ""),
    ("FRAME_TYPE", 0, ""), ("FRAME_CLASS", 1, ""),
]

# Fake status messages for tarpitting
FAKE_STATUSES = [
    "PreArm: Calibrating barometer",
    "PreArm: Calibrating gyros",
    "EKF2 IMU0 is using GPS",
    "EKF2 IMU1 initial yaw alignment complete",
    "GPS 1: detected u-blox at 115200 baud",
    "Firmware update available: v4.5.2-beta3",
    "Download from http://firmware.ardupilot.org/update/v452b3_{token}",
    "PreArm: Compass not calibrated",
    "PreArm: RC not calibrated",
    "Initializing SD card...",
    "Loading mission from SD card...",
    "Battery failsafe: RTL triggered",
    "Terrain database loading...",
    "Waypoint 0 uploaded",
    "Fence breach detected",
    "AHRS: DCM active",
    "EKF2: source reset to primary",
    "Throttle failsafe ON",
    "RC override timeout",
    "Mode change denied: not armed",
]


@dataclass
class TarpitSession:
    """Per-attacker tarpit tracking."""
    attacker_ip: str
    skill_level: str = "UNKNOWN"
    strategy: str = "STANDARD"       # STANDARD, SLOW, INFINITE, TRAP
    total_delay_ms: float = 0        # Total ms of delay injected
    wasted_time_sec: float = 0       # Estimated attacker time wasted
    packets_tarpitted: int = 0
    params_served: int = 0           # Fake params sent
    fake_statuses_sent: int = 0
    trap_stages_completed: int = 0
    current_trap_stage: int = 0
    first_seen: str = ""
    last_seen: str = ""
    bandwidth_wasted_bytes: int = 0


class AttackerTarpit:
    """
    Wastes attacker time with multiple tarpitting strategies.

    Strategies by skill level:
    - SCRIPT_KIDDIE → INFINITE: send 1000+ fake params, slow delays
    - INTERMEDIATE  → SLOW: logarithmically increasing response delay
    - ADVANCED      → TRAP: fake auth sequences, multi-step traps
    - APT           → STANDARD: subtle delays to avoid detection
    """

    # Delay settings
    BASE_DELAY_MS = 50      # Minimum delay
    MAX_DELAY_MS = 5000     # Maximum delay per response
    DELAY_GROWTH_RATE = 1.3 # Logarithmic growth factor

    # Infinite param list settings
    MAX_FAKE_PARAMS = 500   # How many params to serve

    # Trap settings
    TRAP_STAGES = [
        {"name": "auth_challenge",  "response": "AUTH: Enter access code via PARAM_SET 'AUTH_CODE'"},
        {"name": "auth_wait",       "response": "AUTH: Verifying credentials... Please wait."},
        {"name": "auth_retry",      "response": "AUTH: Code expired. Re-enter via PARAM_SET 'AUTH_CODE'"},
        {"name": "auth_2fa",        "response": "AUTH: 2FA required. Send code via PARAM_SET 'AUTH_2FA'"},
        {"name": "auth_processing", "response": "AUTH: Processing 2FA... Estimated wait: 30s"},
        {"name": "auth_upgrade",    "response": "AUTH: Firmware update required for access. Stand by."},
        {"name": "firmware_dl",     "response": "FIRMWARE: Downloading update... 12%"},
        {"name": "firmware_apply",  "response": "FIRMWARE: Applying update... Do not disconnect."},
        {"name": "reboot",          "response": "SYSTEM: Rebooting... ETA: 45 seconds"},
        {"name": "post_reboot",     "response": "SYSTEM: Reinitializing... Please reconnect."},
    ]

    def __init__(self):
        self.sessions: Dict[str, TarpitSession] = {}
        self.param_counters: Dict[str, int] = defaultdict(int)
        self._load()

    def _load(self):
        if os.path.exists(TARPIT_FILE):
            try:
                with open(TARPIT_FILE, 'r') as f:
                    data = json.load(f)
                for ip, sdata in data.items():
                    self.sessions[ip] = TarpitSession(**sdata)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(TARPIT_FILE), exist_ok=True)
            with open(TARPIT_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.sessions.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def _ensure_session(self, ip: str, skill: str = "UNKNOWN") -> TarpitSession:
        if ip not in self.sessions:
            self.sessions[ip] = TarpitSession(
                attacker_ip=ip,
                skill_level=skill,
                first_seen=datetime.now().isoformat(),
            )
            self._select_strategy(ip, skill)
        return self.sessions[ip]

    def _select_strategy(self, ip: str, skill: str):
        """Select tarpitting strategy based on attacker skill."""
        session = self.sessions[ip]
        session.skill_level = skill

        if skill in ("SCRIPT_KIDDIE", "UNKNOWN"):
            session.strategy = "INFINITE"
        elif skill == "INTERMEDIATE":
            session.strategy = "SLOW"
        elif skill == "ADVANCED":
            session.strategy = "TRAP"
        elif skill == "APT":
            session.strategy = "STANDARD"  # Subtle for APTs
        else:
            session.strategy = "SLOW"

    # ── Tarpitting Actions ──

    def get_delay_ms(self, attacker_ip: str, skill: str = "UNKNOWN") -> float:
        """
        Calculate how much delay to inject in the response.
        Returns delay in milliseconds.
        """
        session = self._ensure_session(attacker_ip, skill)
        n = session.packets_tarpitted + 1

        if session.strategy == "STANDARD":
            # Subtle: slight random jitter
            delay = self.BASE_DELAY_MS + random.uniform(0, 50)
        elif session.strategy == "SLOW":
            # Logarithmic growth
            delay = self.BASE_DELAY_MS + math.log(n + 1) * 100 * self.DELAY_GROWTH_RATE
        elif session.strategy == "INFINITE":
            # Moderate but consistent delay
            delay = self.BASE_DELAY_MS + min(n * 20, 2000)
        elif session.strategy == "TRAP":
            # Longer delays at trap stages
            stage = session.current_trap_stage
            delay = self.BASE_DELAY_MS + (stage + 1) * 300
        else:
            delay = self.BASE_DELAY_MS

        delay = min(delay, self.MAX_DELAY_MS)

        session.total_delay_ms += delay
        session.packets_tarpitted += 1
        session.wasted_time_sec = round(session.total_delay_ms / 1000, 2)
        session.last_seen = datetime.now().isoformat()

        if session.packets_tarpitted % 10 == 0:
            self._save()

        return delay

    def get_fake_params(self, attacker_ip: str, batch_size: int = 10) -> List[dict]:
        """
        Generate a batch of fake parameters for PARAM_REQUEST_LIST attacks.
        Keeps serving more and more params to waste time.
        """
        session = self._ensure_session(attacker_ip)
        start_idx = self.param_counters[attacker_ip]

        params = []
        for i in range(batch_size):
            idx = (start_idx + i) % len(FAKE_PARAMS)
            name, value, unit = FAKE_PARAMS[idx]

            # Add random variation
            if isinstance(value, float):
                value = round(value + random.uniform(-0.01, 0.01), 4)
            elif isinstance(value, int) and value > 10:
                value += random.randint(-2, 2)

            params.append({
                "param_id": name,
                "param_value": value,
                "param_type": 9 if isinstance(value, float) else 6,  # REAL32 or INT32
                "param_count": self.MAX_FAKE_PARAMS,
                "param_index": start_idx + i,
            })

        self.param_counters[attacker_ip] = start_idx + batch_size
        session.params_served += batch_size
        session.bandwidth_wasted_bytes += batch_size * 25  # ~25 bytes per param msg

        return params

    def get_trap_response(self, attacker_ip: str) -> dict:
        """
        Get the current trap stage response for state machine traps.
        Advances through multi-step fake auth/update sequences.
        """
        session = self._ensure_session(attacker_ip)
        stage_idx = session.current_trap_stage

        if stage_idx >= len(self.TRAP_STAGES):
            # Loop back to create infinite loop
            session.current_trap_stage = 0
            stage_idx = 0

        stage = self.TRAP_STAGES[stage_idx]
        session.current_trap_stage += 1
        session.trap_stages_completed += 1

        return {
            "stage_name": stage["name"],
            "status_message": stage["response"],
            "stage_number": stage_idx + 1,
            "total_stages": len(self.TRAP_STAGES),
            "is_trap": True,
        }

    def get_fake_status(self, attacker_ip: str) -> str:
        """Get a random fake status message."""
        session = self._ensure_session(attacker_ip)
        session.fake_statuses_sent += 1
        return random.choice(FAKE_STATUSES)

    # ── Analytics ──

    def get_all_sessions(self) -> List[dict]:
        """Get all tarpit sessions."""
        return [asdict(s) for s in sorted(
            self.sessions.values(),
            key=lambda s: s.wasted_time_sec,
            reverse=True,
        )]

    def get_stats(self) -> dict:
        """Overall tarpitting statistics."""
        total_delay = sum(s.total_delay_ms for s in self.sessions.values())
        total_wasted = sum(s.wasted_time_sec for s in self.sessions.values())
        total_params = sum(s.params_served for s in self.sessions.values())
        total_bandwidth = sum(s.bandwidth_wasted_bytes for s in self.sessions.values())

        strategy_dist = defaultdict(int)
        for s in self.sessions.values():
            strategy_dist[s.strategy] += 1

        return {
            "active_tarpits": len(self.sessions),
            "total_delay_sec": round(total_delay / 1000, 1),
            "total_time_wasted_sec": round(total_wasted, 1),
            "total_time_wasted_min": round(total_wasted / 60, 1),
            "total_params_served": total_params,
            "total_bandwidth_wasted_kb": round(total_bandwidth / 1024, 1),
            "strategy_distribution": dict(strategy_dist),
        }


if __name__ == "__main__":
    print("🕳️  Attacker Tarpit — Test")

    tarpit = AttackerTarpit()

    # Simulate script kiddie
    for i in range(20):
        delay = tarpit.get_delay_ms("10.0.0.1", skill="SCRIPT_KIDDIE")
    params = tarpit.get_fake_params("10.0.0.1", batch_size=5)
    print(f"  Script kiddie: strategy=INFINITE, delay={delay:.0f}ms, params={len(params)}")

    # Simulate APT
    for i in range(20):
        delay = tarpit.get_delay_ms("10.0.0.2", skill="APT")
    print(f"  APT: strategy=STANDARD, delay={delay:.0f}ms")

    # Simulate trap stages
    for i in range(5):
        trap = tarpit.get_trap_response("10.0.0.3")
    print(f"  Trap stage: {trap['stage_name']} — '{trap['status_message']}'")

    stats = tarpit.get_stats()
    print(f"\n  Time wasted: {stats['total_time_wasted_sec']}s")
    print(f"  Params served: {stats['total_params_served']}")
