#!/usr/bin/env python3
"""
MAVLink Honeypot — Adaptive Deception Engine
Dynamically adjusts honeypot responses based on attacker behavior and skill level.
"""

import random
import time
import json
import os
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional


STRATEGIES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'adaptive_strategies.json'
)


@dataclass
class DronePersonality:
    """A fake drone identity the honeypot can assume."""
    name: str
    system_id: int
    component_id: int
    autopilot_type: int      # MAV_AUTOPILOT enum
    vehicle_type: int         # MAV_TYPE enum
    firmware_version: str
    board_name: str
    # Fake telemetry ranges
    gps_lat_range: tuple = (37.7, 37.8)
    gps_lon_range: tuple = (-122.5, -122.4)
    alt_range: tuple = (10, 120)
    battery_range: tuple = (60, 100)
    speed_range: tuple = (0, 15)


# ── Pre-built drone personalities ──
PERSONALITIES = {
    "pixhawk4": DronePersonality(
        name="Pixhawk 4", system_id=1, component_id=1,
        autopilot_type=12,  # MAV_AUTOPILOT_PX4
        vehicle_type=2,     # MAV_TYPE_QUADROTOR
        firmware_version="1.14.3",
        board_name="PX4_FMU_V5",
        gps_lat_range=(37.77, 37.79),
        gps_lon_range=(-122.42, -122.41),
        alt_range=(15, 80),
        battery_range=(65, 95),
    ),
    "ardupilot": DronePersonality(
        name="ArduPilot Copter", system_id=1, component_id=1,
        autopilot_type=3,   # MAV_AUTOPILOT_ARDUPILOTMEGA
        vehicle_type=2,     # MAV_TYPE_QUADROTOR
        firmware_version="4.5.1",
        board_name="CubeOrange",
        gps_lat_range=(34.05, 34.07),
        gps_lon_range=(-118.25, -118.24),
        alt_range=(10, 120),
        battery_range=(70, 100),
    ),
    "dji_mimic": DronePersonality(
        name="DJI Phantom (Cloned)", system_id=1, component_id=1,
        autopilot_type=0,   # MAV_AUTOPILOT_GENERIC
        vehicle_type=2,     # MAV_TYPE_QUADROTOR
        firmware_version="v02.04.03",
        board_name="FC550",
        gps_lat_range=(40.71, 40.73),
        gps_lon_range=(-74.01, -73.99),
        alt_range=(5, 50),
        battery_range=(75, 100),
    ),
    "military_uav": DronePersonality(
        name="Military Recon UAV", system_id=1, component_id=1,
        autopilot_type=12,  # MAV_AUTOPILOT_PX4
        vehicle_type=1,     # MAV_TYPE_FIXED_WING
        firmware_version="MIL-STD-v3.2.1",
        board_name="CLASSIFIED",
        gps_lat_range=(38.89, 38.92),
        gps_lon_range=(-77.04, -77.01),
        alt_range=(200, 500),
        battery_range=(80, 99),
        speed_range=(20, 60),
    ),
}


@dataclass
class DeceptionStrategy:
    """Per-attacker deception strategy state."""
    attacker_ip: str
    skill_level: str = "UNKNOWN"
    strategy: str = "STANDARD"       # STANDARD, ENGAGING, WASTING, MIRRORING
    personality: str = "pixhawk4"
    escalation_level: int = 0        # 0-5, how much fake data to expose
    interactions: int = 0
    last_adjusted: str = ""

    # Effectiveness tracking
    avg_session_duration_sec: float = 0
    returned: bool = False
    total_commands_received: int = 0


class AdaptiveDeception:
    """
    Dynamically adjusts honeypot responses based on attacker profile.

    Strategies:
    - STANDARD: Normal fake responses (for unknown/new attackers)
    - ENGAGING: Richer fake data to keep curious attackers interested
    - WASTING: Introduce subtle delays/inconsistencies to waste advanced attackers' time
    - MIRRORING: Adapt personality to match what the attacker expects
    """

    def __init__(self):
        self.strategies: Dict[str, DeceptionStrategy] = {}
        self._load()

    def _load(self):
        if os.path.exists(STRATEGIES_FILE):
            try:
                with open(STRATEGIES_FILE, 'r') as f:
                    data = json.load(f)
                for ip, sdata in data.items():
                    self.strategies[ip] = DeceptionStrategy(**sdata)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(STRATEGIES_FILE), exist_ok=True)
            with open(STRATEGIES_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.strategies.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def get_strategy(self, ip: str, skill_level: str = "UNKNOWN") -> DeceptionStrategy:
        """Get or create the deception strategy for an attacker."""
        if ip not in self.strategies:
            self.strategies[ip] = DeceptionStrategy(
                attacker_ip=ip,
                skill_level=skill_level,
                last_adjusted=datetime.now().isoformat()
            )
        strategy = self.strategies[ip]

        # Update skill level if provided
        if skill_level != "UNKNOWN":
            strategy.skill_level = skill_level

        return strategy

    def select_response(self, ip: str, msg_id: int, intent: str,
                        skill_level: str = "UNKNOWN") -> dict:
        """
        Select the best deception response for this attacker and message.

        Returns:
            dict with: personality, response_delay_ms, data_richness,
                      inject_inconsistency, fake_data_overrides
        """
        strat = self.get_strategy(ip, skill_level)
        strat.interactions += 1
        strat.total_commands_received += 1

        # Auto-adjust strategy based on skill level
        self._auto_adjust(strat)

        personality = PERSONALITIES.get(strat.personality, PERSONALITIES["pixhawk4"])

        response = {
            "personality": strat.personality,
            "system_id": personality.system_id,
            "autopilot_type": personality.autopilot_type,
            "vehicle_type": personality.vehicle_type,
            "firmware_version": personality.firmware_version,
            "response_delay_ms": 0,
            "data_richness": "NORMAL",
            "inject_inconsistency": False,
            "fake_data": self._generate_telemetry(personality, strat),
        }

        if strat.strategy == "STANDARD":
            response["response_delay_ms"] = random.randint(10, 50)
            response["data_richness"] = "NORMAL"

        elif strat.strategy == "ENGAGING":
            response["response_delay_ms"] = random.randint(20, 80)
            response["data_richness"] = "RICH"
            # Add "sensitive-looking" data to entice the attacker
            response["fake_data"]["mission_count"] = random.randint(3, 12)
            response["fake_data"]["waypoints_loaded"] = random.randint(5, 25)
            response["fake_data"]["camera_status"] = "RECORDING"

        elif strat.strategy == "WASTING":
            # Add subtle delays to waste advanced attacker's time
            response["response_delay_ms"] = random.randint(100, 500)
            response["data_richness"] = "RICH"
            # Occasionally inject subtle inconsistencies
            if random.random() < 0.15:
                response["inject_inconsistency"] = True
                # GPS coordinates that drift slightly — makes attacker investigate
                response["fake_data"]["gps_lat"] += random.uniform(-0.001, 0.001)
                response["fake_data"]["gps_lon"] += random.uniform(-0.001, 0.001)

        elif strat.strategy == "MIRRORING":
            response["response_delay_ms"] = random.randint(5, 30)
            response["data_richness"] = "MAXIMUM"
            # Full fake operations — mission plans, parameters, everything
            response["fake_data"]["mission_count"] = random.randint(8, 20)
            response["fake_data"]["param_count"] = random.randint(200, 800)
            response["fake_data"]["flight_mode"] = random.choice([
                "STABILIZE", "LOITER", "AUTO", "RTL", "GUIDED"
            ])

        strat.last_adjusted = datetime.now().isoformat()
        self._save()

        return response

    def _auto_adjust(self, strat: DeceptionStrategy):
        """Automatically adjust strategy based on attacker behavior."""
        # New attackers start with STANDARD
        if strat.interactions < 3:
            strat.strategy = "STANDARD"
            return

        # Script kiddies get ENGAGING to keep them busy
        if strat.skill_level in ("SCRIPT_KIDDIE", "UNKNOWN"):
            strat.strategy = "ENGAGING"
            strat.personality = "pixhawk4"

        # Intermediate attackers get richer data
        elif strat.skill_level == "INTERMEDIATE":
            strat.strategy = "ENGAGING"
            # Switch to more interesting personality
            strat.personality = random.choice(["ardupilot", "dji_mimic"])

        # Advanced attackers get time-wasting tactics
        elif strat.skill_level == "ADVANCED":
            strat.strategy = "WASTING"
            strat.personality = "ardupilot"

        # APTs get full mirroring to gather maximum intel
        elif strat.skill_level == "APT":
            strat.strategy = "MIRRORING"
            strat.personality = "military_uav"

        # Escalate data exposure over time
        strat.escalation_level = min(5, strat.interactions // 5)

    def _generate_telemetry(self, persona: DronePersonality,
                           strat: DeceptionStrategy) -> dict:
        """Generate fake telemetry data based on personality."""
        return {
            "gps_lat": random.uniform(*persona.gps_lat_range),
            "gps_lon": random.uniform(*persona.gps_lon_range),
            "altitude": round(random.uniform(*persona.alt_range), 1),
            "battery_pct": random.randint(*persona.battery_range),
            "speed": round(random.uniform(*persona.speed_range), 1),
            "heading": random.randint(0, 359),
            "satellites": random.randint(8, 16),
            "firmware": persona.firmware_version,
            "board": persona.board_name,
        }

    def on_session_end(self, ip: str, duration_sec: float):
        """Record session ending for effectiveness tracking."""
        if ip in self.strategies:
            s = self.strategies[ip]
            # Running average
            if s.avg_session_duration_sec == 0:
                s.avg_session_duration_sec = duration_sec
            else:
                s.avg_session_duration_sec = (
                    s.avg_session_duration_sec * 0.7 + duration_sec * 0.3
                )
            self._save()

    def on_returning_attacker(self, ip: str):
        """Record that an attacker returned — strong signal we're fooling them."""
        if ip in self.strategies:
            self.strategies[ip].returned = True
            self._save()

    def get_all_strategies(self) -> List[dict]:
        """Get all active strategies for dashboard display."""
        return [asdict(s) for s in self.strategies.values()]

    def get_personality_info(self, personality_name: str) -> dict:
        """Get personality details for display."""
        p = PERSONALITIES.get(personality_name)
        if not p:
            return {}
        return {
            "name": p.name,
            "autopilot": p.autopilot_type,
            "vehicle": p.vehicle_type,
            "firmware": p.firmware_version,
            "board": p.board_name,
        }

    def get_available_personalities(self) -> List[dict]:
        """List all available drone personalities."""
        return [
            {"id": k, "name": v.name, "firmware": v.firmware_version, "board": v.board_name}
            for k, v in PERSONALITIES.items()
        ]


if __name__ == "__main__":
    print("🎭 Adaptive Deception Engine — Test")

    engine = AdaptiveDeception()

    # Simulate attacker interactions
    test_ip = "192.168.1.100"
    for i in range(8):
        skill = "SCRIPT_KIDDIE" if i < 3 else "INTERMEDIATE"
        resp = engine.select_response(test_ip, 0, "RECON", skill)
        print(f"\n  Interaction {i+1} (skill={skill}):")
        print(f"    Strategy: {engine.strategies[test_ip].strategy}")
        print(f"    Personality: {resp['personality']}")
        print(f"    Delay: {resp['response_delay_ms']}ms")
        print(f"    Richness: {resp['data_richness']}")
        print(f"    GPS: ({resp['fake_data']['gps_lat']:.4f}, {resp['fake_data']['gps_lon']:.4f})")
