#!/usr/bin/env python3
"""
MAVLink Honeypot — Decoy Fleet Simulation
Simulates multiple drones on the network to study attacker target selection.
"""

import random
import json
import os
import time
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List


FLEET_STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'fleet_state.json'
)


@dataclass
class DecoyDrone:
    """A single decoy drone in the fleet."""
    drone_id: str
    callsign: str
    system_id: int
    model: str
    status: str = "PATROL"        # PATROL, HOVER, LANDING, CHARGING, MISSION
    is_targeted: bool = False
    target_count: int = 0         # How many times this drone was targeted

    # Fake telemetry
    gps_lat: float = 0.0
    gps_lon: float = 0.0
    altitude: float = 50.0
    battery_pct: int = 85
    speed: float = 5.0
    heading: int = 0

    # Mission info
    mission_name: str = ""
    waypoint_count: int = 0
    current_waypoint: int = 0

    # Tracking
    last_heartbeat: str = ""
    attacks_received: int = 0
    attack_types_received: List[str] = field(default_factory=list)


# ── Pre-configured fleet ──
DEFAULT_FLEET = [
    {
        "drone_id": "UAV-01",
        "callsign": "ALPHA",
        "system_id": 1,
        "model": "Pixhawk 4 Quadrotor",
        "status": "PATROL",
        "gps_lat": 37.7749, "gps_lon": -122.4194,
        "altitude": 45.0, "battery_pct": 87,
        "mission_name": "Perimeter Sweep",
        "waypoint_count": 8, "current_waypoint": 3,
    },
    {
        "drone_id": "UAV-02",
        "callsign": "BRAVO",
        "system_id": 2,
        "model": "ArduPilot Hexacopter",
        "status": "HOVER",
        "gps_lat": 37.7755, "gps_lon": -122.4180,
        "altitude": 30.0, "battery_pct": 62,
        "mission_name": "Overwatch Station",
        "waypoint_count": 1, "current_waypoint": 1,
    },
    {
        "drone_id": "UAV-03",
        "callsign": "CHARLIE",
        "system_id": 3,
        "model": "Fixed-Wing Recon",
        "status": "MISSION",
        "gps_lat": 37.7730, "gps_lon": -122.4210,
        "altitude": 120.0, "battery_pct": 91,
        "speed": 18.5,
        "mission_name": "Area Survey Grid-7",
        "waypoint_count": 24, "current_waypoint": 11,
    },
    {
        "drone_id": "UAV-04",
        "callsign": "DELTA",
        "system_id": 4,
        "model": "DJI Matrice Clone",
        "status": "CHARGING",
        "gps_lat": 37.7745, "gps_lon": -122.4188,
        "altitude": 0.0, "battery_pct": 34,
        "speed": 0.0,
        "mission_name": "Standby",
        "waypoint_count": 0, "current_waypoint": 0,
    },
    {
        "drone_id": "UAV-05",
        "callsign": "ECHO",
        "system_id": 5,
        "model": "Classified Recon Platform",
        "status": "PATROL",
        "gps_lat": 37.7760, "gps_lon": -122.4170,
        "altitude": 200.0, "battery_pct": 95,
        "speed": 25.0,
        "mission_name": "High-Altitude Surveillance",
        "waypoint_count": 16, "current_waypoint": 7,
    },
]


class DecoyFleet:
    """
    Manages a fleet of decoy drones.
    Each drone has unique characteristics to study attacker target selection.
    """

    def __init__(self):
        self.drones: Dict[str, DecoyDrone] = {}
        self._load()

        # Initialize default fleet if empty
        if not self.drones:
            self._init_default_fleet()

    def _init_default_fleet(self):
        """Initialize the fleet with default drones."""
        for drone_data in DEFAULT_FLEET:
            drone = DecoyDrone(**drone_data)
            drone.last_heartbeat = datetime.now().isoformat()
            self.drones[drone.drone_id] = drone
        self._save()

    def _load(self):
        if os.path.exists(FLEET_STATE_FILE):
            try:
                with open(FLEET_STATE_FILE, 'r') as f:
                    data = json.load(f)
                for did, ddata in data.items():
                    self.drones[did] = DecoyDrone(**ddata)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(FLEET_STATE_FILE), exist_ok=True)
            with open(FLEET_STATE_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.drones.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def get_drone_by_system_id(self, system_id: int) -> DecoyDrone:
        """Find a drone by its MAVLink system_id."""
        for drone in self.drones.values():
            if drone.system_id == system_id:
                return drone
        # Default to first drone
        return list(self.drones.values())[0] if self.drones else None

    def on_attack(self, system_id: int, attack_type: str, attacker_ip: str):
        """Record an attack targeting a specific drone."""
        drone = self.get_drone_by_system_id(system_id)
        if drone:
            drone.is_targeted = True
            drone.target_count += 1
            drone.attacks_received += 1
            if attack_type not in drone.attack_types_received:
                drone.attack_types_received.append(attack_type)
            self._save()

    def clear_target_flags(self):
        """Clear targeting flags (call periodically)."""
        for drone in self.drones.values():
            drone.is_targeted = False
        self._save()

    def simulate_telemetry_update(self):
        """Simulate realistic telemetry changes across the fleet."""
        for drone in self.drones.values():
            if drone.status == "CHARGING":
                drone.battery_pct = min(100, drone.battery_pct + random.randint(0, 2))
                if drone.battery_pct >= 95:
                    drone.status = "PATROL"
                continue

            # Drain battery slowly
            if random.random() < 0.3:
                drone.battery_pct = max(5, drone.battery_pct - 1)

            # Move GPS slightly
            if drone.status in ("PATROL", "MISSION"):
                drone.gps_lat += random.uniform(-0.0005, 0.0005)
                drone.gps_lon += random.uniform(-0.0005, 0.0005)
                drone.heading = (drone.heading + random.randint(-10, 10)) % 360
                drone.speed = max(0, drone.speed + random.uniform(-0.5, 0.5))

                # Advance waypoint
                if drone.waypoint_count > 0 and random.random() < 0.1:
                    drone.current_waypoint = (drone.current_waypoint + 1) % drone.waypoint_count

            # Altitude jitter
            drone.altitude = max(0, drone.altitude + random.uniform(-1, 1))

            # Low battery → land
            if drone.battery_pct <= 15:
                drone.status = "LANDING"
                drone.altitude = max(0, drone.altitude - 5)
                if drone.altitude <= 0:
                    drone.status = "CHARGING"
                    drone.speed = 0

            drone.last_heartbeat = datetime.now().isoformat()

        self._save()

    def get_fleet_status(self) -> List[dict]:
        """Get status of all drones for dashboard."""
        return [asdict(d) for d in self.drones.values()]

    def get_target_analysis(self) -> dict:
        """Analyze which drones attackers prefer to target."""
        total_attacks = sum(d.attacks_received for d in self.drones.values())
        if total_attacks == 0:
            return {"total_attacks": 0, "drones": []}

        analysis = []
        for drone in self.drones.values():
            analysis.append({
                "drone_id": drone.drone_id,
                "callsign": drone.callsign,
                "model": drone.model,
                "attacks_received": drone.attacks_received,
                "attack_share_pct": round(
                    drone.attacks_received / total_attacks * 100, 1
                ) if total_attacks > 0 else 0,
                "attack_types": drone.attack_types_received,
                "most_targeted": drone.attacks_received == max(
                    d.attacks_received for d in self.drones.values()
                ),
            })

        # Sort by attacks received
        analysis.sort(key=lambda x: x["attacks_received"], reverse=True)

        return {
            "total_attacks": total_attacks,
            "fleet_size": len(self.drones),
            "drones": analysis,
        }

    def get_heartbeat_data(self, system_id: int) -> dict:
        """Generate MAVLink heartbeat data for a specific drone."""
        drone = self.get_drone_by_system_id(system_id)
        if not drone:
            return {}

        status_map = {
            "PATROL": 4,    # MAV_STATE_ACTIVE
            "HOVER": 4,     # MAV_STATE_ACTIVE
            "MISSION": 4,   # MAV_STATE_ACTIVE
            "LANDING": 4,   # MAV_STATE_ACTIVE
            "CHARGING": 3,  # MAV_STATE_STANDBY
        }

        return {
            "system_id": drone.system_id,
            "component_id": 1,
            "type": 2,  # quadrotor
            "autopilot": 12,  # PX4
            "base_mode": 129,
            "custom_mode": 0,
            "system_status": status_map.get(drone.status, 0),
            "mavlink_version": 3,
        }


if __name__ == "__main__":
    print("🛩️  Decoy Fleet — Test")

    fleet = DecoyFleet()

    print(f"\n  Fleet size: {len(fleet.drones)}")
    for drone in fleet.drones.values():
        print(f"    {drone.callsign} ({drone.model}) — {drone.status}, "
              f"Alt: {drone.altitude}m, Batt: {drone.battery_pct}%")

    # Simulate an attack on UAV-03
    fleet.on_attack(3, "GPS_SPOOF", "10.0.0.1")
    fleet.on_attack(3, "HIJACK", "10.0.0.1")
    fleet.on_attack(1, "RECON", "10.0.0.2")

    analysis = fleet.get_target_analysis()
    print(f"\n  Target Analysis:")
    for d in analysis["drones"]:
        prefix = "🎯" if d["most_targeted"] else "  "
        print(f"    {prefix} {d['callsign']}: {d['attacks_received']} attacks "
              f"({d['attack_share_pct']}%) — types: {d['attack_types']}")
