#!/usr/bin/env python3
"""
MAVLink Honeypot — MITRE ATT&CK Auto-Mapper
Maps every observed attack to MITRE ATT&CK for ICS techniques and
generates real-time ATT&CK Navigator layers.
"""

import os
import json
import hashlib
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field


MITRE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'mitre_mapping.json'
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MITRE ATT&CK for ICS + Drone-Specific TTP Mapping
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MAVLINK_TO_MITRE = {
    # ── Reconnaissance ──
    "RECON": {
        "techniques": [
            {
                "id": "T0846",
                "name": "Remote System Discovery",
                "tactic": "Discovery",
                "description": "Attacker enumerates drone systems via MAVLink heartbeat/status probing",
            },
            {
                "id": "T0888",
                "name": "Remote System Information Discovery",
                "tactic": "Discovery",
                "description": "Querying system status, version, and capabilities",
            },
        ],
        "kill_chain_phase": "RECONNAISSANCE",
    },

    # ── Control Attempts ──
    "CONTROL": {
        "techniques": [
            {
                "id": "T0858",
                "name": "Change Operating Mode",
                "tactic": "Impair Process Control",
                "description": "Attempting to change drone flight mode (SET_MODE, COMMAND_LONG)",
            },
            {
                "id": "T0855",
                "name": "Unauthorized Command Message",
                "tactic": "Impair Process Control",
                "description": "Sending control commands to manipulate drone behavior",
            },
        ],
        "kill_chain_phase": "EXPLOITATION",
    },

    # ── Hijack ──
    "HIJACK": {
        "techniques": [
            {
                "id": "T0831",
                "name": "Manipulation of Control",
                "tactic": "Impair Process Control",
                "description": "Direct control takeover via attitude/position target messages",
            },
            {
                "id": "T0836",
                "name": "Modify Parameter",
                "tactic": "Inhibit Response Function",
                "description": "Overriding navigation targets to hijack drone flight path",
            },
        ],
        "kill_chain_phase": "COMMAND_AND_CONTROL",
    },

    # ── GPS Spoofing ──
    "GPS_SPOOF": {
        "techniques": [
            {
                "id": "T0830",
                "name": "Manipulation of View",
                "tactic": "Impair Process Control",
                "description": "GPS spoofing via HIL_GPS/GPS_INPUT to feed false position data",
            },
            {
                "id": "T0832",
                "name": "Manipulation of State",
                "tactic": "Impair Process Control",
                "description": "Manipulating drone's perceived state through sensor falsification",
            },
        ],
        "kill_chain_phase": "ACTION_ON_OBJECTIVES",
    },

    # ── Mission Injection ──
    "MISSION_INJECT": {
        "techniques": [
            {
                "id": "T0821",
                "name": "Modify Controller Tasking",
                "tactic": "Execution",
                "description": "Injecting malicious waypoints/missions into drone flight plan",
            },
            {
                "id": "T0873",
                "name": "Project File Infection",
                "tactic": "Persistence",
                "description": "Modifying stored mission files to persistently alter behavior",
            },
        ],
        "kill_chain_phase": "ACTION_ON_OBJECTIVES",
    },

    # ── Configuration Attacks ──
    "CONFIG_ATTACK": {
        "techniques": [
            {
                "id": "T0836",
                "name": "Modify Parameter",
                "tactic": "Inhibit Response Function",
                "description": "Modifying autopilot parameters to weaken safety systems",
            },
            {
                "id": "T0857",
                "name": "System Firmware",
                "tactic": "Persistence",
                "description": "Attempting to modify system configuration for persistent access",
            },
        ],
        "kill_chain_phase": "EXPLOITATION",
    },

    # ── Sensor Spoofing ──
    "SENSOR_SPOOF": {
        "techniques": [
            {
                "id": "T0832",
                "name": "Manipulation of State",
                "tactic": "Impair Process Control",
                "description": "Injecting false sensor data (IMU, vibration) to confuse autopilot",
            },
        ],
        "kill_chain_phase": "ACTION_ON_OBJECTIVES",
    },

    # ── DoS ──
    "DOS_FLOOD": {
        "techniques": [
            {
                "id": "T0814",
                "name": "Denial of Service",
                "tactic": "Inhibit Response Function",
                "description": "Flooding drone with packets to disrupt communications",
            },
        ],
        "kill_chain_phase": "ACTION_ON_OBJECTIVES",
    },
}

# Kill chain phase ordering
KILL_CHAIN_ORDER = [
    "RECONNAISSANCE",
    "WEAPONIZATION",
    "DELIVERY",
    "EXPLOITATION",
    "INSTALLATION",
    "COMMAND_AND_CONTROL",
    "ACTION_ON_OBJECTIVES",
]


@dataclass
class AttackerMITREProfile:
    """MITRE ATT&CK coverage for a specific attacker."""
    attacker_ip: str
    techniques_observed: Dict[str, int] = field(default_factory=dict)  # tech_id -> count
    tactics_observed: Dict[str, int] = field(default_factory=dict)     # tactic -> count
    kill_chain_phases: Dict[str, str] = field(default_factory=dict)    # phase -> first_seen
    current_phase: str = "RECONNAISSANCE"
    phase_progression: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    total_mapped_events: int = 0


class MITREMapper:
    """
    Auto-maps MAVLink honeypot events to MITRE ATT&CK for ICS.
    Tracks per-attacker TTP coverage and kill chain progression.
    """

    def __init__(self):
        self.profiles: Dict[str, AttackerMITREProfile] = {}
        self.global_techniques: Dict[str, int] = defaultdict(int)
        self.global_tactics: Dict[str, int] = defaultdict(int)
        self._load()

    def _load(self):
        """Load existing mappings."""
        if os.path.exists(MITRE_FILE):
            try:
                with open(MITRE_FILE, 'r') as f:
                    data = json.load(f)
                for ip, pdata in data.get("profiles", {}).items():
                    self.profiles[ip] = AttackerMITREProfile(**pdata)
                self.global_techniques = defaultdict(int, data.get("global_techniques", {}))
                self.global_tactics = defaultdict(int, data.get("global_tactics", {}))
            except Exception:
                pass

    def _save(self):
        """Persist MITRE data."""
        try:
            os.makedirs(os.path.dirname(MITRE_FILE), exist_ok=True)
            with open(MITRE_FILE, 'w') as f:
                json.dump({
                    "profiles": {k: asdict(v) for k, v in self.profiles.items()},
                    "global_techniques": dict(self.global_techniques),
                    "global_tactics": dict(self.global_tactics),
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    def map_event(self, attacker_ip: str, intent: str, msg_name: str = "",
                  severity: int = 0) -> dict:
        """
        Map a honeypot event to MITRE ATT&CK techniques.

        Returns:
            dict with mapped techniques, kill chain phase, and attacker profile
        """
        mapping = MAVLINK_TO_MITRE.get(intent, None)
        if not mapping:
            return {"mapped": False, "techniques": []}

        now = datetime.now().isoformat()

        # Create or update attacker profile
        if attacker_ip not in self.profiles:
            self.profiles[attacker_ip] = AttackerMITREProfile(
                attacker_ip=attacker_ip,
                first_seen=now,
                last_seen=now,
            )

        profile = self.profiles[attacker_ip]
        profile.last_seen = now
        profile.total_mapped_events += 1

        # Map techniques
        mapped_techniques = []
        for tech in mapping["techniques"]:
            tech_id = tech["id"]
            tactic = tech["tactic"]

            profile.techniques_observed[tech_id] = \
                profile.techniques_observed.get(tech_id, 0) + 1
            profile.tactics_observed[tactic] = \
                profile.tactics_observed.get(tactic, 0) + 1

            self.global_techniques[tech_id] += 1
            self.global_tactics[tactic] += 1

            mapped_techniques.append({
                "technique_id": tech_id,
                "technique_name": tech["name"],
                "tactic": tactic,
                "description": tech["description"],
            })

        # Update kill chain phase
        phase = mapping["kill_chain_phase"]
        if phase not in profile.kill_chain_phases:
            profile.kill_chain_phases[phase] = now
            profile.phase_progression.append(phase)

        # Track current phase (highest observed)
        for p in reversed(KILL_CHAIN_ORDER):
            if p in profile.kill_chain_phases:
                profile.current_phase = p
                break

        self._save()

        return {
            "mapped": True,
            "intent": intent,
            "techniques": mapped_techniques,
            "kill_chain_phase": phase,
            "attacker_phase": profile.current_phase,
            "total_techniques": len(profile.techniques_observed),
        }

    def get_attacker_profile(self, ip: str) -> Optional[dict]:
        """Get MITRE profile for a specific attacker."""
        if ip not in self.profiles:
            return None
        return asdict(self.profiles[ip])

    def get_attack_matrix(self) -> dict:
        """
        Generate ATT&CK-style matrix data: tactics vs techniques.
        """
        matrix = {}
        all_techniques = set()

        for mapping in MAVLINK_TO_MITRE.values():
            for tech in mapping["techniques"]:
                tactic = tech["tactic"]
                if tactic not in matrix:
                    matrix[tactic] = []
                entry = {
                    "id": tech["id"],
                    "name": tech["name"],
                    "count": self.global_techniques.get(tech["id"], 0),
                }
                if entry not in matrix[tactic]:
                    matrix[tactic].append(entry)
                all_techniques.add(tech["id"])

        return {
            "matrix": matrix,
            "total_techniques_defined": len(all_techniques),
            "total_techniques_observed": sum(
                1 for t in all_techniques
                if self.global_techniques.get(t, 0) > 0
            ),
            "coverage_pct": round(
                sum(1 for t in all_techniques if self.global_techniques.get(t, 0) > 0)
                / len(all_techniques) * 100, 1
            ) if all_techniques else 0,
        }

    def generate_navigator_layer(self) -> dict:
        """
        Generate an ATT&CK Navigator layer JSON for visualization.
        Can be imported directly into MITRE ATT&CK Navigator.
        """
        techniques_list = []
        max_count = max(self.global_techniques.values()) if self.global_techniques else 1

        for tech_id, count in self.global_techniques.items():
            # Find technique name
            name = tech_id
            for mapping in MAVLINK_TO_MITRE.values():
                for tech in mapping["techniques"]:
                    if tech["id"] == tech_id:
                        name = tech["name"]
                        break

            # Score 1-100 based on frequency
            score = round(count / max_count * 100) if max_count else 0

            techniques_list.append({
                "techniqueID": tech_id,
                "tactic": "",
                "color": "",
                "comment": f"Observed {count} times in honeypot",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False,
                "score": score,
            })

        layer = {
            "name": "MAVLink Honeypot — Observed TTPs",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "ics-attack",
            "description": f"Auto-generated from MAVLink honeypot observations. "
                          f"Last updated: {datetime.now().isoformat()}",
            "filters": {"platforms": ["Control Server", "Field Controller/RTU/PLC/IED"]},
            "sorting": 3,
            "layout": {"layout": "side", "aggregateFunction": "average",
                       "showID": True, "showName": True, "showAggregateScores": True},
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Not observed", "color": "#ffffff"},
                {"label": "Low frequency", "color": "#ffcccc"},
                {"label": "High frequency", "color": "#ff6666"},
            ],
            "metadata": [
                {"name": "honeypot", "value": "MAVLink Adaptive Honeypot"},
                {"name": "generated", "value": datetime.now().isoformat()},
            ],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        return layer

    def export_navigator_layer(self, output_path: str = None) -> str:
        """Export ATT&CK Navigator layer to file."""
        if output_path is None:
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'threat_intel_exports'
            )
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, "mitre_navigator_layer.json")

        layer = self.generate_navigator_layer()
        with open(output_path, 'w') as f:
            json.dump(layer, f, indent=2)

        return output_path

    def get_kill_chain_summary(self) -> dict:
        """Get summary of attacker kill chain progression across all attackers."""
        phase_counts = defaultdict(int)
        phase_attackers = defaultdict(set)
        furthest_phases = defaultdict(int)

        for ip, profile in self.profiles.items():
            for phase in profile.kill_chain_phases:
                phase_counts[phase] += 1
                phase_attackers[phase].add(ip)

            # Track where attackers are on the kill chain
            furthest_phases[profile.current_phase] += 1

        return {
            "phase_counts": dict(phase_counts),
            "phase_attacker_counts": {
                k: len(v) for k, v in phase_attackers.items()
            },
            "current_phase_distribution": dict(furthest_phases),
            "kill_chain_order": KILL_CHAIN_ORDER,
            "total_profiled_attackers": len(self.profiles),
        }

    def get_stats(self) -> dict:
        """Overall MITRE mapping statistics."""
        matrix = self.get_attack_matrix()
        return {
            "total_techniques_observed": matrix["total_techniques_observed"],
            "total_techniques_defined": matrix["total_techniques_defined"],
            "coverage_pct": matrix["coverage_pct"],
            "total_mapped_events": sum(
                p.total_mapped_events for p in self.profiles.values()
            ),
            "profiled_attackers": len(self.profiles),
            "top_techniques": sorted(
                self.global_techniques.items(),
                key=lambda x: x[1], reverse=True
            )[:10],
            "top_tactics": sorted(
                self.global_tactics.items(),
                key=lambda x: x[1], reverse=True
            )[:10],
        }


if __name__ == "__main__":
    print("🗺️  MITRE ATT&CK Mapper — Test")

    mapper = MITREMapper()

    # Simulate attack sequence
    events = [
        ("10.0.0.1", "RECON", "HEARTBEAT"),
        ("10.0.0.1", "RECON", "PARAM_REQUEST_LIST"),
        ("10.0.0.1", "CONTROL", "SET_MODE"),
        ("10.0.0.1", "HIJACK", "SET_POSITION_TARGET_LOCAL_NED"),
        ("10.0.0.1", "GPS_SPOOF", "HIL_GPS"),
        ("10.0.0.2", "RECON", "HEARTBEAT"),
        ("10.0.0.2", "DOS_FLOOD", "HEARTBEAT"),
    ]

    for ip, intent, msg in events:
        result = mapper.map_event(ip, intent, msg)
        if result["mapped"]:
            techs = ", ".join(t["technique_id"] for t in result["techniques"])
            print(f"  {ip}: {intent} → {techs} (Phase: {result['kill_chain_phase']})")

    # Show stats
    stats = mapper.get_stats()
    print(f"\n  Coverage: {stats['coverage_pct']}%")
    print(f"  Techniques observed: {stats['total_techniques_observed']}/{stats['total_techniques_defined']}")

    # Export navigator layer
    path = mapper.export_navigator_layer()
    print(f"\n  Navigator layer: {path}")

    # Kill chain summary
    kc = mapper.get_kill_chain_summary()
    print(f"  Kill chain: {kc['current_phase_distribution']}")
