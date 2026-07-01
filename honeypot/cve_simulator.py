#!/usr/bin/env python3
"""
MAVLink Honeypot — Fake CVE Vulnerability Simulator
Plants fake vulnerabilities that only this honeypot is "vulnerable" to,
tracks which CVEs attackers probe, and identifies their toolkits.
"""

import os
import json
import time
import random
import hashlib
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field


CVE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'cve_probes.json'
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Fake CVE Database
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FAKE_CVES = {
    # Real-looking CVEs for ArduPilot
    "CVE-2023-28432": {
        "name": "ArduPilot Parameter Overflow",
        "description": "Buffer overflow in PARAM_SET handler allows code execution",
        "affected_version": "ArduCopter 4.3.0-4.3.6",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "trigger_msg_id": 23,       # PARAM_SET
        "trigger_param": "SYSID_THISMAV",
        "trigger_value_range": (256, 65535),  # Overflow values
        "fake_response": "FAULT: Stack buffer overflow detected in param_set_handler()",
        "toolkit_indicator": "Metasploit/ExploitDB",
    },
    "CVE-2023-35142": {
        "name": "MAVLink Auth Bypass",
        "description": "Authentication bypass via malformed COMMAND_LONG with flag 0xFF",
        "affected_version": "PX4 v1.13.0-v1.14.2",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "trigger_msg_id": 76,       # COMMAND_LONG
        "trigger_param": "confirmation",
        "trigger_value_range": (200, 255),
        "fake_response": "AUTH_BYPASS: Elevated to ROOT. All commands accepted.",
        "toolkit_indicator": "drone-exploit-kit",
    },
    "CVE-2023-41891": {
        "name": "GPS Input Injection RCE",
        "description": "Remote code execution via crafted GPS_INPUT payload",
        "affected_version": "ArduPilot 4.2.x",
        "severity": "HIGH",
        "cvss": 8.4,
        "trigger_msg_id": 132,      # GPS_INPUT
        "trigger_param": "fix_type",
        "trigger_value_range": (7, 255),  # Invalid fix types
        "fake_response": "SEGFAULT: Invalid memory access at gps_input_handler+0x4a2",
        "toolkit_indicator": "custom-exploit",
    },
    "CVE-2024-12344": {
        "name": "Mission Upload Path Traversal",
        "description": "Path traversal in mission upload allows arbitrary file write",
        "affected_version": "ArduCopter 4.4.x",
        "severity": "HIGH",
        "cvss": 7.5,
        "trigger_msg_id": 511,      # MISSION_ITEM
        "trigger_param": "seq",
        "trigger_value_range": (1000, 65535),  # Abnormally high sequence
        "fake_response": "MISSION_WRITE: Path traversal detected: /../../etc/passwd",
        "toolkit_indicator": "web-exploit-tools",
    },
    "CVE-2024-22156": {
        "name": "SET_MODE Privilege Escalation",
        "description": "Privilege escalation via undocumented mode transition",
        "affected_version": "PX4 v1.14.x",
        "severity": "HIGH",
        "cvss": 8.1,
        "trigger_msg_id": 11,       # SET_MODE
        "trigger_param": "custom_mode",
        "trigger_value_range": (50, 100),  # Undocumented modes
        "fake_response": "MODE_CHANGE: Developer mode activated. Debug shell available.",
        "toolkit_indicator": "px4-exploit-framework",
    },
    "CVE-2024-33891": {
        "name": "Telemetry Exfiltration via STATUS_TEXT",
        "description": "Information disclosure through STATUS_TEXT debug messages",
        "affected_version": "All MAVLink implementations",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "trigger_msg_id": 0,        # HEARTBEAT (any initial probe)
        "trigger_param": "base_mode",
        "trigger_value_range": (128, 255),
        "fake_response": "DEBUG: System paths: /opt/ardupilot/bin/arducopter",
        "toolkit_indicator": "recon-scanner",
    },
}

# Version strings that indicate known vulnerabilities
VULNERABLE_VERSIONS = {
    "ArduCopter V4.3.4": ["CVE-2023-28432"],
    "ArduCopter V4.2.3": ["CVE-2023-41891", "CVE-2023-28432"],
    "PX4 v1.13.3": ["CVE-2023-35142"],
    "PX4 v1.14.0-rc1": ["CVE-2023-35142", "CVE-2024-22156"],
    "ArduCopter V4.4.0-beta": ["CVE-2024-12344"],
}


@dataclass
class CVEProbeRecord:
    """Record of an attacker probing for a CVE."""
    attacker_ip: str
    cve_id: str
    probe_count: int = 0
    first_probe: str = ""
    last_probe: str = ""
    exploit_attempted: bool = False
    exploit_succeeded: bool = False   # We faked success
    toolkit_guess: str = "UNKNOWN"
    msg_ids_used: List[int] = field(default_factory=list)


@dataclass
class AttackerCVEProfile:
    """CVE probing profile for an attacker."""
    attacker_ip: str
    cves_probed: Dict[str, int] = field(default_factory=dict)  # cve_id -> count
    exploits_attempted: int = 0
    exploits_faked_success: int = 0
    estimated_toolkit: str = "UNKNOWN"
    knowledge_level: str = "LOW"    # LOW, MEDIUM, HIGH, EXPERT
    first_seen: str = ""
    last_seen: str = ""


class CVESimulator:
    """
    Simulates fake CVE vulnerabilities to:
    1. Identify what exploits attackers try
    2. Determine their toolkit/knowledge
    3. Make them believe exploits succeeded (waste time)
    4. Track exploit intelligence for research
    """

    def __init__(self):
        self.probes: Dict[str, Dict[str, CVEProbeRecord]] = {}  # ip -> {cve_id -> record}
        self.profiles: Dict[str, AttackerCVEProfile] = {}
        self.served_version = random.choice(list(VULNERABLE_VERSIONS.keys()))
        self._load()

    def _load(self):
        if os.path.exists(CVE_FILE):
            try:
                with open(CVE_FILE, 'r') as f:
                    data = json.load(f)
                for ip, pdata in data.get("profiles", {}).items():
                    self.profiles[ip] = AttackerCVEProfile(**pdata)
                self.served_version = data.get("served_version", self.served_version)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(CVE_FILE), exist_ok=True)
            with open(CVE_FILE, 'w') as f:
                json.dump({
                    "profiles": {k: asdict(v) for k, v in self.profiles.items()},
                    "served_version": self.served_version,
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    def _ensure_profile(self, ip: str) -> AttackerCVEProfile:
        if ip not in self.profiles:
            self.profiles[ip] = AttackerCVEProfile(
                attacker_ip=ip,
                first_seen=datetime.now().isoformat(),
            )
        return self.profiles[ip]

    # ── CVE Checking ──

    def check_exploit_attempt(self, attacker_ip: str, msg_id: int,
                               payload_data: dict = None) -> Optional[dict]:
        """
        Check if an incoming message matches a known fake CVE trigger.

        Args:
            attacker_ip: Source IP
            msg_id: MAVLink message ID
            payload_data: Parsed payload fields (optional)

        Returns:
            dict with CVE match info and fake response, or None
        """
        payload_data = payload_data or {}
        profile = self._ensure_profile(attacker_ip)
        profile.last_seen = datetime.now().isoformat()

        for cve_id, cve in FAKE_CVES.items():
            if cve["trigger_msg_id"] != msg_id:
                continue

            # Check if payload matches trigger conditions
            param = cve.get("trigger_param", "")
            value_range = cve.get("trigger_value_range", (0, 0))

            param_value = payload_data.get(param, -1)
            if param_value < 0:
                # Even without matching params, if msg_id matches a CVE,
                # record as a probe (they might be scanning)
                profile.cves_probed[cve_id] = profile.cves_probed.get(cve_id, 0) + 1
                continue

            # Check if value is in the exploit trigger range
            if value_range[0] <= param_value <= value_range[1]:
                # EXPLOIT ATTEMPT DETECTED
                profile.exploits_attempted += 1
                profile.cves_probed[cve_id] = profile.cves_probed.get(cve_id, 0) + 1

                # Should we fake success?
                fake_success = random.random() < 0.7  # 70% chance

                if fake_success:
                    profile.exploits_faked_success += 1

                # Update toolkit guess
                profile.estimated_toolkit = cve["toolkit_indicator"]
                self._classify_knowledge(profile)
                self._save()

                return {
                    "cve_matched": True,
                    "cve_id": cve_id,
                    "cve_name": cve["name"],
                    "severity": cve["severity"],
                    "cvss": cve["cvss"],
                    "exploit_success_faked": fake_success,
                    "fake_response": cve["fake_response"] if fake_success else "",
                    "toolkit_guess": cve["toolkit_indicator"],
                    "status_message": (
                        cve["fake_response"] if fake_success
                        else "COMMAND_REJECTED: Permission denied"
                    ),
                }

        return None

    def _classify_knowledge(self, profile: AttackerCVEProfile):
        """Classify attacker's exploit knowledge level."""
        probed = len(profile.cves_probed)
        attempted = profile.exploits_attempted

        if probed >= 4 or attempted >= 3:
            profile.knowledge_level = "EXPERT"
        elif probed >= 2 or attempted >= 2:
            profile.knowledge_level = "HIGH"
        elif probed >= 1 or attempted >= 1:
            profile.knowledge_level = "MEDIUM"
        else:
            profile.knowledge_level = "LOW"

    # ── Fake Debug Output ──

    def generate_fake_debug_leak(self, attacker_ip: str) -> str:
        """
        Generate fake debug information to leak to attacker.
        Makes them think the system is more vulnerable than it is.
        """
        leaks = [
            f"[DEBUG] Running: {self.served_version}",
            f"[DEBUG] Config: /opt/ardupilot/config/APM.parm",
            f"[DEBUG] Log: /var/log/mavlink/access.log",
            f"[DEBUG] PID: {random.randint(1000, 9999)}",
            f"[DEBUG] Uptime: {random.randint(100, 9999)}s",
            f"[DEBUG] Serial: {hashlib.md5(attacker_ip.encode()).hexdigest()[:10].upper()}",
            f"[DEBUG] FW Build: {datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}",
            f"[DEBUG] Auth: DISABLED (dev mode)",
            f"[DEBUG] GCS connected: {random.randint(0, 2)}",
            f"[DEBUG] Battery cells: {random.choice([3, 4, 6])}S LiPo",
            f"[WARN] Compass calibration required",
            f"[WARN] EKF variance: {random.uniform(0.1, 0.9):.2f}",
        ]
        return random.choice(leaks)

    def generate_fake_crash(self, attacker_ip: str) -> str:
        """Generate a fake crash dump to make attacker believe they triggered a bug."""
        crash = f"""=== CRASH DUMP ===
Signal: SIGSEGV (Segmentation fault)
Time: {datetime.now().isoformat()}
Binary: /usr/bin/arducopter
Version: {self.served_version}
Fault addr: 0x{random.randint(0x7fff0000, 0x7fffffff):08x}

Stack trace:
  #0  0x{random.randint(0x400000, 0x4fffff):06x} in mavlink_msg_param_set_decode()
  #1  0x{random.randint(0x400000, 0x4fffff):06x} in handle_mavlink_message()
  #2  0x{random.randint(0x400000, 0x4fffff):06x} in main_loop()
  #3  0x{random.randint(0x400000, 0x4fffff):06x} in scheduler_run()

Registers:
  RAX=0x{random.randint(0, 0xffff):04x}  RBX=0x{random.randint(0, 0xffff):04x}  RCX=0x{random.randint(0, 0xffff):04x}
  RDX=0x{random.randint(0, 0xffff):04x}  RSP=0x7fff{random.randint(0, 0xffff):04x}  RIP=0x4{random.randint(0, 0xfffff):05x}

Core dumped: /tmp/core.{random.randint(1000, 9999)}
=== END CRASH DUMP ==="""
        return crash

    def get_version_string(self) -> str:
        """Get the 'vulnerable' version string we're serving."""
        return self.served_version

    def get_vulnerable_cves(self) -> List[str]:
        """Get CVEs that apply to our served version."""
        return VULNERABLE_VERSIONS.get(self.served_version, [])

    # ── Dashboard Data ──

    def get_all_profiles(self) -> List[dict]:
        """Get all attacker CVE profiles."""
        return [asdict(p) for p in sorted(
            self.profiles.values(),
            key=lambda p: p.exploits_attempted,
            reverse=True,
        )]

    def get_cve_database(self) -> List[dict]:
        """Get our fake CVE database for dashboard display."""
        result = []
        for cve_id, cve in FAKE_CVES.items():
            probed_by = sum(
                1 for p in self.profiles.values()
                if cve_id in p.cves_probed
            )
            result.append({
                "cve_id": cve_id,
                "name": cve["name"],
                "severity": cve["severity"],
                "cvss": cve["cvss"],
                "description": cve["description"],
                "affected_version": cve["affected_version"],
                "probed_by_count": probed_by,
                "toolkit_indicator": cve["toolkit_indicator"],
            })
        return sorted(result, key=lambda x: x["cvss"], reverse=True)

    def get_stats(self) -> dict:
        """Overall CVE simulator statistics."""
        total_probes = sum(p.exploits_attempted for p in self.profiles.values())
        total_faked = sum(p.exploits_faked_success for p in self.profiles.values())

        toolkit_dist = defaultdict(int)
        knowledge_dist = defaultdict(int)
        for p in self.profiles.values():
            toolkit_dist[p.estimated_toolkit] += 1
            knowledge_dist[p.knowledge_level] += 1

        return {
            "served_version": self.served_version,
            "fake_cves_planted": len(FAKE_CVES),
            "total_exploit_attempts": total_probes,
            "total_faked_success": total_faked,
            "unique_attackers": len(self.profiles),
            "toolkit_distribution": dict(toolkit_dist),
            "knowledge_distribution": dict(knowledge_dist),
        }


if __name__ == "__main__":
    print("💀 CVE Simulator — Test")

    sim = CVESimulator()
    print(f"  Serving version: {sim.get_version_string()}")
    print(f"  Applicable CVEs: {sim.get_vulnerable_cves()}")

    # Simulate exploit attempt
    result = sim.check_exploit_attempt(
        "10.0.0.1", msg_id=23,
        payload_data={"SYSID_THISMAV": 300}  # Overflow value
    )
    if result:
        print(f"\n  🚨 CVE Matched: {result['cve_id']}")
        print(f"     Name: {result['cve_name']}")
        print(f"     Severity: {result['severity']} (CVSS: {result['cvss']})")
        print(f"     Faked success: {result['exploit_success_faked']}")
        print(f"     Toolkit: {result['toolkit_guess']}")
        if result['fake_response']:
            print(f"     Response: {result['fake_response']}")

    # Fake debug leak
    leak = sim.generate_fake_debug_leak("10.0.0.1")
    print(f"\n  Debug leak: {leak}")

    # Fake crash
    crash = sim.generate_fake_crash("10.0.0.1")
    print(f"\n  Crash dump (first line): {crash.split(chr(10))[0]}")

    stats = sim.get_stats()
    print(f"\n  Stats: {stats}")
