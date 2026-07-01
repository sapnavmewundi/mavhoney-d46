#!/usr/bin/env python3
"""
MAVLink Honeypot — Canary Token Engine
Plants trackable traps in honeypot responses to detect human operators,
identify tool reuse, and trace attacker infrastructure.
"""

import os
import json
import time
import hashlib
import random
import string
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional


CANARY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'canary_tokens.json'
)


@dataclass
class CanaryToken:
    """A trackable token embedded in honeypot responses."""
    token_id: str
    token_type: str           # GPS_COORD, FIRMWARE_URL, PARAM_VALUE, MISSION_FILE
    value: str                # The actual canary value served
    attacker_ip: str          # Who received this token
    created: str              # When it was served
    triggered: bool = False   # Has the token been accessed/reused?
    trigger_time: str = ""    # When it was triggered
    trigger_source: str = ""  # Who/what triggered it
    trigger_count: int = 0    # How many times triggered
    metadata: dict = field(default_factory=dict)


class CanaryTokenEngine:
    """
    Generates and tracks canary tokens embedded in honeypot responses.

    Token Types:
    1. GPS_COORD     — Unique coordinates per attacker; if looked up = human confirmed
    2. FIRMWARE_URL  — Fake firmware update URLs; any fetch = tool/human detected
    3. PARAM_VALUE   — Unique parameter values; reuse on other systems = tracked
    4. MISSION_FILE  — Fake mission files with embedded identifiers
    5. SERIAL_NUMBER — Unique drone serial number per connection
    6. VERSION_STRING — Unique version identifiers to track tool propagation
    """

    # Canary coordinate zones — real-looking but in uninhabited areas
    CANARY_ZONES = [
        (71.7, -42.6, "Greenland Ice Sheet"),      # Remote Greenland
        (-54.8, -68.3, "Tierra del Fuego"),         # Patagonia
        (78.2, 15.6, "Svalbard"),                   # Arctic Norway
        (-72.0, 2.5, "Queen Maud Land"),            # Antarctica
        (48.9, 87.5, "Altai Mountains"),            # Central Asia steppe
    ]

    # Fake firmware version templates
    FIRMWARE_TEMPLATES = [
        "ArduCopter V4.{minor}.{patch}-{token}",
        "PX4 v1.{minor}.{patch}-rc{token}",
        "BetaFlight {major}.{minor}.{patch}-dev{token}",
    ]

    def __init__(self):
        self.tokens: Dict[str, CanaryToken] = {}
        self.ip_tokens: Dict[str, List[str]] = {}  # ip -> [token_ids]
        self._load()

    def _load(self):
        """Load existing tokens."""
        if os.path.exists(CANARY_FILE):
            try:
                with open(CANARY_FILE, 'r') as f:
                    data = json.load(f)
                for tid, tdata in data.items():
                    self.tokens[tid] = CanaryToken(**tdata)
                    ip = tdata.get("attacker_ip", "")
                    if ip not in self.ip_tokens:
                        self.ip_tokens[ip] = []
                    self.ip_tokens[ip].append(tid)
            except Exception:
                pass

    def _save(self):
        """Persist tokens to disk."""
        try:
            os.makedirs(os.path.dirname(CANARY_FILE), exist_ok=True)
            with open(CANARY_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.tokens.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def _gen_id(self, prefix: str = "CAN") -> str:
        """Generate a short unique token ID."""
        rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"{prefix}-{rand}"

    # ── Token Generators ──

    def generate_gps_canary(self, attacker_ip: str) -> dict:
        """
        Generate unique GPS coordinates for this attacker.
        Coordinates are in real-looking but uninhabited zones.
        Each attacker gets a unique micro-offset so we can identify them.
        """
        zone = random.choice(self.CANARY_ZONES)
        base_lat, base_lon, zone_name = zone

        # Unique micro-offset per attacker (±0.001° ≈ 100m)
        ip_hash = int(hashlib.md5(attacker_ip.encode()).hexdigest()[:8], 16)
        lat_offset = (ip_hash % 1000) / 1_000_000  # ~0.1m precision
        lon_offset = ((ip_hash >> 16) % 1000) / 1_000_000

        canary_lat = base_lat + lat_offset
        canary_lon = base_lon + lon_offset

        token_id = self._gen_id("GPS")
        token = CanaryToken(
            token_id=token_id,
            token_type="GPS_COORD",
            value=f"{canary_lat:.6f},{canary_lon:.6f}",
            attacker_ip=attacker_ip,
            created=datetime.now().isoformat(),
            metadata={
                "zone": zone_name,
                "lat": canary_lat,
                "lon": canary_lon,
                "purpose": "If coordinates are looked up on maps, attacker is human",
            }
        )

        self.tokens[token_id] = token
        self.ip_tokens.setdefault(attacker_ip, []).append(token_id)
        self._save()

        return {
            "lat": canary_lat,
            "lon": canary_lon,
            "token_id": token_id,
        }

    def generate_firmware_canary(self, attacker_ip: str) -> dict:
        """
        Generate a unique firmware version string.
        If this version string appears in any other context, we know it leaked.
        """
        token_id = self._gen_id("FW")
        short_hash = hashlib.md5(
            f"{attacker_ip}:{time.time()}".encode()
        ).hexdigest()[:6]

        template = random.choice(self.FIRMWARE_TEMPLATES)
        version = template.format(
            major=random.randint(3, 5),
            minor=random.randint(0, 9),
            patch=random.randint(0, 99),
            token=short_hash,
        )

        token = CanaryToken(
            token_id=token_id,
            token_type="FIRMWARE_URL",
            value=version,
            attacker_ip=attacker_ip,
            created=datetime.now().isoformat(),
            metadata={
                "version_string": version,
                "unique_hash": short_hash,
                "purpose": "Track firmware version reuse/propagation",
            }
        )

        self.tokens[token_id] = token
        self.ip_tokens.setdefault(attacker_ip, []).append(token_id)
        self._save()

        return {"version": version, "token_id": token_id}

    def generate_param_canary(self, attacker_ip: str, param_name: str = "BATT_CAPACITY") -> dict:
        """
        Generate a unique parameter value for this attacker.
        If the value appears on another system, the attacker reused our data.
        """
        token_id = self._gen_id("PAR")
        ip_hash = int(hashlib.md5(attacker_ip.encode()).hexdigest()[:4], 16)

        # Embed token in realistic parameter values
        canary_values = {
            "BATT_CAPACITY": 3200 + (ip_hash % 800),       # 3200-4000 mAh
            "WPNAV_SPEED": 500 + (ip_hash % 500),          # 500-1000 cm/s
            "INS_ACCOFFS_X": round(0.01 + (ip_hash % 100) / 10000, 4),
            "COMPASS_OFS_X": round((ip_hash % 200) - 100 + 0.37, 2),
            "SERIAL0_BAUD": [57, 115, 230, 460, 921][ip_hash % 5],
        }

        value = canary_values.get(param_name, 3200 + (ip_hash % 800))

        token = CanaryToken(
            token_id=token_id,
            token_type="PARAM_VALUE",
            value=str(value),
            attacker_ip=attacker_ip,
            created=datetime.now().isoformat(),
            metadata={
                "param_name": param_name,
                "param_value": value,
                "purpose": "Track parameter value reuse on other systems",
            }
        )

        self.tokens[token_id] = token
        self.ip_tokens.setdefault(attacker_ip, []).append(token_id)
        self._save()

        return {"param_name": param_name, "value": value, "token_id": token_id}

    def generate_serial_canary(self, attacker_ip: str) -> dict:
        """Generate a unique drone serial number for tracking."""
        token_id = self._gen_id("SER")
        ip_hash = hashlib.md5(attacker_ip.encode()).hexdigest()[:8].upper()
        serial = f"DJIF{ip_hash}M4P"

        token = CanaryToken(
            token_id=token_id,
            token_type="SERIAL_NUMBER",
            value=serial,
            attacker_ip=attacker_ip,
            created=datetime.now().isoformat(),
            metadata={"serial": serial}
        )

        self.tokens[token_id] = token
        self.ip_tokens.setdefault(attacker_ip, []).append(token_id)
        self._save()

        return {"serial": serial, "token_id": token_id}

    # ── Token Trigger Detection ──

    def check_token(self, value: str, source: str = "unknown") -> Optional[CanaryToken]:
        """
        Check if a value matches any canary token.
        If found, mark it as triggered.
        """
        for token in self.tokens.values():
            if token.value == value or value in token.value:
                token.triggered = True
                token.trigger_count += 1
                token.trigger_time = datetime.now().isoformat()
                token.trigger_source = source
                self._save()
                return token
        return None

    def check_param_reuse(self, param_name: str, param_value, source_ip: str) -> Optional[dict]:
        """
        Check if a parameter value was previously served as a canary.
        If source_ip differs from original → confirmed reuse/propagation.
        """
        for token in self.tokens.values():
            if token.token_type != "PARAM_VALUE":
                continue
            meta = token.metadata
            if (meta.get("param_name") == param_name and
                    str(meta.get("param_value")) == str(param_value)):
                if token.attacker_ip != source_ip:
                    # Different IP using our canary value = confirmed reuse
                    token.triggered = True
                    token.trigger_count += 1
                    token.trigger_time = datetime.now().isoformat()
                    token.trigger_source = source_ip
                    self._save()
                    return {
                        "alert": "CANARY_REUSE_DETECTED",
                        "original_attacker": token.attacker_ip,
                        "reuse_source": source_ip,
                        "param": param_name,
                        "token_id": token.token_id,
                    }
        return None

    # ── Analytics ──

    def get_all_tokens(self) -> List[dict]:
        """Get all tokens for dashboard display."""
        return [asdict(t) for t in sorted(
            self.tokens.values(),
            key=lambda t: t.created,
            reverse=True,
        )]

    def get_triggered_tokens(self) -> List[dict]:
        """Get only triggered tokens."""
        return [asdict(t) for t in self.tokens.values() if t.triggered]

    def get_stats(self) -> dict:
        """Get canary token statistics."""
        total = len(self.tokens)
        triggered = sum(1 for t in self.tokens.values() if t.triggered)
        by_type = {}
        for t in self.tokens.values():
            by_type[t.token_type] = by_type.get(t.token_type, 0) + 1

        return {
            "total_tokens": total,
            "triggered": triggered,
            "trigger_rate": round(triggered / total * 100, 1) if total else 0,
            "by_type": by_type,
            "unique_attackers": len(self.ip_tokens),
        }

    def get_tokens_for_ip(self, ip: str) -> List[dict]:
        """Get all tokens served to a specific attacker."""
        token_ids = self.ip_tokens.get(ip, [])
        return [asdict(self.tokens[tid]) for tid in token_ids if tid in self.tokens]


if __name__ == "__main__":
    print("🪤 Canary Token Engine — Test")

    engine = CanaryTokenEngine()

    # Generate canaries
    gps = engine.generate_gps_canary("192.168.1.100")
    print(f"  GPS Canary: {gps['lat']:.6f}, {gps['lon']:.6f}")

    fw = engine.generate_firmware_canary("192.168.1.100")
    print(f"  Firmware Canary: {fw['version']}")

    param = engine.generate_param_canary("192.168.1.100")
    print(f"  Param Canary: {param['param_name']}={param['value']}")

    serial = engine.generate_serial_canary("192.168.1.100")
    print(f"  Serial Canary: {serial['serial']}")

    # Check reuse from different IP
    reuse = engine.check_param_reuse("BATT_CAPACITY", param['value'], "10.0.0.50")
    if reuse:
        print(f"\n  🚨 CANARY TRIGGERED: {reuse['alert']}")
        print(f"     Original: {reuse['original_attacker']} → Reused by: {reuse['reuse_source']}")

    stats = engine.get_stats()
    print(f"\n  Stats: {stats}")
