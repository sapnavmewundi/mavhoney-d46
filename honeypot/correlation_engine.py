#!/usr/bin/env python3
"""
MAVLink Honeypot — Attack Correlation Engine
Links related attacks into campaigns and detects coordinated attacks.
"""

import os
import json
import hashlib
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional
from collections import defaultdict


CAMPAIGNS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'campaigns.json'
)


@dataclass
class Campaign:
    """A group of correlated attack events."""
    campaign_id: str = ""
    name: str = ""
    status: str = "ACTIVE"           # ACTIVE, DORMANT, CONCLUDED
    first_seen: str = ""
    last_seen: str = ""
    duration_hours: float = 0.0

    # Participants
    attacker_ips: List[str] = field(default_factory=list)
    fingerprint_ids: List[str] = field(default_factory=list)

    # Attack info
    attack_types: List[str] = field(default_factory=list)
    total_events: int = 0
    peak_severity: int = 0
    event_ids: List[str] = field(default_factory=list)

    # Classification
    is_coordinated: bool = False      # Multiple IPs, similar timing
    campaign_type: str = "UNKNOWN"    # SCAN, TARGETED, BRUTE_FORCE, APT
    threat_level: str = "LOW"         # LOW, MEDIUM, HIGH, CRITICAL


class AttackCorrelator:
    """
    Correlates attack events into campaigns.

    Correlation rules:
    1. Same IP attacks within a time window → same campaign
    2. Same fingerprint across IPs → same campaign
    3. Similar attack patterns within a time window → coordinated
    """

    # Time window for linking events (6 hours)
    CORRELATION_WINDOW_SEC = 6 * 3600
    # Time before marking a campaign dormant (24 hours)
    DORMANT_THRESHOLD_SEC = 24 * 3600

    def __init__(self):
        self.campaigns: Dict[str, Campaign] = {}
        self.ip_to_campaign: Dict[str, str] = {}  # IP → active campaign_id
        self.fp_to_campaign: Dict[str, str] = {}  # fingerprint_id → campaign_id
        self._load()

    def _load(self):
        """Load campaigns from disk."""
        if os.path.exists(CAMPAIGNS_FILE):
            try:
                with open(CAMPAIGNS_FILE, 'r') as f:
                    data = json.load(f)
                for cid, cdata in data.items():
                    self.campaigns[cid] = Campaign(**cdata)
                    # Rebuild lookup indices
                    for ip in cdata.get("attacker_ips", []):
                        self.ip_to_campaign[ip] = cid
                    for fp_id in cdata.get("fingerprint_ids", []):
                        self.fp_to_campaign[fp_id] = cid
            except Exception:
                pass

    def _save(self):
        """Persist campaigns to disk."""
        try:
            os.makedirs(os.path.dirname(CAMPAIGNS_FILE), exist_ok=True)
            with open(CAMPAIGNS_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.campaigns.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def correlate_event(self, event: dict) -> Campaign:
        """
        Process an attack event and assign it to a campaign.

        Args:
            event: dict with keys: attacker_ip, intent, severity, timestamp,
                   msg_name, fingerprint_id (optional)

        Returns:
            The Campaign the event was assigned to.
        """
        ip = event.get("attacker_ip", "unknown")
        intent = event.get("intent", "UNKNOWN")
        severity = event.get("severity", 1)
        timestamp = event.get("timestamp", datetime.now().isoformat())
        fp_id = event.get("fingerprint_id", "")
        event_id = event.get("event_id", hashlib.md5(
            f"{ip}:{timestamp}:{intent}".encode()
        ).hexdigest()[:12])

        now = time.time()
        campaign = None

        # Rule 1: Check if IP is part of an active campaign
        if ip in self.ip_to_campaign:
            cid = self.ip_to_campaign[ip]
            if cid in self.campaigns:
                c = self.campaigns[cid]
                # Check if within time window
                try:
                    last = datetime.fromisoformat(c.last_seen)
                    age = (datetime.now() - last).total_seconds()
                    if age < self.CORRELATION_WINDOW_SEC:
                        campaign = c
                except Exception:
                    campaign = c

        # Rule 2: Check if fingerprint is linked to a campaign
        if campaign is None and fp_id and fp_id in self.fp_to_campaign:
            cid = self.fp_to_campaign[fp_id]
            if cid in self.campaigns:
                campaign = self.campaigns[cid]

        # Rule 3: No match → create new campaign
        if campaign is None:
            cid = hashlib.md5(f"{ip}:{now}".encode()).hexdigest()[:12]
            campaign = Campaign(
                campaign_id=cid,
                name=self._generate_name(intent, ip),
                first_seen=timestamp,
                status="ACTIVE"
            )
            self.campaigns[cid] = campaign

        # Update campaign with this event
        campaign.last_seen = timestamp
        campaign.total_events += 1
        campaign.peak_severity = max(campaign.peak_severity, severity)

        if ip not in campaign.attacker_ips:
            campaign.attacker_ips.append(ip)
        if intent not in campaign.attack_types:
            campaign.attack_types.append(intent)
        if fp_id and fp_id not in campaign.fingerprint_ids:
            campaign.fingerprint_ids.append(fp_id)
        if event_id not in campaign.event_ids:
            campaign.event_ids.append(event_id)

        # Update indices
        self.ip_to_campaign[ip] = campaign.campaign_id
        if fp_id:
            self.fp_to_campaign[fp_id] = campaign.campaign_id

        # Recalculate campaign properties
        self._reclassify(campaign)
        self._save()

        return campaign

    def _generate_name(self, intent: str, ip: str) -> str:
        """Generate a human-readable campaign name."""
        intent_names = {
            "RECON": "Reconnaissance",
            "CONTROL": "Control Attempt",
            "HIJACK": "Hijack Operation",
            "GPS_SPOOF": "GPS Spoofing",
            "MISSION_INJECT": "Mission Injection",
            "CONFIG_ATTACK": "Config Attack",
            "SENSOR_SPOOF": "Sensor Spoofing",
            "DOS_FLOOD": "DoS Flood",
        }
        base = intent_names.get(intent, "Unknown")
        short_ip = ip.split(".")[-1] if "." in ip else ip[:6]
        return f"{base} #{short_ip}"

    def _reclassify(self, campaign: Campaign):
        """Reclassify campaign type and threat level."""
        c = campaign

        # Duration
        try:
            first = datetime.fromisoformat(c.first_seen)
            last = datetime.fromisoformat(c.last_seen)
            c.duration_hours = round((last - first).total_seconds() / 3600, 2)
        except Exception:
            pass

        # Coordinated detection
        c.is_coordinated = len(c.attacker_ips) >= 2

        # Campaign type
        types = set(c.attack_types)
        if types == {"RECON"} or (len(types) == 1 and "RECON" in types):
            c.campaign_type = "SCAN"
        elif "DOS_FLOOD" in types:
            c.campaign_type = "BRUTE_FORCE"
        elif c.duration_hours > 24 and c.total_events > 20:
            c.campaign_type = "APT"
        elif len(types) >= 3:
            c.campaign_type = "TARGETED"
        else:
            c.campaign_type = "OPPORTUNISTIC"

        # Threat level
        if c.peak_severity >= 9 or c.campaign_type == "APT":
            c.threat_level = "CRITICAL"
        elif c.peak_severity >= 7 or c.is_coordinated:
            c.threat_level = "HIGH"
        elif c.peak_severity >= 4 or c.total_events >= 10:
            c.threat_level = "MEDIUM"
        else:
            c.threat_level = "LOW"

        # Status
        try:
            last = datetime.fromisoformat(c.last_seen)
            age = (datetime.now() - last).total_seconds()
            if age > self.DORMANT_THRESHOLD_SEC:
                c.status = "DORMANT"
        except Exception:
            pass

    def detect_coordinated(self, window_minutes: int = 30) -> List[dict]:
        """
        Detect potential coordinated attacks: different IPs attacking
        within a short time window.

        Returns list of coordinated groups.
        """
        window_sec = window_minutes * 60
        coordinated = []

        active = [c for c in self.campaigns.values() if c.status == "ACTIVE"]
        for i, c1 in enumerate(active):
            for c2 in active[i+1:]:
                try:
                    t1 = datetime.fromisoformat(c1.last_seen)
                    t2 = datetime.fromisoformat(c2.last_seen)
                    overlap = abs((t1 - t2).total_seconds())

                    if overlap < window_sec:
                        # Check for overlapping attack types
                        shared_types = set(c1.attack_types) & set(c2.attack_types)
                        if shared_types:
                            coordinated.append({
                                "campaign_ids": [c1.campaign_id, c2.campaign_id],
                                "shared_attack_types": list(shared_types),
                                "time_delta_sec": round(overlap),
                                "combined_ips": list(set(c1.attacker_ips + c2.attacker_ips)),
                            })
                except Exception:
                    continue

        return coordinated

    def get_campaigns(self, status: str = None) -> List[dict]:
        """Get all campaigns, optionally filtered by status."""
        campaigns = list(self.campaigns.values())
        if status:
            campaigns = [c for c in campaigns if c.status == status]

        # Sort by last_seen, newest first
        campaigns.sort(key=lambda c: c.last_seen, reverse=True)
        return [asdict(c) for c in campaigns]

    def get_campaign(self, campaign_id: str) -> Optional[dict]:
        """Get a specific campaign by ID."""
        c = self.campaigns.get(campaign_id)
        return asdict(c) if c else None

    def get_summary(self) -> dict:
        """Get campaign summary statistics."""
        active = sum(1 for c in self.campaigns.values() if c.status == "ACTIVE")
        dormant = sum(1 for c in self.campaigns.values() if c.status == "DORMANT")
        total_events = sum(c.total_events for c in self.campaigns.values())
        coordinated = sum(1 for c in self.campaigns.values() if c.is_coordinated)

        threat_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for c in self.campaigns.values():
            threat_counts[c.threat_level] += 1
            type_counts[c.campaign_type] += 1

        return {
            "total_campaigns": len(self.campaigns),
            "active": active,
            "dormant": dormant,
            "coordinated": coordinated,
            "total_events": total_events,
            "threat_levels": dict(threat_counts),
            "campaign_types": dict(type_counts),
        }


if __name__ == "__main__":
    print("🔗 Attack Correlator — Standalone Test")

    correlator = AttackCorrelator()

    # Simulate events from the same IP
    events = [
        {"attacker_ip": "192.168.1.100", "intent": "RECON", "severity": 1,
         "timestamp": datetime.now().isoformat()},
        {"attacker_ip": "192.168.1.100", "intent": "HIJACK", "severity": 8,
         "timestamp": datetime.now().isoformat()},
        {"attacker_ip": "10.0.0.50", "intent": "GPS_SPOOF", "severity": 9,
         "timestamp": datetime.now().isoformat()},
    ]

    for evt in events:
        campaign = correlator.correlate_event(evt)
        print(f"\n  Event: {evt['attacker_ip']} / {evt['intent']}")
        print(f"    → Campaign: {campaign.name} ({campaign.campaign_id})")
        print(f"    → Type: {campaign.campaign_type}, Threat: {campaign.threat_level}")

    print(f"\n📊 Summary: {json.dumps(correlator.get_summary(), indent=2)}")
