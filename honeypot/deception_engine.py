#!/usr/bin/env python3
"""
Deception Scoring Engine
Measures how effectively the honeypot is fooling each attacker in real-time
"""

import time
import json
import os
from dataclasses import dataclass, asdict, field
from typing import Dict, List
from datetime import datetime


SCORES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'deception_scores.json'
)


@dataclass
class DeceptionProfile:
    """Per-attacker deception effectiveness profile"""
    attacker_ip: str
    # Initial score = neutral baseline (no signals yet).
    # Updated dynamically as positive/negative signals accumulate.
    score: float = 0.0               # 0-100 deception score, starts at 0 (no data)
    confidence: str = "LOW"          # LOW, MEDIUM, HIGH
    first_seen: str = ""
    last_seen: str = ""

    # Positive signals (attacker is being fooled)
    session_duration_sec: float = 0  # Longer = more fooled
    total_commands_sent: int = 0     # More commands = believes it
    follow_up_attacks: int = 0       # Tried multiple attack types
    returned_sessions: int = 0       # Came back = fully deceived
    gps_override_attempts: int = 0   # Tried to override fake GPS = buying it

    # Negative signals (attacker suspects honeypot)
    rapid_disconnect: int = 0        # Quick disconnects = suspicious
    probe_only_sessions: int = 0     # Only sent heartbeats = testing
    pattern_testing: int = 0         # Sent same msg repeatedly = fingerprinting

    # Derived
    engagement_level: str = "NONE"   # NONE, CURIOUS, ENGAGED, COMMITTED, DEDICATED


class DeceptionScorer:
    """Real-time deception score calculator"""

    def __init__(self):
        self.profiles: Dict[str, DeceptionProfile] = {}
        self.session_starts: Dict[str, float] = {}  # session_id -> start time
        self.session_commands: Dict[str, List[str]] = {}
        self._load()

    def _load(self):
        if os.path.exists(SCORES_FILE):
            try:
                with open(SCORES_FILE, 'r') as f:
                    data = json.load(f)
                    for ip, d in data.items():
                        self.profiles[ip] = DeceptionProfile(**d)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(SCORES_FILE), exist_ok=True)
            with open(SCORES_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.profiles.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def on_connect(self, session_id: str, ip: str):
        """Called when an attacker connects"""
        self.session_starts[session_id] = time.time()
        self.session_commands[session_id] = []

        if ip not in self.profiles:
            self.profiles[ip] = DeceptionProfile(
                attacker_ip=ip,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat()
            )
        else:
            self.profiles[ip].returned_sessions += 1
            self.profiles[ip].last_seen = datetime.now().isoformat()

    def on_command(self, session_id: str, ip: str, msg_name: str, intent: str):
        """Called when attacker sends a command"""
        if ip not in self.profiles:
            self.on_connect(session_id, ip)

        profile = self.profiles[ip]
        profile.total_commands_sent += 1
        profile.last_seen = datetime.now().isoformat()

        if session_id in self.session_commands:
            self.session_commands[session_id].append(intent)

        # Track specific behaviors
        if intent == "GPS_SPOOF":
            profile.gps_override_attempts += 1

        # Check for pattern testing (same msg 5+ times)
        cmds = self.session_commands.get(session_id, [])
        if len(cmds) >= 5 and len(set(cmds[-5:])) == 1:
            profile.pattern_testing += 1

        # Count unique attack types
        unique_intents = set(cmds)
        if len(unique_intents) >= 2:
            profile.follow_up_attacks = len(unique_intents)

        self._recalculate(ip)

    def on_disconnect(self, session_id: str, ip: str):
        """Called when attacker disconnects"""
        if session_id in self.session_starts:
            duration = time.time() - self.session_starts[session_id]
            cmds = self.session_commands.get(session_id, [])

            if ip in self.profiles:
                profile = self.profiles[ip]
                profile.session_duration_sec = max(profile.session_duration_sec, duration)

                # Rapid disconnect = suspicious
                if duration < 3 and len(cmds) <= 1:
                    profile.rapid_disconnect += 1

                # Probe-only session
                if all(c == "RECON" for c in cmds) and len(cmds) <= 3:
                    profile.probe_only_sessions += 1

                self._recalculate(ip)

            self.session_starts.pop(session_id, None)
            self.session_commands.pop(session_id, None)

        self._save()

    def _recalculate(self, ip: str):
        """Recalculate deception score for an attacker"""
        if ip not in self.profiles:
            return

        p = self.profiles[ip]
        score = 50.0  # Base score

        # Positive signals (attacker is fooled)
        if p.session_duration_sec > 60:
            score += 10
        if p.session_duration_sec > 180:
            score += 10

        if p.total_commands_sent > 5:
            score += 8
        if p.total_commands_sent > 20:
            score += 7

        if p.follow_up_attacks >= 2:
            score += 8
        if p.follow_up_attacks >= 4:
            score += 7

        if p.returned_sessions >= 1:
            score += 12
        if p.returned_sessions >= 3:
            score += 8

        if p.gps_override_attempts >= 2:
            score += 5

        # Negative signals (attacker suspects) - use diminishing returns with caps
        score -= min(p.rapid_disconnect * 3, 15)
        score -= min(p.probe_only_sessions * 2, 12)
        score -= min(p.pattern_testing * 1.5, 10)

        # Clamp
        p.score = round(max(0, min(100, score)), 1)

        # Confidence
        data_points = p.total_commands_sent + p.returned_sessions
        if data_points >= 15:
            p.confidence = "HIGH"
        elif data_points >= 5:
            p.confidence = "MEDIUM"
        else:
            p.confidence = "LOW"

        # Engagement level
        if p.total_commands_sent == 0:
            p.engagement_level = "NONE"
        elif p.total_commands_sent <= 3 and p.returned_sessions == 0:
            p.engagement_level = "CURIOUS"
        elif p.follow_up_attacks >= 2:
            p.engagement_level = "ENGAGED"
        elif p.returned_sessions >= 1:
            p.engagement_level = "COMMITTED"
        if p.returned_sessions >= 3 and p.total_commands_sent >= 20:
            p.engagement_level = "DEDICATED"

    def get_all_scores(self) -> List[dict]:
        """Get all scores for dashboard"""
        return [asdict(p) for p in self.profiles.values()]

    def get_average_score(self) -> float:
        """Average deception score across all attackers"""
        if not self.profiles:
            return 0
        return round(sum(p.score for p in self.profiles.values()) / len(self.profiles), 1)
