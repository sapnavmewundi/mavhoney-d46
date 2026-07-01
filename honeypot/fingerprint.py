#!/usr/bin/env python3
"""
Attacker Behavioral Fingerprinting
Identifies returning attackers even across VPN/IP changes
"""

import hashlib
import json
import os
import time
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional


FINGERPRINTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'fingerprints.json'
)


@dataclass
class BehaviorSignature:
    """Behavioral fingerprint of an attacker"""
    fingerprint_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    sessions: int = 0

    # Behavioral signals
    attack_sequence_hash: str = ""     # Hash of preferred attack order
    avg_inter_action_ms: float = 0.0   # Average time between actions
    preferred_attacks: Dict[str, int] = field(default_factory=dict)  # Attack type counts
    first_attack_type: str = ""        # What they always try first
    browser_hash: str = ""             # User-agent + screen info hash
    timezone_offset: int = 0           # Browser timezone

    # Matching metadata
    ips_used: List[str] = field(default_factory=list)
    similarity_matches: List[str] = field(default_factory=list)  # Other fingerprint IDs

    # Classification
    skill_level: str = "UNKNOWN"       # SCRIPT_KIDDIE, INTERMEDIATE, ADVANCED
    threat_score: float = 0.0


class AttackerFingerprinter:
    """Builds and matches behavioral fingerprints"""

    SIMILARITY_THRESHOLD = 0.65  # 65% match = same person

    def __init__(self):
        self.fingerprints: Dict[str, BehaviorSignature] = {}
        self.active_sessions: Dict[str, dict] = {}  # session_id -> session data
        self._load()

    def _load(self):
        """Load fingerprints from disk"""
        if os.path.exists(FINGERPRINTS_FILE):
            try:
                with open(FINGERPRINTS_FILE, 'r') as f:
                    data = json.load(f)
                    for fp_id, fp_data in data.items():
                        self.fingerprints[fp_id] = BehaviorSignature(**fp_data)
            except Exception:
                pass

    def _save(self):
        """Save fingerprints to disk"""
        try:
            os.makedirs(os.path.dirname(FINGERPRINTS_FILE), exist_ok=True)
            with open(FINGERPRINTS_FILE, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.fingerprints.items()},
                    f, indent=2
                )
        except Exception:
            pass

    def start_session(self, session_id: str, ip: str, user_agent: str = "",
                      screen_info: str = "", timezone: int = 0):
        """Start tracking a new attacker session"""
        self.active_sessions[session_id] = {
            "ip": ip,
            "user_agent": user_agent,
            "screen_info": screen_info,
            "timezone": timezone,
            "attack_sequence": [],
            "timestamps": [],
            "start_time": time.time(),
            "browser_hash": hashlib.md5(f"{user_agent}:{screen_info}".encode()).hexdigest()[:12]
        }

    def record_action(self, session_id: str, attack_type: str):
        """Record an attack action in the session"""
        if session_id not in self.active_sessions:
            return

        session = self.active_sessions[session_id]
        session["attack_sequence"].append(attack_type)
        session["timestamps"].append(time.time())

    def finalize_session(self, session_id: str) -> Optional[BehaviorSignature]:
        """Finalize session and build/update fingerprint"""
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions.pop(session_id)

        if len(session["attack_sequence"]) == 0:
            return None

        # Build behavioral signals
        seq = session["attack_sequence"]
        seq_hash = hashlib.md5("|".join(seq).encode()).hexdigest()[:16]

        # Calculate inter-action timing
        timestamps = session["timestamps"]
        if len(timestamps) >= 2:
            deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_delta_ms = sum(deltas) / len(deltas) * 1000
        else:
            avg_delta_ms = 0

        # Count attack preferences
        attack_counts = {}
        for a in seq:
            attack_counts[a] = attack_counts.get(a, 0) + 1

        first_attack = seq[0] if seq else ""

        # Try to match against existing fingerprints
        best_match_id, best_score = self._find_match(
            seq_hash, avg_delta_ms, attack_counts,
            first_attack, session["browser_hash"], session["timezone"]
        )

        now = datetime.now().isoformat()

        if best_match_id and best_score >= self.SIMILARITY_THRESHOLD:
            # Update existing fingerprint
            fp = self.fingerprints[best_match_id]
            fp.last_seen = now
            fp.sessions += 1
            fp.attack_sequence_hash = seq_hash
            fp.avg_inter_action_ms = (fp.avg_inter_action_ms + avg_delta_ms) / 2

            for a, c in attack_counts.items():
                fp.preferred_attacks[a] = fp.preferred_attacks.get(a, 0) + c

            if session["ip"] not in fp.ips_used:
                fp.ips_used.append(session["ip"])

            fp.skill_level = self._classify_skill(fp)
            fp.threat_score = self._calc_threat(fp)
        else:
            # Create new fingerprint
            fp_id = hashlib.md5(f"{session['ip']}:{time.time()}".encode()).hexdigest()[:12]
            fp = BehaviorSignature(
                fingerprint_id=fp_id,
                first_seen=now,
                last_seen=now,
                sessions=1,
                attack_sequence_hash=seq_hash,
                avg_inter_action_ms=avg_delta_ms,
                preferred_attacks=attack_counts,
                first_attack_type=first_attack,
                browser_hash=session["browser_hash"],
                timezone_offset=session["timezone"],
                ips_used=[session["ip"]],
            )
            fp.skill_level = self._classify_skill(fp)
            fp.threat_score = self._calc_threat(fp)
            self.fingerprints[fp_id] = fp

        self._save()
        return fp

    def _find_match(self, seq_hash, avg_delta_ms, attack_counts,
                    first_attack, browser_hash, timezone) -> tuple:
        """Find the most similar existing fingerprint.
        
        Matching factors (TCP/MAVLink-relevant only):
        - Attack sequence hash (30%) — command order pattern
        - First attack type (15%) — initial recon preference
        - Timing cadence (25%) — inter-packet delay pattern (replaces browser hash)
        - Attack vocabulary overlap (20%) — which commands they know
        - Persistence pattern (10%) — session count behavior (replaces timezone)
        """
        best_id = None
        best_score = 0

        for fp_id, fp in self.fingerprints.items():
            score = 0
            factors = 0

            # Sequence similarity (high weight)
            if fp.attack_sequence_hash == seq_hash:
                score += 0.3
            factors += 0.3

            # First attack preference
            if fp.first_attack_type == first_attack:
                score += 0.15
            factors += 0.15

            # Timing cadence similarity (±30%) — replaces browser_hash
            if fp.avg_inter_action_ms > 0 and avg_delta_ms > 0:
                ratio = min(fp.avg_inter_action_ms, avg_delta_ms) / max(fp.avg_inter_action_ms, avg_delta_ms)
                score += 0.25 * ratio
            factors += 0.25

            # Attack vocabulary overlap — replaces timezone
            if fp.preferred_attacks and attack_counts:
                fp_attacks = set(fp.preferred_attacks.keys())
                new_attacks = set(attack_counts.keys())
                if fp_attacks or new_attacks:
                    overlap = len(fp_attacks & new_attacks) / len(fp_attacks | new_attacks)
                    score += 0.2 * overlap
            factors += 0.2

            # Session persistence (returning = stronger match)
            if fp.sessions >= 2:
                score += 0.1
            factors += 0.1

            normalized = score / factors if factors > 0 else 0

            if normalized > best_score:
                best_score = normalized
                best_id = fp_id

        return best_id, best_score

    # ── Attack sophistication weights ──
    ATTACK_SOPHISTICATION = {
        "RECON": 1, "CONTROL": 3, "HIJACK": 5, "GPS_SPOOF": 5,
        "MISSION_INJECT": 6, "CONFIG_ATTACK": 4, "SENSOR_SPOOF": 5,
        "DOS_FLOOD": 2, "UNKNOWN": 1
    }

    def _classify_skill(self, fp: BehaviorSignature) -> str:
        """
        Multi-factor attacker skill classification.
        Considers: timing discipline, attack diversity, sophistication,
        evasion behavior (multi-IP), and session persistence.
        Returns: SCRIPT_KIDDIE | INTERMEDIATE | ADVANCED | APT
        """
        score = 0.0  # 0–100

        attacks = fp.preferred_attacks
        total = sum(attacks.values()) if attacks else 0
        unique = len(attacks)

        # ── Factor 1: Attack diversity (0-20) ──
        score += min(unique * 5, 20)

        # ── Factor 2: Sophistication of chosen attacks (0-25) ──
        if total > 0:
            weighted = sum(
                self.ATTACK_SOPHISTICATION.get(a, 1) * c
                for a, c in attacks.items()
            )
            avg_sophistication = weighted / total  # 1-6 scale
            score += min(avg_sophistication * 4, 25)

        # ── Factor 3: Timing discipline (0-20) ──
        # Consistent timing = automated/skilled; erratic = script kiddie
        if fp.avg_inter_action_ms > 0:
            if fp.avg_inter_action_ms < 200:
                score += 18  # Very fast = automated tooling
            elif fp.avg_inter_action_ms < 1000:
                score += 12  # Fast but manual
            elif fp.avg_inter_action_ms < 5000:
                score += 6   # Slow, methodical
            else:
                score += 2   # Very slow, fumbling

        # ── Factor 4: Persistence / returning sessions (0-20) ──
        score += min(fp.sessions * 4, 20)

        # ── Factor 5: Evasion — multiple IPs (0-15) ──
        ip_count = len(fp.ips_used) if fp.ips_used else 1
        if ip_count >= 4:
            score += 15  # Rotating IPs = evasion
        elif ip_count >= 2:
            score += 8
        else:
            score += 0

        # ── Classify ──
        score = min(score, 100)
        if score >= 70:
            return "APT"
        elif score >= 50:
            return "ADVANCED"
        elif score >= 25:
            return "INTERMEDIATE"
        else:
            return "SCRIPT_KIDDIE"

    def _calc_threat(self, fp: BehaviorSignature) -> float:
        """Calculate threat score 0-100 with skill-weighted factors."""
        score = 0.0

        # Persistence
        score += min(fp.sessions * 8, 25)

        # Attack variety
        score += min(len(fp.preferred_attacks) * 6, 18)

        # Total volume
        total = sum(fp.preferred_attacks.values()) if fp.preferred_attacks else 0
        score += min(total * 1.5, 15)

        # Sophistication of attacks used
        if total > 0:
            weighted = sum(
                self.ATTACK_SOPHISTICATION.get(a, 1) * c
                for a, c in fp.preferred_attacks.items()
            )
            score += min(weighted / total * 3, 12)

        # Multi-IP usage
        score += min(len(fp.ips_used) * 6, 15)

        # Rapid timing = tooling
        if 0 < fp.avg_inter_action_ms < 500:
            score += 10

        # Skill multiplier
        multiplier = {
            "SCRIPT_KIDDIE": 0.55, "INTERMEDIATE": 0.75,
            "ADVANCED": 0.9, "APT": 1.0
        }
        score *= multiplier.get(fp.skill_level, 0.7)

        return round(min(score, 100), 1)

    def get_skill_breakdown(self, fingerprint_id: str) -> dict:
        """Get detailed skill scoring breakdown for a fingerprint."""
        if fingerprint_id not in self.fingerprints:
            return {}
        fp = self.fingerprints[fingerprint_id]
        attacks = fp.preferred_attacks
        total = sum(attacks.values()) if attacks else 0
        unique = len(attacks)

        weighted_soph = 0
        if total > 0:
            weighted_soph = sum(
                self.ATTACK_SOPHISTICATION.get(a, 1) * c
                for a, c in attacks.items()
            ) / total

        return {
            "fingerprint_id": fingerprint_id,
            "skill_level": fp.skill_level,
            "threat_score": fp.threat_score,
            "factors": {
                "attack_diversity": unique,
                "avg_sophistication": round(weighted_soph, 2),
                "timing_avg_ms": round(fp.avg_inter_action_ms, 1),
                "session_count": fp.sessions,
                "ip_count": len(fp.ips_used),
                "total_attacks": total,
            }
        }

    def get_all_fingerprints(self) -> List[dict]:
        """Get all fingerprints for dashboard display"""
        return [asdict(fp) for fp in self.fingerprints.values()]
