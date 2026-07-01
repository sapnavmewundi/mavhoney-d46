#!/usr/bin/env python3
"""
MAVLink Honeypot — Protocol Fuzzing Detector
Detects when attackers are fuzzing the MAVLink protocol through entropy
analysis, mutation tracking, malformation patterns, and sequence anomalies.
"""

import os
import json
import math
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field


FUZZ_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'fuzz_detections.json'
)


@dataclass
class FuzzProfile:
    """Fuzzing detection profile for an attacker."""
    attacker_ip: str
    is_fuzzing: bool = False
    confidence: float = 0.0            # 0-1
    fuzz_type: str = "NONE"            # NONE, RANDOM, MUTATIONAL, SMART, GRAMMAR
    total_anomalies: int = 0
    high_entropy_packets: int = 0
    malformed_packets: int = 0
    invalid_field_packets: int = 0
    sequence_anomalies: int = 0
    mutation_detections: int = 0
    total_packets_analyzed: int = 0
    first_seen: str = ""
    last_seen: str = ""
    estimated_tool: str = "UNKNOWN"    # AFL, Boofuzz, custom, etc.
    anomaly_timeline: List[dict] = field(default_factory=list)


# Known MAVLink message ID ranges
VALID_MSG_IDS = set(range(0, 300)) | set(range(510, 520)) | {
    397, 400, 11000, 11001, 11002
}

# Expected field ranges for common messages
FIELD_RANGES = {
    0: {  # HEARTBEAT
        "type": (0, 26),           # MAV_TYPE enum
        "autopilot": (0, 18),      # MAV_AUTOPILOT enum
        "base_mode": (0, 255),
        "system_status": (0, 8),   # MAV_STATE enum
    },
    76: {  # COMMAND_LONG
        "command": (0, 50000),     # MAV_CMD enum
        "confirmation": (0, 255),
    },
    11: {  # SET_MODE
        "base_mode": (0, 255),
        "custom_mode": (0, 100),
    },
}


class FuzzDetector:
    """
    Detects protocol fuzzing through multiple analysis techniques:
    1. Shannon entropy of payloads (high = random fuzzing)
    2. Invalid field values (out of enum/range)
    3. Packet malformation (bad STX, bad CRC, truncated)
    4. Sequence anomalies (impossible message ordering)
    5. Mutation tracking (small variations = mutational fuzzer)
    """

    # Thresholds
    HIGH_ENTROPY_THRESHOLD = 4.5   # Bits per byte (max 8)
    FUZZ_CONFIDENCE_THRESHOLD = 0.6
    MUTATION_SIMILARITY_THRESHOLD = 0.85  # 85% similar = mutation
    ANOMALY_WINDOW = 100           # Analyze last N packets

    def __init__(self):
        self.profiles: Dict[str, FuzzProfile] = {}
        self.recent_payloads: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=50)
        )
        self.msg_sequences: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self._load()

    def _load(self):
        if os.path.exists(FUZZ_LOG):
            try:
                with open(FUZZ_LOG, 'r') as f:
                    data = json.load(f)
                for ip, pdata in data.items():
                    # Remove anomaly_timeline if too large for reload
                    pdata.pop("anomaly_timeline", None)
                    pdata["anomaly_timeline"] = []
                    self.profiles[ip] = FuzzProfile(**pdata)
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(FUZZ_LOG), exist_ok=True)
            save_data = {}
            for ip, p in self.profiles.items():
                d = asdict(p)
                d["anomaly_timeline"] = d["anomaly_timeline"][-20:]  # Keep last 20
                save_data[ip] = d
            with open(FUZZ_LOG, 'w') as f:
                json.dump(save_data, f, indent=2)
        except Exception:
            pass

    def _ensure_profile(self, ip: str) -> FuzzProfile:
        if ip not in self.profiles:
            self.profiles[ip] = FuzzProfile(
                attacker_ip=ip,
                first_seen=datetime.now().isoformat(),
            )
        return self.profiles[ip]

    # ── Analysis Methods ──

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def _byte_similarity(a: bytes, b: bytes) -> float:
        """Calculate byte-level similarity between two payloads."""
        if not a or not b:
            return 0.0
        min_len = min(len(a), len(b))
        if min_len == 0:
            return 0.0
        matches = sum(1 for i in range(min_len) if a[i] == b[i])
        return matches / max(len(a), len(b))

    def _check_field_ranges(self, msg_id: int, payload: bytes) -> List[str]:
        """Check if payload field values are within valid ranges."""
        violations = []
        if msg_id not in FIELD_RANGES or len(payload) < 6:
            return violations

        # Basic field extraction (simplified for common messages)
        if msg_id == 0 and len(payload) >= 9:  # HEARTBEAT
            mav_type = payload[4]
            autopilot = payload[5]
            system_status = payload[8]

            ranges = FIELD_RANGES[0]
            if not (ranges["type"][0] <= mav_type <= ranges["type"][1]):
                violations.append(f"invalid_mav_type={mav_type}")
            if not (ranges["autopilot"][0] <= autopilot <= ranges["autopilot"][1]):
                violations.append(f"invalid_autopilot={autopilot}")
            if not (ranges["system_status"][0] <= system_status <= ranges["system_status"][1]):
                violations.append(f"invalid_system_status={system_status}")

        return violations

    def _detect_mutations(self, ip: str, payload: bytes) -> bool:
        """Detect mutational fuzzing (payloads with small variations)."""
        recent = self.recent_payloads[ip]
        mutation_found = False

        for prev_payload in recent:
            similarity = self._byte_similarity(payload, prev_payload)
            if self.MUTATION_SIMILARITY_THRESHOLD <= similarity < 1.0:
                mutation_found = True
                break

        recent.append(payload)
        return mutation_found

    # ── Main Analysis Entry Point ──

    def analyze_packet(self, attacker_ip: str, raw_data: bytes,
                       msg_id: int = -1) -> dict:
        """
        Analyze a raw packet for fuzzing indicators.

        Args:
            attacker_ip: Source IP
            raw_data: Raw packet bytes
            msg_id: Parsed message ID (if available)

        Returns:
            Analysis result dict with anomaly details
        """
        profile = self._ensure_profile(attacker_ip)
        profile.total_packets_analyzed += 1
        profile.last_seen = datetime.now().isoformat()

        anomalies = []

        # 1. Entropy analysis
        entropy = self._shannon_entropy(raw_data)
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            anomalies.append({"type": "HIGH_ENTROPY", "value": entropy})
            profile.high_entropy_packets += 1

        # 2. Malformation checks
        if len(raw_data) >= 1:
            stx = raw_data[0]
            if stx not in (0xFE, 0xFD):
                anomalies.append({"type": "BAD_STX", "value": hex(stx)})
                profile.malformed_packets += 1

        if len(raw_data) >= 2:
            payload_len = raw_data[1]
            if stx == 0xFE:  # MAVLink 1.0
                expected_total = 6 + payload_len + 2
                if len(raw_data) > expected_total + 10:
                    anomalies.append({
                        "type": "OVERSIZED",
                        "expected": expected_total,
                        "actual": len(raw_data)
                    })
                    profile.malformed_packets += 1

        # 3. Invalid message ID
        if msg_id >= 0 and msg_id not in VALID_MSG_IDS:
            anomalies.append({"type": "INVALID_MSG_ID", "value": msg_id})
            profile.invalid_field_packets += 1

        # 4. Field range violations
        if msg_id >= 0:
            violations = self._check_field_ranges(msg_id, raw_data)
            if violations:
                anomalies.append({"type": "FIELD_VIOLATION", "fields": violations})
                profile.invalid_field_packets += 1

        # 5. Mutation detection
        if self._detect_mutations(attacker_ip, raw_data):
            anomalies.append({"type": "MUTATION_DETECTED"})
            profile.mutation_detections += 1

        # 6. Sequence anomaly
        if msg_id >= 0:
            self.msg_sequences[attacker_ip].append(msg_id)
            seq = list(self.msg_sequences[attacker_ip])
            if len(seq) >= 5:
                unique_ratio = len(set(seq[-10:])) / min(len(seq), 10)
                if unique_ratio > 0.9 and len(seq) >= 10:
                    anomalies.append({"type": "HIGH_MSG_DIVERSITY",
                                      "unique_ratio": round(unique_ratio, 2)})
                    profile.sequence_anomalies += 1

        # Update anomaly tracking
        profile.total_anomalies += len(anomalies)

        if anomalies:
            profile.anomaly_timeline.append({
                "timestamp": datetime.now().isoformat(),
                "anomalies": [a["type"] for a in anomalies],
            })

        # Classify fuzzing
        self._classify_fuzzing(profile)

        if profile.total_packets_analyzed % 20 == 0:
            self._save()

        return {
            "is_fuzzing": profile.is_fuzzing,
            "confidence": profile.confidence,
            "fuzz_type": profile.fuzz_type,
            "anomalies": anomalies,
            "estimated_tool": profile.estimated_tool,
        }

    def _classify_fuzzing(self, profile: FuzzProfile):
        """Classify fuzzing type and confidence based on accumulated evidence."""
        total = profile.total_packets_analyzed
        if total < 10:
            return

        # Calculate anomaly rates
        entropy_rate = profile.high_entropy_packets / total
        malform_rate = profile.malformed_packets / total
        field_rate = profile.invalid_field_packets / total
        mutation_rate = profile.mutation_detections / total
        sequence_rate = profile.sequence_anomalies / total

        # Overall anomaly rate
        anomaly_rate = profile.total_anomalies / total

        # Confidence calculation
        confidence = 0.0
        confidence += min(entropy_rate * 2, 0.3)
        confidence += min(malform_rate * 3, 0.25)
        confidence += min(field_rate * 2, 0.2)
        confidence += min(mutation_rate * 3, 0.15)
        confidence += min(sequence_rate * 2, 0.1)

        profile.confidence = round(min(confidence, 1.0), 3)
        profile.is_fuzzing = profile.confidence >= self.FUZZ_CONFIDENCE_THRESHOLD

        # Classify type
        if not profile.is_fuzzing:
            profile.fuzz_type = "NONE"
            profile.estimated_tool = "NONE"
        elif mutation_rate > 0.3:
            profile.fuzz_type = "MUTATIONAL"
            profile.estimated_tool = "AFL/libFuzzer-style"
        elif entropy_rate > 0.4:
            profile.fuzz_type = "RANDOM"
            profile.estimated_tool = "Radamsa/zzuf-style"
        elif field_rate > 0.3 and malform_rate < 0.1:
            profile.fuzz_type = "SMART"
            profile.estimated_tool = "Boofuzz/Peach-style"
        elif sequence_rate > 0.2:
            profile.fuzz_type = "GRAMMAR"
            profile.estimated_tool = "Grammar-based fuzzer"
        else:
            profile.fuzz_type = "MIXED"
            profile.estimated_tool = "Custom/hybrid fuzzer"

    # ── Dashboard Data ──

    def get_all_profiles(self) -> List[dict]:
        """Get all fuzz detection profiles."""
        return [asdict(p) for p in sorted(
            self.profiles.values(),
            key=lambda p: p.confidence,
            reverse=True,
        )]

    def get_fuzzers(self) -> List[dict]:
        """Get only confirmed fuzzers."""
        return [asdict(p) for p in self.profiles.values() if p.is_fuzzing]

    def get_stats(self) -> dict:
        """Overall fuzzing detection statistics."""
        total = len(self.profiles)
        fuzzers = sum(1 for p in self.profiles.values() if p.is_fuzzing)
        type_dist = defaultdict(int)
        tool_dist = defaultdict(int)
        for p in self.profiles.values():
            if p.is_fuzzing:
                type_dist[p.fuzz_type] += 1
                tool_dist[p.estimated_tool] += 1

        return {
            "total_analyzed": total,
            "confirmed_fuzzers": fuzzers,
            "fuzz_rate": round(fuzzers / total * 100, 1) if total else 0,
            "type_distribution": dict(type_dist),
            "tool_distribution": dict(tool_dist),
            "total_anomalies": sum(p.total_anomalies for p in self.profiles.values()),
        }


if __name__ == "__main__":
    print("🔬 Fuzz Detector — Test")

    detector = FuzzDetector()

    # Normal packet (MAVLink 1.0 heartbeat)
    normal = bytes([0xFE, 9, 0, 1, 1, 0, 0, 0, 0, 0, 2, 3, 0, 6, 3, 0xAA, 0xBB])
    r = detector.analyze_packet("10.0.0.1", normal, msg_id=0)
    print(f"  Normal packet: fuzzing={r['is_fuzzing']}, anomalies={len(r['anomalies'])}")

    # Random fuzzing (high entropy)
    import random
    for i in range(30):
        fuzz = bytes([random.randint(0, 255) for _ in range(20)])
        r = detector.analyze_packet("10.0.0.2", fuzz, msg_id=random.randint(0, 65535))

    print(f"  Random fuzzer: fuzzing={r['is_fuzzing']}, confidence={r['confidence']:.1%}, type={r['fuzz_type']}")

    # Mutational fuzzing
    base = bytes([0xFE, 9, 0, 1, 1, 0, 0, 0, 0, 0, 2, 3, 0, 6, 3, 0xAA, 0xBB])
    for i in range(30):
        mutant = bytearray(base)
        pos = random.randint(4, len(mutant) - 1)
        mutant[pos] = (mutant[pos] + random.randint(1, 5)) % 256
        r = detector.analyze_packet("10.0.0.3", bytes(mutant), msg_id=0)

    print(f"  Mutational fuzzer: fuzzing={r['is_fuzzing']}, confidence={r['confidence']:.1%}, type={r['fuzz_type']}")

    stats = detector.get_stats()
    print(f"\n  Stats: {stats}")
