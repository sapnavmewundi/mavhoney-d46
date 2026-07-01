#!/usr/bin/env python3
"""
MAVLink Honeypot — Replay Attack Detector
Detects replay attacks using sequence number tracking and payload hashing.
Flags duplicate packets based on (sys_id, comp_id, seq) tuples and
SHA-256 payload hashes within a configurable time window.
"""

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.logger import get_logger

logger = get_logger("replay_detector")


@dataclass
class ReplayStats:
    """Statistics for replay detection per attacker."""
    total_packets: int = 0
    replays_detected: int = 0
    duplicate_payloads: int = 0
    sequence_anomalies: int = 0
    last_seen: float = 0.0


class ReplayDetector:
    """
    Detects replay attacks in MAVLink traffic.

    Detection methods:
    1. **Sequence tracking**: MAVLink seq numbers should increment monotonically
       (0-255 wrapping). Repeated or regressing seq numbers indicate replay.
    2. **Payload hashing**: SHA-256 of the full payload is tracked. Identical
       payloads within the replay window are flagged.
    3. **Timing analysis**: Packets arriving with identical content within
       the replay window are suspicious.
    """

    def __init__(self, replay_window_sec: float = 60.0, max_tracked_hashes: int = 10000):
        self.replay_window = replay_window_sec
        self.max_hashes = max_tracked_hashes

        # Per-attacker sequence tracking: {ip: {(sys_id, comp_id): last_seq}}
        self._sequences: Dict[str, Dict[Tuple[int, int], int]] = defaultdict(dict)

        # Payload hash tracking: {hash: (timestamp, attacker_ip)}
        self._payload_hashes: Dict[str, Tuple[float, str]] = {}

        # Per-attacker stats
        self._stats: Dict[str, ReplayStats] = defaultdict(ReplayStats)

        # Detection results buffer
        self._detections: list = []

    def check_packet(
        self,
        attacker_ip: str,
        sys_id: int,
        comp_id: int,
        seq: int,
        payload: bytes,
        msg_id: int = 0,
    ) -> dict:
        """
        Check a packet for replay indicators.

        Args:
            attacker_ip: Source IP of the packet
            sys_id: MAVLink system ID
            comp_id: MAVLink component ID
            seq: MAVLink sequence number (0-255)
            payload: Raw payload bytes
            msg_id: MAVLink message ID

        Returns:
            dict with keys:
                is_replay: bool
                replay_type: str or None ('SEQUENCE_REPLAY', 'PAYLOAD_DUPLICATE', 'BOTH')
                confidence: float (0.0-1.0)
                details: str
        """
        now = time.time()
        stats = self._stats[attacker_ip]
        stats.total_packets += 1
        stats.last_seen = now

        is_replay = False
        replay_types = []
        details = []
        confidence = 0.0

        # ── 1. Sequence number analysis ──
        key = (sys_id, comp_id)
        if key in self._sequences[attacker_ip]:
            last_seq = self._sequences[attacker_ip][key]
            expected = (last_seq + 1) % 256

            if seq == last_seq:
                # Exact repeat — strong replay indicator
                replay_types.append('SEQUENCE_REPLAY')
                stats.sequence_anomalies += 1
                confidence = max(confidence, 0.85)
                details.append(f"Repeated seq={seq} for sys_id={sys_id}")
                is_replay = True
            elif seq < last_seq and (last_seq - seq) < 128:
                # Regressing seq (not a wrap-around) — moderate indicator
                replay_types.append('SEQUENCE_REGRESSION')
                stats.sequence_anomalies += 1
                confidence = max(confidence, 0.7)
                details.append(
                    f"Seq regression: got {seq}, expected {expected} "
                    f"(last={last_seq})"
                )
                is_replay = True

        self._sequences[attacker_ip][key] = seq

        # ── 2. Payload hash deduplication ──
        payload_hash = hashlib.sha256(payload).hexdigest()

        if payload_hash in self._payload_hashes:
            prev_time, prev_ip = self._payload_hashes[payload_hash]
            elapsed = now - prev_time

            if elapsed < self.replay_window:
                replay_types.append('PAYLOAD_DUPLICATE')
                stats.duplicate_payloads += 1
                confidence = max(confidence, 0.9 if prev_ip == attacker_ip else 0.6)
                details.append(
                    f"Identical payload seen {elapsed:.1f}s ago "
                    f"(from {'same' if prev_ip == attacker_ip else 'different'} IP)"
                )
                is_replay = True

        self._payload_hashes[payload_hash] = (now, attacker_ip)

        # Garbage collect old hashes
        if len(self._payload_hashes) > self.max_hashes:
            cutoff = now - self.replay_window
            self._payload_hashes = {
                h: (t, ip) for h, (t, ip) in self._payload_hashes.items()
                if t > cutoff
            }

        # ── Record detection ──
        if is_replay:
            stats.replays_detected += 1
            replay_type = '+'.join(replay_types)
            detection = {
                'timestamp': now,
                'attacker_ip': attacker_ip,
                'replay_type': replay_type,
                'confidence': confidence,
                'msg_id': msg_id,
                'seq': seq,
                'sys_id': sys_id,
                'details': '; '.join(details),
            }
            self._detections.append(detection)
            if len(self._detections) > 1000:
                self._detections = self._detections[-500:]

            logger.warning(
                "REPLAY DETECTED from %s: %s (confidence=%.0f%%)",
                attacker_ip, replay_type, confidence * 100
            )

        return {
            'is_replay': is_replay,
            'replay_type': '+'.join(replay_types) if replay_types else None,
            'confidence': confidence,
            'details': '; '.join(details) if details else 'Clean',
        }

    def get_stats(self, attacker_ip: str = None) -> dict:
        """Get replay detection statistics."""
        if attacker_ip:
            s = self._stats.get(attacker_ip, ReplayStats())
            return {
                'ip': attacker_ip,
                'total_packets': s.total_packets,
                'replays_detected': s.replays_detected,
                'duplicate_payloads': s.duplicate_payloads,
                'sequence_anomalies': s.sequence_anomalies,
                'replay_rate': round(
                    s.replays_detected / max(s.total_packets, 1) * 100, 2
                ),
            }

        return {
            'total_attackers': len(self._stats),
            'total_replays': sum(s.replays_detected for s in self._stats.values()),
            'total_packets': sum(s.total_packets for s in self._stats.values()),
            'per_attacker': {
                ip: {
                    'replays': s.replays_detected,
                    'packets': s.total_packets,
                    'rate': round(s.replays_detected / max(s.total_packets, 1) * 100, 2),
                }
                for ip, s in self._stats.items()
            },
        }

    def get_recent_detections(self, limit: int = 20) -> list:
        """Get recent replay detections."""
        return self._detections[-limit:]


if __name__ == "__main__":
    print("Replay Detector — Test")

    rd = ReplayDetector(replay_window_sec=5.0)

    # Normal sequence
    for i in range(5):
        r = rd.check_packet("10.0.0.1", 1, 1, i, f"payload_{i}".encode())
        print(f"  Packet seq={i}: replay={r['is_replay']}")

    # Replay: same seq
    r = rd.check_packet("10.0.0.1", 1, 1, 4, b"payload_4")
    print(f"  Replayed seq=4: replay={r['is_replay']} type={r['replay_type']}")

    # Replay: same payload
    r = rd.check_packet("10.0.0.1", 1, 1, 5, b"payload_3")
    print(f"  Dup payload: replay={r['is_replay']} type={r['replay_type']}")

    print(f"\n  Stats: {rd.get_stats()}")
