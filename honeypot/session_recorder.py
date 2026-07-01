#!/usr/bin/env python3
"""
MAVLink Honeypot — Session Recorder
Records complete attack sessions for replay and forensic analysis.
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field


SESSIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'sessions'
)


@dataclass
class SessionEvent:
    """A single event within a recorded session."""
    timestamp: float          # Unix timestamp
    elapsed_ms: float         # Time since session start
    event_type: str           # CONNECT, MESSAGE, RESPONSE, DISCONNECT
    msg_id: int = 0
    msg_name: str = ""
    intent: str = ""
    severity: int = 0
    direction: str = "IN"     # IN (attacker → honeypot) or OUT (honeypot → attacker)
    payload_hex: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RecordedSession:
    """A complete recorded attack session."""
    session_id: str
    attacker_ip: str
    start_time: str
    end_time: str = ""
    duration_sec: float = 0
    total_events: int = 0
    attack_types: List[str] = field(default_factory=list)
    peak_severity: int = 0
    events: List[dict] = field(default_factory=list)  # List of SessionEvent dicts
    fingerprint_id: str = ""
    skill_level: str = "UNKNOWN"
    campaign_id: str = ""


class SessionRecorder:
    """
    Records attack sessions for replay and analysis.
    Each session is stored as a JSON file in logs/sessions/.
    """

    def __init__(self):
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        self.active_sessions: Dict[str, RecordedSession] = {}
        self._start_times: Dict[str, float] = {}

    def start_recording(self, session_id: str, attacker_ip: str):
        """Begin recording a new session."""
        now = time.time()
        self._start_times[session_id] = now

        session = RecordedSession(
            session_id=session_id,
            attacker_ip=attacker_ip,
            start_time=datetime.now().isoformat(),
        )

        # Add CONNECT event
        session.events.append(asdict(SessionEvent(
            timestamp=now,
            elapsed_ms=0,
            event_type="CONNECT",
            direction="IN",
            metadata={"attacker_ip": attacker_ip},
        )))

        self.active_sessions[session_id] = session

    def record_event(self, session_id: str, msg_id: int, msg_name: str,
                     intent: str, severity: int, direction: str = "IN",
                     payload_hex: str = "", **metadata):
        """Record a message event in the session."""
        if session_id not in self.active_sessions:
            return

        now = time.time()
        start = self._start_times.get(session_id, now)
        elapsed = (now - start) * 1000  # Convert to ms

        session = self.active_sessions[session_id]
        event = SessionEvent(
            timestamp=now,
            elapsed_ms=round(elapsed, 1),
            event_type="MESSAGE" if direction == "IN" else "RESPONSE",
            msg_id=msg_id,
            msg_name=msg_name,
            intent=intent,
            severity=severity,
            direction=direction,
            payload_hex=payload_hex,
            metadata=metadata if metadata else {},
        )

        session.events.append(asdict(event))
        session.total_events += 1
        session.peak_severity = max(session.peak_severity, severity)

        if intent and intent not in session.attack_types:
            session.attack_types.append(intent)

    def stop_recording(self, session_id: str, fingerprint_id: str = "",
                       skill_level: str = "UNKNOWN", campaign_id: str = ""):
        """Stop recording and save the session to disk."""
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions.pop(session_id)
        now = time.time()
        start = self._start_times.pop(session_id, now)

        session.end_time = datetime.now().isoformat()
        session.duration_sec = round(now - start, 2)
        session.fingerprint_id = fingerprint_id
        session.skill_level = skill_level
        session.campaign_id = campaign_id

        # Add DISCONNECT event
        session.events.append(asdict(SessionEvent(
            timestamp=now,
            elapsed_ms=round((now - start) * 1000, 1),
            event_type="DISCONNECT",
            direction="IN",
        )))
        session.total_events += 1

        # Save to file
        filename = f"session_{session_id}.json"
        filepath = os.path.join(SESSIONS_DIR, filename)
        try:
            with open(filepath, 'w') as f:
                json.dump(asdict(session), f, indent=2)
        except Exception:
            pass

        return session

    def list_sessions(self, limit: int = 50) -> List[dict]:
        """List recorded sessions (metadata only, no events)."""
        sessions = []
        try:
            files = sorted(
                [f for f in os.listdir(SESSIONS_DIR) if f.endswith('.json')],
                reverse=True
            )[:limit]

            for filename in files:
                filepath = os.path.join(SESSIONS_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    # Return metadata without full events list
                    sessions.append({
                        "session_id": data.get("session_id"),
                        "attacker_ip": data.get("attacker_ip"),
                        "start_time": data.get("start_time"),
                        "end_time": data.get("end_time"),
                        "duration_sec": data.get("duration_sec"),
                        "total_events": data.get("total_events"),
                        "attack_types": data.get("attack_types", []),
                        "peak_severity": data.get("peak_severity"),
                        "skill_level": data.get("skill_level"),
                        "campaign_id": data.get("campaign_id"),
                    })
                except Exception:
                    continue
        except Exception:
            pass

        return sessions

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a complete recorded session with all events."""
        filename = f"session_{session_id}.json"
        filepath = os.path.join(SESSIONS_DIR, filename)

        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def get_replay_events(self, session_id: str) -> List[dict]:
        """
        Get events formatted for replay playback.
        Events include relative timing for synchronization.
        """
        session = self.get_session(session_id)
        if not session:
            return []

        events = session.get("events", [])
        replay_events = []

        for i, event in enumerate(events):
            replay_events.append({
                "index": i,
                "elapsed_ms": event.get("elapsed_ms", 0),
                "event_type": event.get("event_type"),
                "msg_name": event.get("msg_name", ""),
                "intent": event.get("intent", ""),
                "severity": event.get("severity", 0),
                "direction": event.get("direction", "IN"),
                # Delay until next event (for replay timing)
                "delay_to_next_ms": (
                    events[i+1]["elapsed_ms"] - event["elapsed_ms"]
                    if i < len(events) - 1 else 0
                ),
            })

        return replay_events


class SessionPlayer:
    """Replays recorded sessions at configurable speed."""

    def __init__(self, session_id: str, speed: float = 1.0):
        self.recorder = SessionRecorder()
        self.session_id = session_id
        self.speed = speed
        self.events = self.recorder.get_replay_events(session_id)
        self.current_index = 0
        self.is_playing = False
        self.is_paused = False

    def play(self, callback=None):
        """
        Play back events with timing. Calls callback(event) for each event.
        """
        self.is_playing = True
        self.current_index = 0

        for event in self.events:
            if not self.is_playing:
                break

            while self.is_paused:
                time.sleep(0.1)

            if callback:
                callback(event)

            # Wait for appropriate delay
            delay = event.get("delay_to_next_ms", 0) / 1000.0 / self.speed
            if delay > 0:
                time.sleep(delay)

            self.current_index += 1

        self.is_playing = False

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def stop(self):
        self.is_playing = False
        self.is_paused = False

    def get_progress(self) -> dict:
        return {
            "current": self.current_index,
            "total": len(self.events),
            "progress_pct": round(
                self.current_index / len(self.events) * 100
                if self.events else 0, 1
            ),
            "is_playing": self.is_playing,
            "is_paused": self.is_paused,
            "speed": self.speed,
        }


if __name__ == "__main__":
    print("🎬 Session Recorder — Test")

    recorder = SessionRecorder()

    # Simulate a session
    sid = "test_session_001"
    recorder.start_recording(sid, "192.168.1.100")

    time.sleep(0.1)
    recorder.record_event(sid, 0, "HEARTBEAT", "RECON", 1)
    time.sleep(0.1)
    recorder.record_event(sid, 76, "COMMAND_LONG", "HIJACK", 8)
    time.sleep(0.1)
    recorder.record_event(sid, 76, "COMMAND_ACK", "", 0, direction="OUT")

    session = recorder.stop_recording(sid, skill_level="INTERMEDIATE")
    print(f"  Recorded: {session.session_id}")
    print(f"  Duration: {session.duration_sec}s")
    print(f"  Events: {session.total_events}")
    print(f"  Attacks: {session.attack_types}")

    # List sessions
    sessions = recorder.list_sessions()
    print(f"\n  Stored sessions: {len(sessions)}")
