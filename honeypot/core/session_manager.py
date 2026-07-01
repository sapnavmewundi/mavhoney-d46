"""
Session Manager — Per-connection state, attack events, and attacker profiles.

Provides the data structures that flow through the honeypot pipeline:
  - ``ConnectionSandbox``: isolated decoy telemetry per attacker session
  - ``AttackEvent``:        single logged attack event
  - ``AttackerProfile``:    cumulative behavioral profile per IP
  - ``SessionLogger``:      CSV + JSON log writer
"""

from __future__ import annotations

import csv
import json
import os
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ── Data Classes ──────────────────────────────────────────────


@dataclass
class AttackEvent:
    """A single attack event captured by the honeypot.

    Attributes:
        timestamp: ISO-8601 timestamp when the event was recorded.
        attacker_ip: Source IP address of the attacker.
        attacker_port: Source port of the attacker.
        msg_id: MAVLink message ID received.
        msg_name: Human-readable MAVLink message name.
        intent: Classified intent (RECON, CONTROL, HIJACK, etc.).
        severity: Threat severity on a 1–10 scale.
        payload_hex: Hex-encoded raw payload bytes.
        session_id: Unique identifier for this TCP session.
        fake_response_type: Type of decoy response sent back.
        fake_gps_lat: Decoy GPS latitude sent to the attacker.
        fake_gps_lon: Decoy GPS longitude sent to the attacker.
        fake_altitude: Decoy altitude in metres.
        fake_battery: Decoy battery percentage.
        fake_heading: Decoy heading in degrees (0–360).
        fake_speed: Decoy ground speed in m/s.
        honeypot_state: FSM state when the event was recorded.
    """

    timestamp: str
    attacker_ip: str
    attacker_port: int
    msg_id: int
    msg_name: str
    intent: str
    severity: int
    payload_hex: str
    session_id: str
    fake_response_type: str = "NONE"
    fake_gps_lat: float = 0.0
    fake_gps_lon: float = 0.0
    fake_altitude: float = 0.0
    fake_battery: float = 0.0
    fake_heading: int = 0
    fake_speed: float = 0.0
    honeypot_state: str = "NORMAL"
    anomaly_flag: bool = False
    anomaly_score: float = 0.0


@dataclass
class AttackerProfile:
    """Cumulative behavioral profile of an attacker.

    Attributes:
        ip: Attacker IP address.
        first_seen: ISO-8601 timestamp of first contact.
        last_seen: ISO-8601 timestamp of most recent contact.
        total_packets: Total packets received from this IP.
        attack_types: Mapping of intent category to count.
        severity_score: Exponential moving average of severity.
        command_sequence: Last 10 message names received.
        avg_packet_rate: Exponential moving average of packets/sec.
        country: GeoIP country (if available).
        city: GeoIP city (if available).
        isp: GeoIP ISP (if available).
        estimated_distance_km: Estimated distance from honeypot.
    """

    ip: str
    first_seen: str
    last_seen: str
    total_packets: int
    attack_types: Dict[str, int]
    severity_score: float
    command_sequence: List[str]
    avg_packet_rate: float
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    estimated_distance_km: float = 0.0


@dataclass
class ConnectionSandbox:
    """Isolated decoy telemetry state for a single attacker connection.

    Each attacker gets their own sandbox so that concurrent sessions cannot
    interfere with each other's telemetry drift.

    Attributes:
        decoy_lat: Current decoy latitude (WGS-84 degrees).
        decoy_lon: Current decoy longitude (WGS-84 degrees).
        decoy_alt: Current decoy altitude (metres AGL).
        decoy_battery: Current decoy battery percentage (0–100).
        decoy_heading: Current decoy heading (0–360°).
        decoy_speed: Current decoy ground speed (m/s).
        current_state: FSM state for this session.
        reboot_timer: Countdown ticks remaining in REBOOTING state.
        packets_received: Total packets received this session.
        last_activity: Monotonic timestamp of most recent packet.
        session_start: Monotonic timestamp when the session began.
        log_env: 'prod' or 'test' — separates testing from real logs.
    """

    decoy_lat: float = 0.0
    decoy_lon: float = 0.0
    decoy_alt: float = 100.0
    decoy_battery: float = 100.0
    decoy_heading: int = 0
    decoy_speed: float = 0.0
    current_state: str = "NORMAL"
    reboot_timer: int = 0
    packets_received: int = 0
    last_activity: float = 0.0
    session_start: float = 0.0
    log_env: str = "prod"

    # Drift parameters (configurable)
    _gps_drift_rate: float = 0.00002    # degrees per tick
    _battery_drain_rate: float = 0.02   # percent per tick
    _alt_oscillation: float = 0.5       # meters per tick
    _heading_drift: float = 1.0         # degrees per tick
    _alt_direction: int = 1             # +1 climb, -1 descend

    @classmethod
    def create(cls, log_env: str = "prod") -> "ConnectionSandbox":
        """Factory that initialises a sandbox with realistic random values.

        Returns:
            A new ``ConnectionSandbox`` with randomised GPS coordinates
            near San Francisco and a random heading.
        """
        now = time.time()
        return cls(
            decoy_lat=37.7749 + random.uniform(-0.01, 0.01),
            decoy_lon=-122.4194 + random.uniform(-0.01, 0.01),
            decoy_alt=100.0 + random.uniform(-20, 20),
            decoy_battery=100.0,
            decoy_heading=random.randint(0, 360),
            decoy_speed=0.0,
            last_activity=now,
            session_start=now,
            log_env=log_env,
        )

    def update_telemetry(self) -> None:
        """Apply one tick of realistic telemetry drift.

        Should be called each time a response is generated. Simulates:
        - GPS random walk (lat/lon drift)
        - Battery linear discharge
        - Altitude oscillation (climb/descend pattern)
        - Heading gradual drift
        - Speed variation based on state
        """
        # GPS drift: random walk
        self.decoy_lat += random.uniform(
            -self._gps_drift_rate, self._gps_drift_rate
        )
        self.decoy_lon += random.uniform(
            -self._gps_drift_rate, self._gps_drift_rate
        )

        # Battery drain: linear discharge, clamp at 0
        self.decoy_battery = max(
            0.0, self.decoy_battery - self._battery_drain_rate
        )

        # Altitude oscillation: climb/descend pattern
        self.decoy_alt += self._alt_oscillation * self._alt_direction
        if self.decoy_alt > 150.0 or self.decoy_alt < 50.0:
            self._alt_direction *= -1  # reverse direction
        # Add slight noise
        self.decoy_alt += random.uniform(-0.2, 0.2)

        # Heading drift
        self.decoy_heading = (
            self.decoy_heading + int(random.uniform(-self._heading_drift,
                                                      self._heading_drift))
        ) % 360

        # Speed: varies based on state
        if self.current_state in ("NORMAL", "WEAK"):
            self.decoy_speed = max(0.0, self.decoy_speed + random.uniform(-0.5, 0.5))
            self.decoy_speed = min(15.0, self.decoy_speed)  # cap at 15 m/s
        elif self.current_state == "CRASHED":
            self.decoy_speed = 0.0
        else:
            self.decoy_speed = max(0.0, self.decoy_speed * 0.95)


# ── Session Logger ────────────────────────────────────────────


class SessionLogger:
    """Writes attack events to a JSON log file and a CSV dataset.

    All writes are flushed immediately to prevent data loss on crash
    or unexpected restart.

    Args:
        base_dir: Project root directory.  Logs are stored under
            ``<base_dir>/logs/`` and datasets under ``<base_dir>/datasets/``.

    Attributes:
        log_file: Path to the current JSON event log (date-based, persistent).
        dataset_file: Path to the current CSV dataset.
        connections_file: Path to the connections CSV (every TCP connection).
    """

    #: CSV column header used by the ML training pipeline.
    CSV_COLUMNS: List[str] = [
        "timestamp", "ip", "port", "msg_id", "msg_name",
        "intent", "severity", "payload_hex", "session_id",
        "honeypot_state", "packet_rate",
    ]

    #: Columns for the raw connection log.
    CONN_COLUMNS: List[str] = [
        "timestamp", "ip", "port", "session_id", "event_type",
        "packets", "duration_sec",
    ]

    def __init__(self, base_dir: str) -> None:
        self._logs_dir = os.path.join(base_dir, "logs")
        self._datasets_dir = os.path.join(base_dir, "datasets")
        os.makedirs(self._logs_dir, exist_ok=True)
        os.makedirs(self._datasets_dir, exist_ok=True)

        # Date-based JSON log — survives restarts within the same day
        date_str = datetime.now().strftime("%Y%m%d")
        self.log_file: str = os.path.join(
            self._logs_dir, f"honeypot_{date_str}.jsonl"
        )
        # Use fixed filename so data persists across restarts
        self.dataset_file: str = os.path.join(
            self._datasets_dir, "adaptive_data.csv"
        )
        # Raw connection log — every TCP connect/disconnect
        self.connections_file: str = os.path.join(
            self._datasets_dir, "connections.csv"
        )
        self._init_dataset()
        self._init_connections()

        # Log the restart event itself for forensic tracing
        self._log_restart()

    def _init_dataset(self) -> None:
        """Write the CSV header row only if file doesn't exist or is empty."""
        if not os.path.exists(self.dataset_file) or os.path.getsize(self.dataset_file) == 0:
            with open(self.dataset_file, "w", newline="") as fh:
                csv.writer(fh).writerow(self.CSV_COLUMNS)
                fh.flush()
                os.fsync(fh.fileno())

    def _init_connections(self) -> None:
        """Write the connections CSV header if file doesn't exist or is empty."""
        if not os.path.exists(self.connections_file) or os.path.getsize(self.connections_file) == 0:
            with open(self.connections_file, "w", newline="") as fh:
                csv.writer(fh).writerow(self.CONN_COLUMNS)
                fh.flush()
                os.fsync(fh.fileno())

    def _log_restart(self) -> None:
        """Log a restart marker to the JSON log for forensic tracing."""
        restart_entry = {
            "event": "HONEYPOT_RESTART",
            "timestamp": datetime.now().isoformat(),
            "log_file": os.path.basename(self.log_file),
            "dataset_file": os.path.basename(self.dataset_file),
        }
        with open(self.log_file, "a") as fh:
            fh.write(f"{json.dumps(restart_entry)}\n")
            fh.flush()
            os.fsync(fh.fileno())

    def log_connection(self, ip: str, port: int, session_id: str,
                       event_type: str = "CONNECT",
                       packets: int = 0, duration_sec: float = 0.0) -> None:
        """Log a raw TCP connection event (connect or disconnect).

        Called on EVERY connection, even zero-packet scanners.
        Flushed immediately to prevent data loss.

        Args:
            ip: Attacker IP address.
            port: Attacker source port.
            session_id: Unique session identifier.
            event_type: 'CONNECT' or 'DISCONNECT'.
            packets: Number of packets exchanged (0 for connect events).
            duration_sec: Session duration in seconds (0 for connect events).
        """
        try:
            with open(self.connections_file, "a", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow([
                    datetime.now().isoformat(), ip, port,
                    session_id, event_type, packets,
                    round(duration_sec, 3),
                ])
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            pass  # Never crash on logging failure

    def log_event(self, event: AttackEvent, packet_rate: float) -> None:
        """Append *event* to both the JSON log and CSV dataset.

        All writes are flushed and fsynced immediately.

        Args:
            event: The attack event to record.
            packet_rate: Current packets-per-second for this session.
        """
        with open(self.log_file, "a") as fh:
            fh.write(f"{json.dumps(asdict(event))}\n")
            fh.flush()
            os.fsync(fh.fileno())

        with open(self.dataset_file, "a", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                event.timestamp, event.attacker_ip, event.attacker_port,
                event.msg_id, event.msg_name, event.intent, event.severity,
                event.payload_hex, event.session_id, event.honeypot_state,
                packet_rate,
            ])
            fh.flush()
            os.fsync(fh.fileno())

    def update_attacker_profile(
        self,
        profiles: Dict[str, AttackerProfile],
        event: AttackEvent,
        packet_rate: float,
    ) -> None:
        """Create or update the ``AttackerProfile`` for *event.attacker_ip*.

        Uses an exponential moving average (α = 0.3) for severity and
        packet-rate smoothing.

        Args:
            profiles: Mutable mapping of IP → profile.
            event: The attack event to incorporate.
            packet_rate: Current packets-per-second for this session.
        """
        key = event.attacker_ip
        alpha = 0.3

        if key not in profiles:
            profiles[key] = AttackerProfile(
                ip=event.attacker_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                total_packets=0,
                attack_types={},
                severity_score=0.0,
                command_sequence=[],
                avg_packet_rate=0.0,
            )

        profile = profiles[key]
        profile.last_seen = event.timestamp
        profile.total_packets += 1

        if event.intent not in profile.attack_types:
            profile.attack_types[event.intent] = 0
        profile.attack_types[event.intent] += 1

        profile.severity_score = (
            alpha * event.severity + (1 - alpha) * profile.severity_score
        )

        profile.command_sequence.append(event.msg_name)
        profile.command_sequence = profile.command_sequence[-10:]

        profile.avg_packet_rate = (
            alpha * packet_rate + (1 - alpha) * profile.avg_packet_rate
        )
