#!/usr/bin/env python3
"""
MAVLink Adaptive Honeypot — Orchestrator
=========================================

High-level server that wires together the modular core
(protocol parsing, semantic analysis, FSM, response generation)
with the security gate, network discovery beacons, and optional
advanced modules.

Usage::

    python -m honeypot.mavlink_honeypot

Architecture::

    Attacker ──TCP──▶ SecurityGate ──▶ Protocol Parser
                                           │
                                    SemanticAnalyzer
                                           │
                                    StateMachine + Sandbox
                                           │
                                    ResponseGenerator ──▶ Attacker
                                           │
                                    SessionLogger ──▶ CSV / JSON
"""

import hashlib
import os
import random
import socket
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

# ── Config & Logging ─────────────────────────────────────────
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_logger
from config import settings

logger = get_logger("honeypot.core")

# ── Core Modules ─────────────────────────────────────────────
from honeypot.core.session_manager import (
    AttackEvent,
    AttackerProfile,
    ConnectionSandbox,
    SessionLogger,
)
from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.semantic_analyzer import (
    MAVLINK_SEMANTICS,
    ATTACK_PATTERNS,
    SemanticAnalyzer,
)
from honeypot.core.state_machine import HoneypotStateMachine
from honeypot.core.response_generator import ResponseGenerator

# ── Optional Module Imports (config-driven) ──────────────────
ENGINES_AVAILABLE = False
try:
    from fingerprint import AttackerFingerprinter
    from deception_engine import DeceptionScorer
    ENGINES_AVAILABLE = True
except ImportError as e:
    logger.warning("Core engines not available: %s", e)

NEW_MODULES_AVAILABLE = False
if any([settings.feature_correlation_engine, settings.feature_adaptive_deception,
        settings.feature_decoy_fleet, settings.feature_telegram,
        settings.feature_session_recorder]):
    try:
        from correlation_engine import AttackCorrelator
        from adaptive_responses import AdaptiveDeception
        from decoy_fleet import DecoyFleet
        from telegram_bot import TelegramNotifier
        from session_recorder import SessionRecorder
        NEW_MODULES_AVAILABLE = True
    except ImportError as e:
        logger.warning("New modules not available: %s", e)

ML_AVAILABLE = False
if settings.feature_ml_detection:
    try:
        from ml.anomaly_detector import AnomalyDetector
        ML_AVAILABLE = True
    except ImportError as e:
        logger.info("ML anomaly detector disabled: %s", e)

SKILL_ML_AVAILABLE = False
try:
    from ml.skill_classifier import SkillClassifier
    SKILL_ML_AVAILABLE = True
except ImportError:
    pass

ADVANCED_MODULES_AVAILABLE = False
_adv_flags = [
    settings.feature_canary_tokens, settings.feature_mitre_mapper,
    settings.feature_fuzz_detector, settings.feature_tarpit,
    settings.feature_health_monitor, settings.feature_biometrics,
    settings.feature_threat_predictor, settings.feature_cve_simulator,
]
if any(_adv_flags):
    try:
        from canary_tokens import CanaryTokenEngine
        from mitre_mapper import MITREMapper
        from fuzz_detector import FuzzDetector
        from tarpit import AttackerTarpit
        from health_monitor import HealthMonitor
        from biometrics import BiometricsEngine
        from threat_predictor import ThreatPredictor
        from cve_simulator import CVESimulator
        ADVANCED_MODULES_AVAILABLE = True
    except ImportError as e:
        logger.warning("Advanced modules not available: %s", e)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Security: Rate Limiter + Blocklist
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SecurityGate:
    """Rate limiting, connection limits, and auto-blocklist.

    Provides three layers of defence before a packet reaches the
    honeypot pipeline:

    1. **IP blocklist** — offenders are blocked for ``BLOCK_DURATION_SEC``.
    2. **Connection cap** — max ``MAX_CONNECTIONS_PER_IP`` concurrent
       sessions per IP.
    3. **Rate limiter** — max ``MAX_PACKETS_PER_WINDOW`` packets per
       ``RATE_WINDOW_SEC``-second sliding window.  Exceeding this
       ``STRIKES_TO_BLOCK`` times triggers an automatic block.

    All methods are thread-safe via an internal lock.
    """

    MAX_PACKETS_PER_WINDOW: int = 100
    RATE_WINDOW_SEC: int = 5
    MAX_CONNECTIONS_PER_IP: int = 10
    MAX_PAYLOAD_BYTES: int = 280
    SESSION_TIMEOUT_SEC: int = 60
    BLOCK_DURATION_SEC: int = 300
    STRIKES_TO_BLOCK: int = 3

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.packet_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.active_connections: Dict[str, int] = defaultdict(int)
        self.strikes: Dict[str, int] = defaultdict(int)
        self.blocklist: Dict[str, float] = {}

    def is_blocked(self, ip: str) -> bool:
        """Return ``True`` if *ip* is currently on the blocklist."""
        with self.lock:
            if ip in self.blocklist:
                if time.time() < self.blocklist[ip]:
                    return True
                del self.blocklist[ip]
                self.strikes[ip] = 0
            return False

    def can_connect(self, ip: str) -> bool:
        """Return ``True`` if *ip* has not hit the connection cap."""
        with self.lock:
            return self.active_connections[ip] < self.MAX_CONNECTIONS_PER_IP

    def register_connection(self, ip: str) -> None:
        """Increment the active-connection counter for *ip*."""
        with self.lock:
            self.active_connections[ip] += 1

    def unregister_connection(self, ip: str) -> None:
        """Decrement the active-connection counter for *ip*."""
        with self.lock:
            self.active_connections[ip] = max(0, self.active_connections[ip] - 1)

    def check_rate(self, ip: str) -> bool:
        """Return ``True`` if within rate limit, ``False`` if exceeded."""
        now = time.time()
        with self.lock:
            self.packet_timestamps[ip] = [
                t for t in self.packet_timestamps[ip]
                if now - t < self.RATE_WINDOW_SEC
            ]
            if len(self.packet_timestamps[ip]) >= self.MAX_PACKETS_PER_WINDOW:
                self.strikes[ip] += 1
                if self.strikes[ip] >= self.STRIKES_TO_BLOCK:
                    self.blocklist[ip] = now + self.BLOCK_DURATION_SEC
                    logger.warning(
                        "AUTO-BLOCKED %s for %ds (rate limit exceeded %dx)",
                        ip, self.BLOCK_DURATION_SEC, self.strikes[ip],
                    )
                return False
            self.packet_timestamps[ip].append(now)
            return True

    def validate_packet(self, data: bytes) -> bool:
        """Return ``True`` if *data* looks like a valid MAVLink frame."""
        if len(data) > self.MAX_PAYLOAD_BYTES or len(data) < 6:
            return False
        if data[0] not in (0xFE, 0xFD):
            return False
        payload_len = data[1]
        if data[0] == 0xFE:
            expected = 6 + payload_len + 2
            if len(data) < min(expected, len(data)):
                return True
        return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Network Discovery: UDP Heartbeat Beacon
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class UDPHeartbeatBeacon(threading.Thread):
    """Broadcasts MAVLink heartbeats over UDP so GCS tools see a "live drone"."""

    BROADCAST_PORT: int = 14550
    BEACON_INTERVAL: float = 1.0

    def __init__(self, tcp_port: int = 5760) -> None:
        super().__init__(daemon=True)
        self.tcp_port = tcp_port
        self.running = True
        self._sys_id = random.randint(1, 254)

    def _craft_heartbeat(self) -> bytes:
        """Craft a MAVLink v1.0 HEARTBEAT for broadcast."""
        payload = struct.pack("<IBBBB B", 0, 2, 3, 81, 4, 3)
        msg = bytearray([
            0xFE, len(payload), random.randint(0, 255),
            self._sys_id, 1, 0,
        ])
        msg.extend(payload)
        msg.extend(b"\x00\x00")
        return bytes(msg)

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while self.running:
            try:
                beacon = self._craft_heartbeat() + struct.pack("<H", self.tcp_port)
                sock.sendto(beacon, ("<broadcast>", self.BROADCAST_PORT))
                sock.sendto(beacon, ("127.0.0.1", self.BROADCAST_PORT))
            except Exception:
                pass
            time.sleep(self.BEACON_INTERVAL)

    def stop(self) -> None:
        self.running = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Network Discovery: mDNS Advertiser
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class MDNSAdvertiser(threading.Thread):
    """Advertises the honeypot as ``_mavlink._tcp.local`` via mDNS."""

    MDNS_ADDR: str = "224.0.0.251"
    MDNS_PORT: int = 5353

    def __init__(self, service_name: str = "DronePilot-HP", tcp_port: int = 5760) -> None:
        super().__init__(daemon=True)
        self.service_name = service_name
        self.tcp_port = tcp_port
        self.running = True

    def _encode_name(self, name: str) -> bytes:
        """Encode a DNS-style dotted name."""
        result = b""
        for part in name.split("."):
            result += bytes([len(part)]) + part.encode()
        return result + b"\x00"

    def _build_response(self) -> bytes:
        """Build a minimal mDNS PTR response."""
        header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        st = "_mavlink._tcp.local"
        name = self._encode_name(st)
        rdata = self._encode_name(f"{self.service_name}.{st}")
        answer = name + struct.pack(">HHI", 12, 1, 120) + struct.pack(">H", len(rdata)) + rdata
        return header + answer

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except Exception:
                    pass
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            while self.running:
                try:
                    sock.sendto(self._build_response(), (self.MDNS_ADDR, self.MDNS_PORT))
                except Exception:
                    pass
                time.sleep(10)
        except Exception:
            pass

    def stop(self) -> None:
        self.running = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Honeypot Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class AdaptiveHoneypot:
    """Adaptive MAVLink Honeypot with real-time semantic analysis.

    Ties together the modular core pipeline with security, logging,
    network discovery, and optional advanced modules.

    Args:
        listen_port: TCP port to listen on (default 5760).
        sitl_port: Upstream SITL port (reserved for future use).
    """

    # Backward-compat: expose state constants here too
    STATE_NORMAL = "NORMAL"
    STATE_WEAK = "WEAK"
    STATE_CONFUSED = "CONFUSED"
    STATE_DEFENSIVE = "DEFENSIVE"
    STATE_CRASHED = "CRASHED"
    STATE_REBOOTING = "REBOOTING"
    STATE_PARTIAL = "PARTIAL"

    DECOY_ENABLED: bool = True
    DECOY_GPS_DRIFT: float = 0.001
    DECOY_BATTERY_DRAIN: float = 0.1

    def __init__(self, listen_port: int = 5760, sitl_port: int = 5761) -> None:
        self.listen_port = listen_port
        self.sitl_port = sitl_port

        # ── Core pipeline ──
        self.protocol = MAVLinkProtocol()
        self.analyzer = SemanticAnalyzer()
        self.fsm = HoneypotStateMachine(
            decoy_enabled=self.DECOY_ENABLED,
            gps_drift=self.DECOY_GPS_DRIFT,
            battery_drain=self.DECOY_BATTERY_DRAIN,
        )
        self.responder = ResponseGenerator(
            protocol=self.protocol,
            min_delay_ms=random.randint(30, 80),
            max_delay_ms=random.randint(200, 600),
        )

        # Anti-fingerprint aliases
        self._sys_id = self.protocol.sys_id
        self._comp_id = self.protocol.comp_id

        # ── State tracking ──
        self.events: List[AttackEvent] = []
        self.attacker_profiles: Dict[str, AttackerProfile] = {}
        self.session_data = self.analyzer.session_data
        self.msg_timestamps = self.analyzer.msg_timestamps

        # ── Security ──
        self.security = SecurityGate()

        # ── Logging ──
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.session_logger = SessionLogger(base_dir)
        self.log_file = self.session_logger.log_file
        self.dataset_file = self.session_logger.dataset_file

        # ── Optional engines ──
        if ENGINES_AVAILABLE:
            self.fingerprinter = AttackerFingerprinter()
            self.deception = DeceptionScorer()

        # ML anomaly detector
        self.anomaly_detector = None
        if ML_AVAILABLE:
            self.anomaly_detector = AnomalyDetector()
            model_path = os.path.join(base_dir, "ml", "trained_model.pkl")
            if self.anomaly_detector.load_model(model_path):
                logger.info("ML Anomaly Detector: LOADED")
            else:
                logger.warning("ML model not found. Run 'python3 ml/train_model.py' to train.")
                self.anomaly_detector = None

        # New modules
        self.correlator = self.adaptive_deception = self.decoy_fleet = None
        self.telegram = self.session_recorder = self.skill_classifier = None

        if NEW_MODULES_AVAILABLE:
            for attr, cls_name, cls in [
                ("correlator", "Attack Correlator", AttackCorrelator),
                ("adaptive_deception", "Adaptive Deception", AdaptiveDeception),
                ("decoy_fleet", "Decoy Fleet", DecoyFleet),
                ("telegram", "Telegram", TelegramNotifier),
                ("session_recorder", "Session Recorder", SessionRecorder),
            ]:
                try:
                    setattr(self, attr, cls())
                    logger.info("%s: LOADED", cls_name)
                except Exception as e:
                    logger.debug("%s init failed: %s", cls_name, e)

            # Wire interactive Telegram bot to this honeypot instance
            if self.telegram:
                self.telegram.set_honeypot(self)
                self.telegram.start_command_listener()

        if SKILL_ML_AVAILABLE:
            try:
                self.skill_classifier = SkillClassifier()
                logger.info("ML Skill Classifier: LOADED")
            except Exception as e:
                logger.debug("Skill Classifier init failed: %s", e)

        # Advanced modules
        self.canary_engine = self.mitre_mapper = self.fuzz_detector = None
        self.tarpit = self.health_monitor = self.biometrics = None
        self.threat_predictor = self.cve_simulator = None

        if ADVANCED_MODULES_AVAILABLE:
            adv_modules = [
                ("canary_engine", "Canary Tokens", CanaryTokenEngine),
                ("mitre_mapper", "MITRE ATT&CK Mapper", MITREMapper),
                ("fuzz_detector", "Fuzz Detector", FuzzDetector),
                ("tarpit", "Attacker Tarpit", AttackerTarpit),
                ("biometrics", "Behavioral Biometrics", BiometricsEngine),
                ("threat_predictor", "Threat Predictor", ThreatPredictor),
                ("cve_simulator", "CVE Simulator", CVESimulator),
            ]
            for attr, label, cls in adv_modules:
                try:
                    setattr(self, attr, cls())
                    logger.info("%s: LOADED", label)
                except Exception as e:
                    logger.debug("%s init failed: %s", label, e)

            # Health monitor needs explicit start
            try:
                self.health_monitor = HealthMonitor()
                self.health_monitor.start_monitoring()
                logger.info("Health Monitor: LOADED (background checks active)")
            except Exception as e:
                logger.debug("Health Monitor init failed: %s", e)

    # ── Backward-compat delegators ────────────────────────────

    def parse_mavlink_packet(self, data: bytes) -> Optional[Dict]:
        """Parse MAVLink packet header (delegates to ``MAVLinkProtocol``)."""
        return self.protocol.parse_packet(data)

    def analyze_intent(self, msg_id: int, addr: tuple) -> Dict:
        """Semantic analysis (delegates to ``SemanticAnalyzer``)."""
        return self.analyzer.analyze_intent(msg_id, addr)

    def _detect_pattern(self, session_key: str, msg_id: int) -> Optional[str]:
        """Pattern detection (delegates to ``SemanticAnalyzer``)."""
        return self.analyzer.detect_pattern(session_key, msg_id)

    def adapt_behavior(self, sandbox: ConnectionSandbox, severity: int, intent: str) -> None:
        """FSM transition (delegates to ``HoneypotStateMachine``)."""
        self.fsm.adapt_behavior(sandbox, severity, intent)

    def generate_response(self, sb: ConnectionSandbox, msg_id: int, intent: str = "UNKNOWN") -> tuple:
        """Response generation (delegates to ``ResponseGenerator``)."""
        return self.responder.generate(sb, msg_id, intent)

    def _init_dataset(self) -> None:
        """Initialize CSV dataset (handled by ``SessionLogger``)."""
        pass  # done in __init__ via SessionLogger

    def log_event(self, event: AttackEvent, packet_rate: float) -> None:
        """Log event to file and dataset."""
        self.session_logger.log_event(event, packet_rate)

    def update_attacker_profile(self, event: AttackEvent, packet_rate: float) -> None:
        """Update or create attacker behavioral profile."""
        self.session_logger.update_attacker_profile(
            self.attacker_profiles, event, packet_rate,
        )

    # ── Packet crafting (backward compat) ─────────────────────

    def _craft_heartbeat(self, sb: ConnectionSandbox, base_mode: int = 81, custom_mode: int = 0) -> bytes:
        return self.protocol.craft_heartbeat(base_mode, custom_mode)

    def _craft_gps_raw(self, sb: ConnectionSandbox) -> bytes:
        return self.protocol.craft_gps_raw(sb.decoy_lat, sb.decoy_lon, sb.decoy_alt, sb.decoy_speed, sb.decoy_heading)

    def _craft_battery_status(self, sb: ConnectionSandbox) -> bytes:
        return self.protocol.craft_battery_status(sb.decoy_battery)

    # ── Connection Handler ────────────────────────────────────

    def handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        """Handle an attacker connection with security enforcement."""
        ip = addr[0]

        if self.security.is_blocked(ip):
            logger.warning("Blocked connection from %s (auto-blocklist)", ip)
            client_sock.close()
            return

        if not self.security.can_connect(ip):
            logger.warning("Rejected connection from %s (max connections exceeded)", ip)
            client_sock.close()
            return

        self.security.register_connection(ip)
        sandbox = ConnectionSandbox.create()
        session_id = hashlib.md5(f"{addr[0]}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]

        if ENGINES_AVAILABLE:
            self.fingerprinter.start_session(session_id, ip)
            self.deception.on_connect(session_id, ip)

        logger.info("New connection from %s:%d (session: %s)", addr[0], addr[1], session_id)

        # Log connection IMMEDIATELY so it's captured even if process crashes
        self.session_logger.log_connection(addr[0], addr[1], session_id, "CONNECT")

        # Alert on ANY connection (even non-MAVLink scanners)
        if self.telegram:
            try:
                self.telegram.send_alert({
                    "intent": "NEW_CONNECTION",
                    "msg_name": "TCP_CONNECT",
                    "severity": 1,
                    "attacker_ip": addr[0],
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
            except Exception:
                pass

        try:
            client_sock.settimeout(self.security.SESSION_TIMEOUT_SEC)

            while True:
                try:
                    data = client_sock.recv(1024)
                except socket.timeout:
                    logger.info("Session timeout: %s:%d", addr[0], addr[1])
                    break

                if not data:
                    break

                if not self.security.validate_packet(data):
                    logger.warning("Invalid packet from %s (%d bytes) — dropped", ip, len(data))
                    continue

                if not self.security.check_rate(ip):
                    logger.warning("Rate limit exceeded for %s — throttling", ip)
                    time.sleep(2)
                    continue

                parsed = self.parse_mavlink_packet(data)
                if not parsed:
                    continue

                msg_id = parsed["msg_id"]
                sandbox.packets_received += 1
                sandbox.last_activity = time.time()

                semantics = self.analyze_intent(msg_id, addr)
                session_key = f"{addr[0]}:{addr[1]}"
                packet_rate = self.analyzer.get_packet_rate(session_key)

                self.adapt_behavior(sandbox, semantics["severity"], semantics["intent"])

                if ENGINES_AVAILABLE:
                    self.fingerprinter.record_action(session_id, semantics["intent"])
                    self.deception.on_command(session_id, ip, semantics["name"], semantics["intent"])

                response, response_type = self.generate_response(sandbox, msg_id, semantics["intent"])

                event = AttackEvent(
                    timestamp=datetime.now().isoformat(),
                    attacker_ip=addr[0],
                    attacker_port=addr[1],
                    msg_id=msg_id,
                    msg_name=semantics["name"],
                    intent=semantics["intent"],
                    severity=semantics["severity"],
                    payload_hex=parsed["payload"].hex(),
                    session_id=session_id,
                    fake_response_type=response_type,
                    fake_gps_lat=round(sandbox.decoy_lat, 6),
                    fake_gps_lon=round(sandbox.decoy_lon, 6),
                    fake_altitude=round(sandbox.decoy_alt, 1),
                    fake_battery=round(sandbox.decoy_battery, 1),
                    fake_heading=sandbox.decoy_heading,
                    fake_speed=round(sandbox.decoy_speed, 1),
                    honeypot_state=sandbox.current_state,
                )

                self.events.append(event)
                self.log_event(event, packet_rate)
                self.update_attacker_profile(event, packet_rate)

                if self.anomaly_detector:
                    is_anomaly, anomaly_score = self.anomaly_detector.predict({
                        "severity": semantics["severity"],
                        "packet_rate": packet_rate,
                        "msg_id": msg_id,
                        "intent": semantics["intent"],
                        "timestamp": event.timestamp,
                        "payload_hex": event.payload_hex,
                    })
                    event.anomaly_flag = is_anomaly
                    event.anomaly_score = anomaly_score
                    if is_anomaly:
                        logger.warning(
                            "ML ANOMALY DETECTED! Score: %s | %s from %s",
                            anomaly_score, semantics["name"], ip,
                        )

                logger.info("[%s] %s -> %s (severity: %d)",
                            sandbox.current_state, semantics["name"],
                            semantics["intent"], semantics["severity"])
                logger.debug("Response: %s | GPS(%s, %s) Alt:%sm Batt:%s%% Hdg:%s° | %d bytes",
                             response_type, event.fake_gps_lat, event.fake_gps_lon,
                             event.fake_altitude, event.fake_battery,
                             event.fake_heading, len(response))

                if response:
                    client_sock.send(response)

        except Exception as e:
            logger.error("Error handling %s: %s", addr, e, exc_info=True)

        finally:
            if ENGINES_AVAILABLE:
                fp = self.fingerprinter.finalize_session(session_id)
                self.deception.on_disconnect(session_id, ip)
                if fp:
                    logger.info("Fingerprint: %s | Skill: %s | Threat: %s",
                                fp.fingerprint_id, fp.skill_level, fp.threat_score)

            # Log session even if 0 valid MAVLink packets (scanner/probe)
            if sandbox.packets_received == 0:
                duration = time.time() - sandbox.last_activity
                event = AttackEvent(
                    timestamp=datetime.now().isoformat(),
                    attacker_ip=addr[0],
                    attacker_port=addr[1],
                    msg_id=0,
                    msg_name="NON_MAVLINK_PROBE",
                    intent="SCANNER",
                    severity=0,
                    payload_hex="",
                    session_id=session_id,
                    fake_response_type="none",
                    fake_gps_lat=0, fake_gps_lon=0, fake_altitude=0,
                    fake_battery=0, fake_heading=0, fake_speed=0,
                    honeypot_state="NORMAL",
                )
                self.log_event(event, 0.0)

            # Log disconnect with duration and packet count
            duration = time.time() - sandbox.session_start
            self.session_logger.log_connection(
                addr[0], addr[1], session_id, "DISCONNECT",
                packets=sandbox.packets_received,
                duration_sec=duration,
            )

            client_sock.close()
            self.security.unregister_connection(ip)

            # Flush Telegram alerts before moving on
            if self.telegram:
                try:
                    self.telegram.flush_now()
                except Exception:
                    pass

            logger.info("Connection closed: %s:%d (pkts: %d, duration: %.1fs)",
                        addr[0], addr[1], sandbox.packets_received, duration)

    # ── Server Start ──────────────────────────────────────────

    def start(self) -> None:
        """Start the honeypot server with network-discovery beacons."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.listen_port))
        server.listen(5)

        UDPHeartbeatBeacon(tcp_port=self.listen_port).start()
        MDNSAdvertiser(tcp_port=self.listen_port).start()

        logger.info("MAVLink Adaptive Honeypot v2.0 starting")
        logger.info("TCP Listener: port %d", self.listen_port)
        logger.info("UDP Beacon: port 14550 (broadcasting heartbeats)")
        logger.info("mDNS: _mavlink._tcp.local (service discovery)")
        logger.info(
            "Security Gate: ARMED (rate=%d/%ds, max_conn=%d/IP, timeout=%ds)",
            SecurityGate.MAX_PACKETS_PER_WINDOW, SecurityGate.RATE_WINDOW_SEC,
            SecurityGate.MAX_CONNECTIONS_PER_IP, SecurityGate.SESSION_TIMEOUT_SEC,
        )
        logger.info("Fingerprinting: %s | Deception: %s",
                     "ACTIVE" if ENGINES_AVAILABLE else "DISABLED",
                     "ACTIVE" if ENGINES_AVAILABLE else "DISABLED")
        logger.info("Telegram Bot: %s",
                     "INTERACTIVE" if (self.telegram and self.telegram.enabled) else "DISABLED")

        while True:
            client, addr = server.accept()
            t = threading.Thread(target=self.handle_client, args=(client, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MAVLink Adaptive Honeypot")
    parser.add_argument("--mode", choices=["adaptive", "static"], default="adaptive",
                       help="Run in adaptive (default) or static mode")
    args = parser.parse_args()

    if args.mode == "static":
        from static_honeypot import StaticHoneypot
        logger.info("Starting in STATIC mode (ON/OFF experiment)")
        honeypot = StaticHoneypot()
    else:
        honeypot = AdaptiveHoneypot()

    honeypot.start()
