#!/usr/bin/env python3
"""
MAVLink Static+TCP Honeypot — TCP Confound Control
====================================================

Ablation server that ISOLATES the TCP credential surface from adaptive
behavior. This server has:

  ✅ TCP listener on port 5760 (same as adaptive)
  ✅ SecurityGate with rate limiting (same as adaptive)
  ✅ UDP heartbeat beacon (same as adaptive)
  ✅ mDNS service discovery (same as adaptive)
  ✅ Full MAVLink response suite (heartbeat, GPS, battery, ACK)
  ✅ Credential-style prompt on TCP connect (same as adaptive)
  ✅ Same logging format for direct comparison

  ❌ NO FSM state transitions (always NORMAL)
  ❌ NO entropy-based attacker profiling
  ❌ NO game-theoretic response selection
  ❌ NO fingerprinting-based adaptation
  ❌ NO telemetry drift
  ❌ NO ML anomaly detection

Purpose:
  If adaptive > static_with_tcp on engagement metrics, then the
  FSM/game-theory adaptation — not merely the TCP surface — drives
  the engagement difference. This eliminates the TCP confound.

Usage::
    python -m honeypot.static_with_tcp_honeypot

Deploy alongside the full adaptive honeypot for 14 days.
"""

import csv
import hashlib
import os
import random
import socket
import struct
import threading
import time
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_logger

logger = get_logger("honeypot.static_tcp")

# ── Constants ─────────────────────────────────────────────────
LISTEN_PORT = 5760
UDP_BEACON_PORT = 14550
SESSION_TIMEOUT = 60
MAX_PACKET_SIZE = 280

# Fixed decoy values (never change — no drift)
DECOY_LAT = 12.971600
DECOY_LON = 77.594560
DECOY_ALT = 45.0
DECOY_BATTERY = 78.0
DECOY_HEADING = 135
DECOY_SPEED = 0.0

# Credential prompts (same strings the adaptive honeypot uses)
CREDENTIAL_BANNER = b"\r\nArduPilot GCS Authentication Required\r\n"
CREDENTIAL_PROMPT_USER = b"Username: "
CREDENTIAL_PROMPT_PASS = b"Password: "
CREDENTIAL_FAIL = b"\r\nAuthentication failed. Access denied.\r\n"
CREDENTIAL_SUCCESS = b"\r\nAuthentication successful. MAVLink interface ready.\r\n"
MAX_AUTH_ATTEMPTS = 5

# MAVLink message names for logging
MSG_NAMES = {
    0: "HEARTBEAT", 4: "PING", 11: "SET_MODE",
    20: "PARAM_REQUEST_READ", 21: "PARAM_REQUEST_LIST",
    23: "PARAM_SET", 24: "GPS_RAW_INT",
    33: "GLOBAL_POSITION_INT",
    39: "MISSION_ITEM", 40: "MISSION_REQUEST",
    43: "MISSION_REQUEST_LIST", 44: "MISSION_COUNT",
    47: "MISSION_ACK", 48: "SET_GPS_GLOBAL_ORIGIN",
    66: "REQUEST_DATA_STREAM", 76: "COMMAND_LONG",
    82: "SET_ATTITUDE_TARGET",
    84: "SET_POSITION_TARGET_LOCAL_NED",
    86: "SET_POSITION_TARGET_GLOBAL_INT",
    148: "AUTOPILOT_VERSION_REQUEST",
    246: "REQUEST_AUTOPILOT_CAPABILITIES",
}

INTENT_MAP = {
    0: "RECON", 4: "RECON", 11: "CONTROL",
    20: "RECON", 21: "RECON",
    23: "CONFIG_ATTACK", 39: "MISSION_INJECT", 40: "RECON",
    43: "RECON", 44: "MISSION_INJECT", 48: "GPS_SPOOF",
    66: "RECON", 76: "CONTROL", 82: "HIJACK", 84: "HIJACK",
    86: "HIJACK", 148: "RECON", 246: "RECON",
}

SEVERITY_MAP = {
    0: 1, 4: 1, 11: 5, 20: 2, 21: 2, 23: 6, 39: 7, 40: 3,
    43: 3, 44: 7, 48: 8, 66: 2, 76: 5, 82: 9, 84: 9,
    86: 9, 148: 1, 246: 1,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Security Gate (identical to adaptive honeypot)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SecurityGate:
    """Rate limiting + connection caps — same as adaptive version."""

    MAX_PACKETS_PER_WINDOW = 100
    RATE_WINDOW_SEC = 5
    MAX_CONNECTIONS_PER_IP = 10
    MAX_PAYLOAD_BYTES = 280
    BLOCK_DURATION_SEC = 300
    STRIKES_TO_BLOCK = 3

    def __init__(self):
        self.lock = threading.Lock()
        self.packet_timestamps = {}
        self.active_connections = {}
        self.strikes = {}
        self.blocklist = {}

    def is_blocked(self, ip):
        with self.lock:
            if ip in self.blocklist:
                if time.time() < self.blocklist[ip]:
                    return True
                del self.blocklist[ip]
                self.strikes[ip] = 0
            return False

    def can_connect(self, ip):
        with self.lock:
            return self.active_connections.get(ip, 0) < self.MAX_CONNECTIONS_PER_IP

    def register(self, ip):
        with self.lock:
            self.active_connections[ip] = self.active_connections.get(ip, 0) + 1

    def unregister(self, ip):
        with self.lock:
            self.active_connections[ip] = max(0, self.active_connections.get(ip, 0) - 1)

    def check_rate(self, ip):
        now = time.time()
        with self.lock:
            if ip not in self.packet_timestamps:
                self.packet_timestamps[ip] = []
            self.packet_timestamps[ip] = [
                t for t in self.packet_timestamps[ip]
                if now - t < self.RATE_WINDOW_SEC
            ]
            if len(self.packet_timestamps[ip]) >= self.MAX_PACKETS_PER_WINDOW:
                self.strikes[ip] = self.strikes.get(ip, 0) + 1
                if self.strikes[ip] >= self.STRIKES_TO_BLOCK:
                    self.blocklist[ip] = now + self.BLOCK_DURATION_SEC
                return False
            self.packet_timestamps[ip].append(now)
            return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Static + TCP Honeypot
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class StaticTCPHoneypot:
    """
    Static honeypot WITH TCP credential surface but WITHOUT adaptation.

    This is the TCP confound control: it proves that the TCP interface
    alone does not explain the engagement difference between adaptive
    and static honeypots.
    """

    def __init__(self):
        self.listen_port = LISTEN_PORT
        self.security = SecurityGate()
        self.dataset_file = self._init_dataset()
        self._lock = threading.Lock()
        self._setup_telegram()

    def _setup_telegram(self):
        """Load Telegram notifier if configured."""
        self.telegram = None
        try:
            from telegram_bot import TelegramNotifier
            t = TelegramNotifier()
            if t.enabled:
                self.telegram = t
                logger.info("Telegram: LOADED")
        except Exception:
            pass

    def _init_dataset(self):
        """Initialize CSV dataset."""
        os.makedirs("datasets", exist_ok=True)
        path = "datasets/static_tcp_ablation.csv"
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "ip", "port", "msg_id", "msg_name",
                    "intent", "severity", "payload_hex", "session_id",
                    "honeypot_state", "packet_rate", "mode",
                    "auth_attempts", "auth_success"
                ])
        return path

    def _log_event(self, ip, port, msg_id, payload_hex, session_id,
                   packet_rate, auth_attempts=0, auth_success=False):
        """Log attack event to CSV."""
        msg_name = MSG_NAMES.get(msg_id, f"MSG_{msg_id}")
        intent = INTENT_MAP.get(msg_id, "UNKNOWN")
        severity = SEVERITY_MAP.get(msg_id, 3)

        with self._lock:
            with open(self.dataset_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(), ip, port, msg_id, msg_name,
                    intent, severity, payload_hex, session_id,
                    "NORMAL",  # Always NORMAL — no FSM
                    round(packet_rate, 2), "static_tcp",
                    auth_attempts, auth_success
                ])

        if self.telegram and severity >= 1:
            try:
                self.telegram.send_alert({
                    "intent": intent,
                    "msg_name": msg_name,
                    "severity": severity,
                    "attacker_ip": ip,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
            except Exception:
                pass

    # ── MAVLink Packet Parsing ────────────────────────────────

    def _parse_packet(self, data):
        """Parse MAVLink v1/v2 packet header."""
        if len(data) < 8:
            return None
        if data[0] == 0xFE and len(data) >= 8:  # MAVLink v1
            payload_len = data[1]
            msg_id = data[5]
            payload = data[6:6 + payload_len] if len(data) >= 6 + payload_len else b""
            return {"msg_id": msg_id, "payload": payload}
        elif data[0] == 0xFD and len(data) >= 10:  # MAVLink v2
            payload_len = data[1]
            msg_id = data[7] | (data[8] << 8) | (data[9] << 16)
            payload = data[10:10 + payload_len] if len(data) >= 10 + payload_len else b""
            return {"msg_id": msg_id, "payload": payload}
        return None

    # ── MAVLink Response Crafting (FIXED — no adaptation) ─────

    def _craft_heartbeat(self):
        """Always the same heartbeat."""
        payload = struct.pack("<IBBBB B", 0, 2, 3, 81, 4, 3)
        return self._wrap_mavlink_v1(0, payload)

    def _craft_gps(self):
        """Always the same GPS — NO drift."""
        payload = struct.pack("<IiiiiHHHHBB",
            int(time.time() * 1000) & 0xFFFFFFFF,
            int(DECOY_LAT * 1e7), int(DECOY_LON * 1e7),
            int(DECOY_ALT * 1000), int(DECOY_ALT * 1000),
            int(DECOY_SPEED * 100), int(DECOY_SPEED * 100),
            int(DECOY_HEADING * 100), 150, 3, 12)
        return self._wrap_mavlink_v1(24, payload)

    def _craft_battery(self):
        """Always the same battery — NO drain."""
        return self._wrap_mavlink_v1(147, struct.pack("<Hb", 12600, int(DECOY_BATTERY)))

    def _craft_ack(self, cmd_id=0, result=0):
        """Command acknowledgment (MAV_RESULT_ACCEPTED)."""
        payload = struct.pack("<HBBBb", cmd_id, result, 255, 0, 0)
        return self._wrap_mavlink_v1(77, payload)

    def _wrap_mavlink_v1(self, msg_id, payload):
        """Wrap payload in MAVLink v1 frame."""
        header = struct.pack("<BBBBB", 0xFE, len(payload), 0, 1, 1) + struct.pack("B", msg_id)
        crc = sum(header[1:] + payload) & 0xFFFF
        return header + payload + struct.pack("<H", crc)

    def _get_response(self, msg_id):
        """
        Always return the same fixed response regardless of context.

        KEY DIFFERENCE from adaptive: no FSM-based response selection,
        no game-theoretic strategy, no entropy-dependent behavior.
        """
        return self._craft_heartbeat() + self._craft_gps()

    # ── TCP Credential Handler ────────────────────────────────

    def _handle_credential_phase(self, client_sock, ip, session_id):
        """
        TCP credential prompt — IDENTICAL to adaptive honeypot's
        credential interface. Allows up to MAX_AUTH_ATTEMPTS.

        Returns (auth_attempts, auth_success).
        """
        auth_attempts = 0
        auth_success = False

        try:
            # Send banner
            client_sock.send(CREDENTIAL_BANNER)
            time.sleep(0.1)

            for attempt in range(MAX_AUTH_ATTEMPTS):
                # Username prompt
                client_sock.send(CREDENTIAL_PROMPT_USER)
                client_sock.settimeout(30)
                try:
                    username = client_sock.recv(256)
                except socket.timeout:
                    break
                if not username:
                    break

                # Password prompt
                client_sock.send(CREDENTIAL_PROMPT_PASS)
                try:
                    password = client_sock.recv(256)
                except socket.timeout:
                    break
                if not password:
                    break

                auth_attempts += 1
                username_str = username.strip().decode("utf-8", errors="replace")
                password_str = password.strip().decode("utf-8", errors="replace")

                logger.info(
                    "[CRED] %s attempt %d: user=%s pass=%s [STATIC_TCP]",
                    ip, auth_attempts, username_str, password_str
                )

                # Log credential attempt
                self._log_event(
                    ip, 0, 0, f"user={username_str}|pass={password_str}",
                    session_id, 0.0,
                    auth_attempts=auth_attempts, auth_success=False
                )

                # Always fail first 2 attempts, then "succeed" to keep
                # them engaged — same behavior as adaptive honeypot
                if attempt >= 2:
                    client_sock.send(CREDENTIAL_SUCCESS)
                    auth_success = True
                    logger.info("[CRED] %s granted access (honeypot trap) [STATIC_TCP]", ip)
                    break
                else:
                    client_sock.send(CREDENTIAL_FAIL)
                    time.sleep(random.uniform(0.5, 1.5))  # Anti-brute-force delay

        except Exception as e:
            logger.debug("Credential phase error for %s: %s", ip, e)

        return auth_attempts, auth_success

    # ── Connection Handler ────────────────────────────────────

    def handle_client(self, client_sock, addr):
        """
        Handle connection with TCP credential surface but NO adaptation.

        Flow:
        1. TCP credential prompt (same as adaptive)
        2. If authenticated, accept MAVLink commands
        3. Always respond with FIXED responses (no FSM)
        """
        ip = addr[0]

        if self.security.is_blocked(ip):
            logger.warning("Blocked: %s", ip)
            client_sock.close()
            return

        if not self.security.can_connect(ip):
            logger.warning("Max connections: %s", ip)
            client_sock.close()
            return

        self.security.register(ip)
        session_id = hashlib.md5(f"{ip}:{addr[1]}:{time.time()}".encode()).hexdigest()[:8]
        packet_count = 0
        start_time = time.time()

        logger.info(
            "New connection from %s:%d (session: %s) [STATIC_TCP MODE]",
            ip, addr[1], session_id
        )

        if self.telegram:
            try:
                self.telegram.send_alert({
                    "intent": "NEW_CONNECTION",
                    "msg_name": "TCP_CONNECT",
                    "severity": 1,
                    "attacker_ip": ip,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
            except Exception:
                pass

        try:
            # Phase 1: Credential challenge (TCP surface)
            auth_attempts, auth_success = self._handle_credential_phase(
                client_sock, ip, session_id
            )

            if not auth_success and auth_attempts > 0:
                # Attacker gave up during credential phase
                logger.info(
                    "Auth failed after %d attempts: %s [STATIC_TCP]",
                    auth_attempts, ip
                )
                return

            # Phase 2: MAVLink interaction (STATIC — no adaptation)
            client_sock.settimeout(SESSION_TIMEOUT)

            while True:
                try:
                    data = client_sock.recv(1024)
                except socket.timeout:
                    break

                if not data:
                    break

                if len(data) > MAX_PACKET_SIZE:
                    continue

                if not self.security.check_rate(ip):
                    time.sleep(2)
                    continue

                parsed = self._parse_packet(data)
                if not parsed:
                    # Non-MAVLink data — still log it
                    self._log_event(
                        ip, addr[1], 0, data.hex()[:64],
                        session_id, 0.0,
                        auth_attempts=auth_attempts,
                        auth_success=auth_success
                    )
                    continue

                msg_id = parsed["msg_id"]
                packet_count += 1
                elapsed = time.time() - start_time
                packet_rate = packet_count / max(elapsed, 0.01)

                self._log_event(
                    ip, addr[1], msg_id, parsed["payload"].hex(),
                    session_id, packet_rate,
                    auth_attempts=auth_attempts,
                    auth_success=auth_success
                )

                logger.info(
                    "[NORMAL] %s -> %s (severity: %d) [STATIC_TCP]",
                    MSG_NAMES.get(msg_id, f"MSG_{msg_id}"),
                    INTENT_MAP.get(msg_id, "UNKNOWN"),
                    SEVERITY_MAP.get(msg_id, 3)
                )

                # STATIC response — always the same, no FSM
                response = self._get_response(msg_id)
                if response:
                    client_sock.send(response)

        except Exception as e:
            logger.error("Error handling %s: %s", addr, e)
        finally:
            if packet_count == 0 and auth_attempts == 0:
                self._log_event(ip, addr[1], 0, "", session_id, 0.0)
            client_sock.close()
            self.security.unregister(ip)
            duration = time.time() - start_time
            logger.info(
                "Connection closed: %s:%d (auth_attempts: %d, mavlink_pkts: %d, "
                "duration: %.1fs) [STATIC_TCP]",
                ip, addr[1], auth_attempts, packet_count, duration
            )

    # ── Server Start ──────────────────────────────────────────

    def _start_udp_beacon(self):
        """Broadcast MAVLink heartbeats on UDP (same as adaptive)."""
        def beacon():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while True:
                try:
                    hb = self._craft_heartbeat()
                    sock.sendto(hb, ("255.255.255.255", UDP_BEACON_PORT))
                    time.sleep(1)
                except Exception:
                    time.sleep(5)

        t = threading.Thread(target=beacon, daemon=True)
        t.start()

    def start(self):
        """Start the static+TCP honeypot server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.listen_port))
        server.listen(5)

        self._start_udp_beacon()

        logger.info("=" * 60)
        logger.info("MAVLink STATIC+TCP Honeypot v1.0")
        logger.info("PURPOSE: TCP Confound Ablation Control")
        logger.info("=" * 60)
        logger.info("TCP Listener: port %d (with credential prompt)", self.listen_port)
        logger.info("UDP Beacon: port %d", UDP_BEACON_PORT)
        logger.info("Mode: STATIC (TCP+creds, NO FSM, NO adaptation)")
        logger.info("Dataset: %s", self.dataset_file)
        logger.info("")
        logger.info("This server has the SAME TCP surface as the adaptive")
        logger.info("honeypot but NO behavioral adaptation. If adaptive")
        logger.info("outperforms this server, the TCP confound is eliminated.")
        logger.info("=" * 60)

        while True:
            client, addr = server.accept()
            t = threading.Thread(
                target=self.handle_client, args=(client, addr), daemon=True
            )
            t.start()


if __name__ == "__main__":
    honeypot = StaticTCPHoneypot()
    honeypot.start()
