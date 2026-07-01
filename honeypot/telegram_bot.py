#!/usr/bin/env python3
"""
MAVLink Honeypot — Telegram Bot (Interactive + Alerts)
======================================================

Two-way Telegram bot that provides:
- **Push alerts**: Real-time attack notifications (existing functionality)
- **Interactive commands**: Query honeypot state, block IPs, export data, etc.

Commands::

    /status   — Honeypot status + uptime
    /attacks  — Recent attack summary (last 20)
    /sessions — Active connection count
    /block    — Block an IP:  /block 1.2.3.4
    /unblock  — Unblock an IP: /unblock 1.2.3.4
    /stats    — Overall statistics
    /profile  — Attacker profile: /profile 1.2.3.4
    /health   — System health (CPU, memory, disk)
    /export   — Trigger dataset export
    /help     — List all commands
"""

import os
import csv
import json
import time
import socket
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'config', 'telegram.json'
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TelegramNotifier:
    """
    Interactive Telegram bot for the MAVLink Honeypot.

    Provides both push notifications (alerts) and pull interactions
    (commands) via Telegram Bot API long-polling.

    Setup:
    1. Create a bot via @BotFather on Telegram
    2. Get the bot token
    3. Start a chat with the bot and get the chat_id
    4. Save to config/telegram.json
    """

    # Rate limiting for alerts
    MIN_INTERVAL_SEC = 3     # Min 3 seconds between messages
    BATCH_WINDOW_SEC = 5     # Batch events within 5 seconds

    # Polling config
    POLL_INTERVAL_SEC = 2    # Check for commands every 2 seconds
    POLL_TIMEOUT_SEC = 30    # Long-polling timeout

    def __init__(self):
        self.bot_token = ""
        self.chat_id = ""
        self.enabled = False
        self.last_sent = 0
        self.pending_events = []
        self._batch_timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

        # Interactive command state
        self._honeypot_ref = None       # Reference to AdaptiveHoneypot instance
        self._start_time = datetime.now()
        self._last_update_id = 0
        self._poll_thread: Optional[threading.Thread] = None
        self._polling = False

        self._load_config()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Configuration
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _load_config(self):
        """Load Telegram config from file."""
        if not os.path.exists(CONFIG_PATH):
            self._create_template()
            return

        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
            self.bot_token = config.get("bot_token", "")
            self.chat_id = config.get("chat_id", "")
            self.enabled = bool(self.bot_token and self.chat_id
                                and self.bot_token != "YOUR_BOT_TOKEN_HERE")
            if self.enabled:
                print(f"✅ Telegram notifications enabled (chat: {self.chat_id})")
            else:
                print("ℹ️  Telegram not configured (edit config/telegram.json)")
        except Exception:
            self.enabled = False

    def _create_template(self):
        """Create template config file."""
        template = {
            "bot_token": "YOUR_BOT_TOKEN_HERE",
            "chat_id": "YOUR_CHAT_ID_HERE",
            "_instructions": [
                "1. Message @BotFather on Telegram to create a new bot",
                "2. Copy the bot token and paste it above",
                "3. Start a chat with your bot",
                "4. Visit: https://api.telegram.org/bot<TOKEN>/getUpdates",
                "5. Find your chat_id in the response and paste it above"
            ]
        }
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, 'w') as f:
                json.dump(template, f, indent=2)
        except Exception:
            pass

    def set_honeypot(self, honeypot) -> None:
        """Register the honeypot instance for interactive queries.

        Args:
            honeypot: The ``AdaptiveHoneypot`` instance to query.
        """
        self._honeypot_ref = honeypot
        self._start_time = datetime.now()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Message Sending (core)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _send_message(self, text: str, parse_mode: str = "HTML",
                      chat_id: str = "") -> bool:
        """Send a message to Telegram."""
        if not self.enabled or not REQUESTS_AVAILABLE:
            return False

        target_chat = chat_id or self.chat_id
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": target_chat,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        try:
            resp = requests.post(url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Push Alerts (existing functionality — unchanged)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def send_alert(self, event: dict):
        """
        Queue an attack alert for sending.
        Events are batched to avoid spam.
        """
        if not self.enabled:
            return

        with self._lock:
            self.pending_events.append(event)

            # If no batch timer is running, start one
            if self._batch_timer is None or not self._batch_timer.is_alive():
                self._batch_timer = threading.Timer(
                    self.BATCH_WINDOW_SEC, self._flush_batch
                )
                self._batch_timer.daemon = True
                self._batch_timer.start()

    def flush_now(self):
        """Force-flush any pending alerts immediately (call on session close)."""
        if self._batch_timer and self._batch_timer.is_alive():
            self._batch_timer.cancel()
        self._flush_batch()

    def _flush_batch(self):
        """Send all pending events as a single message."""
        with self._lock:
            events = self.pending_events[:]
            self.pending_events.clear()

        if not events:
            return

        # Rate limit
        elapsed = time.time() - self.last_sent
        if elapsed < self.MIN_INTERVAL_SEC:
            time.sleep(self.MIN_INTERVAL_SEC - elapsed)

        if len(events) == 1:
            text = self._format_single_alert(events[0])
        else:
            text = self._format_batch_alert(events)

        self._send_message(text)
        self.last_sent = time.time()

    def _format_single_alert(self, event: dict) -> str:
        """Format a single attack event."""
        severity = event.get("severity", 0)
        intent = event.get("intent", "UNKNOWN")
        ip = event.get("attacker_ip", "unknown")
        msg_name = event.get("msg_name", "")
        msg_id = event.get("msg_id", 0)
        timestamp = event.get("timestamp", "")
        payload_hex = event.get("payload_hex", "")
        honeypot_state = event.get("honeypot_state", "")

        # Determine if this is a REAL MAVLink attack (not just TCP probe)
        is_real_mavlink = (
            int(msg_id) > 0
            and msg_name != "NON_MAVLINK_PROBE"
            and intent != "SCANNER"
        )

        # Severity bar
        sev_filled = min(int(severity), 10)
        sev_bar = "🟥" * sev_filled + "⬜" * (10 - sev_filled)

        # Intent emoji
        intent_emoji = {
            "RECON": "🔍", "CONTROL": "🎮", "HIJACK": "✈️",
            "GPS_SPOOF": "📡", "MISSION_INJECT": "💉",
            "CONFIG_ATTACK": "⚙️", "SENSOR_SPOOF": "🌡️",
            "DOS_FLOOD": "🌊", "SCANNER": "🤖",
            "NEW_CONNECTION": "🔗", "UNKNOWN": "❓"
        }

        # GeoIP lookup (best-effort)
        country = self._lookup_country(ip)
        country_str = f" ({country})" if country else ""

        # FSM state indicator
        state_emoji = {
            "NORMAL": "🟢", "WEAK": "🟡", "CONFUSED": "🟠",
            "DEFENSIVE": "🔴", "CRASHED": "💀", "REBOOTING": "🔄",
            "PARTIAL": "⚡"
        }
        fsm_str = ""
        if honeypot_state:
            s_emoji = state_emoji.get(honeypot_state, "⚪")
            fsm_str = f"{s_emoji} <b>FSM:</b> {honeypot_state}\n"

        if is_real_mavlink:
            header = f"🚨 <b>MAVLINK ATTACK</b>\n"
            attack_detail = f"🎮 <b>msg_id:</b> {msg_id}\n"
            if payload_hex:
                attack_detail += f"📦 <code>{payload_hex[:32]}</code>\n"
        else:
            if intent == "NEW_CONNECTION":
                return (
                    f"🔗 <b>New connection</b>\n"
                    f"<code>{ip}</code>{country_str}\n"
                    f"🕐 {timestamp}"
                )
            header = f"⚡ <b>Event</b>\n"
            attack_detail = ""

        ie = intent_emoji.get(intent, '❓')
        return (
            f"{header}\n"
            f"{ie} {intent} → <b>{msg_name}</b>\n"
            f"{attack_detail}"
            f"{sev_bar} {severity}/10\n"
            f"🌐 <code>{ip}</code>{country_str}\n"
            f"{fsm_str}"
            f"🕐 {timestamp}"
        )

    def _format_batch_alert(self, events: list) -> str:
        """Format multiple events into one compact message."""
        total = len(events)
        max_severity = max(e.get("severity", 0) for e in events)
        unique_ips = set(e.get("attacker_ip", "") for e in events)
        intent_counts = {}
        real_mavlink_count = 0
        for e in events:
            intent = e.get("intent", "UNKNOWN")
            intent_counts[intent] = intent_counts.get(intent, 0) + 1
            msg_id = int(e.get("msg_id", 0))
            if msg_id > 0 and e.get("msg_name") != "NON_MAVLINK_PROBE" and intent != "SCANNER":
                real_mavlink_count += 1

        # Severity bar
        sev_filled = min(int(max_severity), 10)
        sev_bar = "🟥" * sev_filled + "⬜" * (10 - sev_filled)

        if real_mavlink_count > 0:
            header = f"🚨 <b>BURST — {total} events ({real_mavlink_count} MAVLink)</b>\n"
        else:
            header = f"⚡ <b>BURST — {total} events</b>\n"

        lines = [
            header,
            f"{sev_bar} peak {max_severity}/10",
            f"🌐 {len(unique_ips)} attacker(s)",
            "",
        ]

        for intent, count in sorted(intent_counts.items(), key=lambda x: -x[1])[:5]:
            pct = round(count / total * 100)
            bar = "█" * max(1, pct // 10)
            lines.append(f"  {intent}: {count}x {bar}")

        # Show top IPs
        ip_counts = {}
        for e in events:
            eip = e.get("attacker_ip", "?")
            ip_counts[eip] = ip_counts.get(eip, 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:3]
        if top_ips:
            lines.append("")
            for eip, cnt in top_ips:
                country = self._lookup_country(eip)
                c_str = f" {country}" if country else ""
                lines.append(f"  <code>{eip}</code>{c_str} ×{cnt}")

        t0 = events[0].get('timestamp', '')[-8:]
        t1 = events[-1].get('timestamp', '')[-8:]
        lines.append(f"\n🕐 {t0} → {t1}")

        return "\n".join(lines)

    def _lookup_country(self, ip: str) -> str:
        """Best-effort GeoIP lookup. Returns country code or empty string."""
        if not self._honeypot_ref:
            return ""
        try:
            geoip = getattr(self._honeypot_ref, 'geoip_service', None)
            if geoip:
                info = geoip.lookup(ip)
                return info.get('country_code', '') if info else ''
        except Exception:
            pass
        # Fallback: check attacker profiles
        try:
            profile = self._honeypot_ref.attacker_profiles.get(ip)
            if profile and hasattr(profile, 'country'):
                return profile.country
        except Exception:
            pass
        return ""

    def send_campaign_alert(self, campaign: dict):
        """Send alert about a detected campaign."""
        if not self.enabled:
            return

        text = (
            f"🎯 <b>CAMPAIGN DETECTED</b>\n\n"
            f"📋 <b>Name:</b> {campaign.get('name', 'Unknown')}\n"
            f"🏷️ <b>Type:</b> {campaign.get('campaign_type', 'UNKNOWN')}\n"
            f"⚠️ <b>Threat:</b> {campaign.get('threat_level', 'LOW')}\n"
            f"🌐 <b>IPs:</b> {len(campaign.get('attacker_ips', []))}\n"
            f"📊 <b>Events:</b> {campaign.get('total_events', 0)}\n"
            f"{'🔗 <b>Coordinated: YES</b>' if campaign.get('is_coordinated') else ''}\n\n"
            f"<i>MAVLink Honeypot — Drone Security Monitor</i>"
        )
        self._send_message(text)

    def send_daily_summary(self, stats: dict):
        """Send a daily summary of honeypot activity."""
        if not self.enabled:
            return

        text = (
            f"📊 <b>DAILY SUMMARY</b>\n\n"
            f"🎯 Total Attacks: {stats.get('total_attacks', 0)}\n"
            f"🌐 Unique Attackers: {stats.get('unique_attackers', 0)}\n"
            f"📈 Most Common: {stats.get('most_common_attack', 'N/A')}\n"
            f"⚡ Max Severity: {stats.get('max_severity', 0)}/10\n"
            f"🛡️ Deception Score: {stats.get('avg_deception_score', 0)}%\n"
            f"🔗 Active Campaigns: {stats.get('active_campaigns', 0)}\n\n"
            f"<i>MAVLink Honeypot — {datetime.now().strftime('%Y-%m-%d')}</i>"
        )
        self._send_message(text)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Interactive Command Polling
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def start_command_listener(self) -> None:
        """Start the background thread that listens for Telegram commands."""
        if not self.enabled:
            return
        if self._polling:
            return

        self._polling = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="TelegramCmdPoller"
        )
        self._poll_thread.start()
        print("🤖 Telegram command listener started (interactive mode)")

    def stop_command_listener(self) -> None:
        """Stop the command polling thread."""
        self._polling = False

    def _poll_loop(self) -> None:
        """Long-poll Telegram for incoming commands."""
        while self._polling:
            try:
                url = (
                    f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
                    f"?offset={self._last_update_id + 1}"
                    f"&timeout={self.POLL_TIMEOUT_SEC}"
                    f"&allowed_updates=[\"message\"]"
                )
                resp = requests.get(url, timeout=self.POLL_TIMEOUT_SEC + 5)
                if resp.status_code != 200:
                    time.sleep(self.POLL_INTERVAL_SEC)
                    continue

                data = resp.json()
                if not data.get("ok"):
                    time.sleep(self.POLL_INTERVAL_SEC)
                    continue

                for update in data.get("result", []):
                    self._last_update_id = update["update_id"]
                    message = update.get("message", {})
                    text = message.get("text", "").strip()
                    chat_id = str(message.get("chat", {}).get("id", ""))

                    # Only respond to authorized chat
                    if chat_id != str(self.chat_id):
                        continue

                    if text.startswith("/"):
                        self._handle_command(text, chat_id)

            except requests.exceptions.Timeout:
                continue
            except Exception:
                time.sleep(self.POLL_INTERVAL_SEC)

    def _handle_command(self, text: str, chat_id: str) -> None:
        """Route a command to its handler."""
        parts = text.split(maxsplit=1)
        command = parts[0].lower().split("@")[0]  # Strip @botname suffix
        args = parts[1].strip() if len(parts) > 1 else ""

        handlers = {
            "/start": self._cmd_help,
            "/help": self._cmd_help,
            "/status": self._cmd_status,
            "/attacks": self._cmd_attacks,
            "/sessions": self._cmd_sessions,
            "/block": self._cmd_block,
            "/unblock": self._cmd_unblock,
            "/stats": self._cmd_stats,
            "/profile": self._cmd_profile,
            "/health": self._cmd_health,
            "/export": self._cmd_export,
            "/top": self._cmd_top,
        }

        handler = handlers.get(command)
        if handler:
            try:
                response = handler(args)
            except Exception as e:
                response = f"❌ Error: {e}"
        else:
            response = f"❓ Unknown command: <code>{command}</code>\nUse /help for available commands."

        self._send_message(response, chat_id=chat_id)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Command Handlers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _cmd_help(self, args: str) -> str:
        """List all available commands."""
        return (
            "🍯 <b>MAVLink Honeypot</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "📊 <b>Monitor</b>\n"
            "  /status — Status + uptime\n"
            "  /attacks — Recent attacks\n"
            "  /sessions — Active connections\n"
            "  /stats — Overall statistics\n"
            "  /top — Most persistent attackers\n"
            "  /health — CPU / RAM / Disk\n\n"
            "🔍 <b>Investigate</b>\n"
            "  /profile &lt;ip&gt; — Attacker profile\n\n"
            "🛡️ <b>Defend</b>\n"
            "  /block &lt;ip&gt; — Block IP (24h)\n"
            "  /unblock &lt;ip&gt; — Unblock IP\n\n"
            "📦 <b>Export</b>\n"
            "  /export — Download dataset"
        )

    def _cmd_status(self, args: str) -> str:
        """Honeypot status overview."""
        uptime = datetime.now() - self._start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        total_events = 0
        unique_ips = 0
        honeypot_state = "UNKNOWN"
        blocked_count = 0

        if self._honeypot_ref:
            total_events = len(self._honeypot_ref.events)
            unique_ips = len(self._honeypot_ref.attacker_profiles)
            blocked_count = len(self._honeypot_ref.security.blocklist)

        # Try to get hostname
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        return (
            f"🍯 <b>HONEYPOT STATUS</b>\n\n"
            f"✅ <b>State:</b> RUNNING\n"
            f"🖥️ <b>Host:</b> <code>{hostname}</code>\n"
            f"⏱️ <b>Uptime:</b> {hours}h {minutes}m {seconds}s\n"
            f"🎯 <b>Total Events:</b> {total_events}\n"
            f"🌐 <b>Unique Attackers:</b> {unique_ips}\n"
            f"🚫 <b>Blocked IPs:</b> {blocked_count}\n"
            f"🕐 <b>Server Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"<i>Port 5760 — Adaptive Mode</i>"
        )

    def _cmd_attacks(self, args: str) -> str:
        """Show recent attacks."""
        events = []

        # Try live events first
        if self._honeypot_ref and self._honeypot_ref.events:
            events = self._honeypot_ref.events[-20:]
        else:
            # Fall back to CSV datasets
            events = self._read_recent_csv_events(20)

        if not events:
            return "📭 <b>No attacks recorded yet.</b>\n\nThe honeypot is waiting for traffic."

        lines = [f"🎯 <b>RECENT ATTACKS</b> ({len(events)} events)\n"]

        for e in events[-10:]:  # Show last 10 in detail
            if isinstance(e, dict):
                ip = e.get("attacker_ip", e.get("ip", "?"))
                intent = e.get("intent", "?")
                severity = e.get("severity", 0)
                msg_name = e.get("msg_name", "?")
                ts = e.get("timestamp", "?")
            else:
                # AttackEvent dataclass
                ip = e.attacker_ip
                intent = e.intent
                severity = e.severity
                msg_name = e.msg_name
                ts = e.timestamp

            sev_icon = "🔴" if int(severity) >= 8 else ("🟠" if int(severity) >= 5 else "🟡")
            # Truncate timestamp to time only
            time_str = str(ts).split("T")[-1][:8] if "T" in str(ts) else str(ts)[:8]

            lines.append(
                f"{sev_icon} <code>{ip}</code> → {intent} "
                f"({msg_name}) sev:{severity} @{time_str}"
            )

        return "\n".join(lines)

    def _cmd_sessions(self, args: str) -> str:
        """Show active sessions."""
        active = 0
        per_ip = {}

        if self._honeypot_ref:
            per_ip = dict(self._honeypot_ref.security.active_connections)
            active = sum(per_ip.values())

        if active == 0:
            return "📡 <b>No active connections.</b>\n\nHoneypot is idle."

        lines = [f"📡 <b>ACTIVE SESSIONS:</b> {active}\n"]
        for ip, count in sorted(per_ip.items(), key=lambda x: -x[1]):
            if count > 0:
                lines.append(f"  • <code>{ip}</code>: {count} connection(s)")

        return "\n".join(lines)

    def _cmd_block(self, args: str) -> str:
        """Block an IP address."""
        ip = args.strip()
        if not ip:
            return "⚠️ Usage: /block &lt;ip_address&gt;\nExample: /block 192.168.1.100"

        # Basic IP validation
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return f"❌ Invalid IP address: <code>{ip}</code>"

        if self._honeypot_ref:
            with self._honeypot_ref.security.lock:
                self._honeypot_ref.security.blocklist[ip] = (
                    time.time() + 86400  # Block for 24 hours
                )
            return (
                f"🚫 <b>BLOCKED:</b> <code>{ip}</code>\n"
                f"⏱️ Duration: 24 hours\n"
                f"📋 Reason: Manual block via Telegram"
            )

        return "⚠️ Honeypot not connected. Cannot block IP."

    def _cmd_unblock(self, args: str) -> str:
        """Unblock an IP address."""
        ip = args.strip()
        if not ip:
            return "⚠️ Usage: /unblock &lt;ip_address&gt;\nExample: /unblock 192.168.1.100"

        if self._honeypot_ref:
            with self._honeypot_ref.security.lock:
                if ip in self._honeypot_ref.security.blocklist:
                    del self._honeypot_ref.security.blocklist[ip]
                    self._honeypot_ref.security.strikes[ip] = 0
                    return f"✅ <b>UNBLOCKED:</b> <code>{ip}</code>"
                else:
                    return f"ℹ️ <code>{ip}</code> is not currently blocked."

        return "⚠️ Honeypot not connected. Cannot unblock IP."

    def _cmd_stats(self, args: str) -> str:
        """Overall honeypot statistics."""
        total_events = 0
        unique_ips = 0
        intent_counts: Dict[str, int] = {}
        max_severity = 0
        blocked = 0

        if self._honeypot_ref:
            total_events = len(self._honeypot_ref.events)
            unique_ips = len(self._honeypot_ref.attacker_profiles)
            blocked = len(self._honeypot_ref.security.blocklist)

            for e in self._honeypot_ref.events:
                intent = e.intent
                intent_counts[intent] = intent_counts.get(intent, 0) + 1
                max_severity = max(max_severity, e.severity)
        else:
            # Fall back to CSV
            csv_events = self._read_recent_csv_events(9999)
            total_events = len(csv_events)
            ips = set()
            for e in csv_events:
                ips.add(e.get("ip", e.get("attacker_ip", "")))
                intent = e.get("intent", "UNKNOWN")
                intent_counts[intent] = intent_counts.get(intent, 0) + 1
                max_severity = max(max_severity, int(e.get("severity", 0)))
            unique_ips = len(ips)

        if total_events == 0:
            return "📊 <b>No data yet.</b>\n\nWaiting for attack traffic."

        lines = [
            f"📊 <b>HONEYPOT STATISTICS</b>\n",
            f"🎯 <b>Total Events:</b> {total_events}",
            f"🌐 <b>Unique Attackers:</b> {unique_ips}",
            f"⚡ <b>Max Severity:</b> {max_severity}/10",
            f"🚫 <b>Blocked IPs:</b> {blocked}",
            "",
            "<b>Attack Distribution:</b>",
        ]

        for intent, count in sorted(intent_counts.items(), key=lambda x: -x[1]):
            pct = round(count / total_events * 100, 1)
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            lines.append(f"  {intent}: {count} ({pct}%)\n  {bar}")

        return "\n".join(lines)

    def _cmd_profile(self, args: str) -> str:
        """Look up an attacker profile."""
        ip = args.strip()
        if not ip:
            return "⚠️ Usage: /profile &lt;ip_address&gt;\nExample: /profile 223.31.218.223"

        profile = None
        if self._honeypot_ref and ip in self._honeypot_ref.attacker_profiles:
            p = self._honeypot_ref.attacker_profiles[ip]
            return (
                f"🔍 <b>ATTACKER PROFILE</b>\n\n"
                f"🌐 <b>IP:</b> <code>{ip}</code>\n"
                f"🏷️ <b>Threat Level:</b> {p.threat_level}\n"
                f"🎯 <b>Total Commands:</b> {p.total_commands}\n"
                f"⏱️ <b>First Seen:</b> {p.first_seen}\n"
                f"⏱️ <b>Last Seen:</b> {p.last_seen}\n"
                f"📈 <b>Max Severity:</b> {p.max_severity}/10\n"
                f"📋 <b>Intents:</b> {dict(p.intent_counts)}\n"
                f"🔗 <b>Behavior Hash:</b> <code>{p.behavior_signature}</code>"
            )

        # Try fingerprint backup file
        fp_file = os.path.join(BASE_DIR, "logs", "fingerprints_india_backup.json")
        if os.path.exists(fp_file):
            try:
                with open(fp_file, "r") as f:
                    fps = json.load(f)
                for fp_id, fp in fps.items():
                    if ip in fp.get("ips_used", []):
                        return (
                            f"🔍 <b>ATTACKER PROFILE (archived)</b>\n\n"
                            f"🌐 <b>IP:</b> <code>{ip}</code>\n"
                            f"🆔 <b>Fingerprint:</b> <code>{fp['fingerprint_id']}</code>\n"
                            f"🏷️ <b>Skill Level:</b> {fp.get('skill_level', '?')}\n"
                            f"⚠️ <b>Threat Score:</b> {fp.get('threat_score', 0)}/100\n"
                            f"📋 <b>Preferred Attacks:</b> {fp.get('preferred_attacks', {})}\n"
                            f"⏱️ <b>First Seen:</b> {fp.get('first_seen', '?')}\n"
                            f"📊 <b>Sessions:</b> {fp.get('sessions', 0)}"
                        )
            except Exception:
                pass

        return f"📭 No profile found for <code>{ip}</code>"

    def _cmd_health(self, args: str) -> str:
        """System health status."""
        if not PSUTIL_AVAILABLE:
            return "⚠️ psutil not installed. Cannot check system health."

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Status indicators
        cpu_icon = "🔴" if cpu > 90 else ("🟠" if cpu > 70 else "🟢")
        mem_icon = "🔴" if mem.percent > 90 else ("🟠" if mem.percent > 70 else "🟢")
        disk_icon = "🔴" if disk.percent > 90 else ("🟠" if disk.percent > 70 else "🟢")

        # Network connections on port 5760
        honey_conns = 0
        try:
            for conn in psutil.net_connections():
                if conn.laddr and conn.laddr.port == 5760 and conn.status == "ESTABLISHED":
                    honey_conns += 1
        except Exception:
            honey_conns = -1

        return (
            f"🏥 <b>SYSTEM HEALTH</b>\n\n"
            f"{cpu_icon} <b>CPU:</b> {cpu}%\n"
            f"{mem_icon} <b>Memory:</b> {mem.percent}% "
            f"({mem.used // (1024**2)}MB / {mem.total // (1024**2)}MB)\n"
            f"{disk_icon} <b>Disk:</b> {disk.percent}% "
            f"({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)\n"
            f"📡 <b>Honeypot Connections:</b> {honey_conns}\n"
            f"🕐 <b>Server Time:</b> {datetime.now().strftime('%H:%M:%S')}"
        )

    def _cmd_top(self, args: str) -> str:
        """Show most persistent attackers."""
        if not self._honeypot_ref or not self._honeypot_ref.attacker_profiles:
            # Fallback to CSV
            csv_events = self._read_recent_csv_events(9999)
            if not csv_events:
                return "📭 No attacker data yet."

            ip_counts = {}
            for e in csv_events:
                eip = e.get("ip", e.get("attacker_ip", ""))
                if eip:
                    ip_counts[eip] = ip_counts.get(eip, 0) + 1
        else:
            ip_counts = {}
            for ip, p in self._honeypot_ref.attacker_profiles.items():
                ip_counts[ip] = p.total_commands

        if not ip_counts:
            return "📭 No attacker data yet."

        top = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]

        lines = [f"🏆 <b>TOP ATTACKERS</b>\n"]

        medals = ["🥇", "🥈", "🥉"]
        for i, (ip, count) in enumerate(top):
            medal = medals[i] if i < 3 else f" {i+1}."
            country = self._lookup_country(ip)
            c_str = f" {country}" if country else ""

            # Threat level from profile if available
            threat = ""
            if self._honeypot_ref and ip in self._honeypot_ref.attacker_profiles:
                p = self._honeypot_ref.attacker_profiles[ip]
                threat = f" | {p.threat_level}" if hasattr(p, 'threat_level') else ""

            lines.append(
                f"{medal} <code>{ip}</code>{c_str}\n"
                f"     {count} cmds{threat}"
            )

        return "\n".join(lines)

    def _cmd_export(self, args: str) -> str:
        """Trigger dataset export."""
        if not self._honeypot_ref:
            return "⚠️ Honeypot not connected. Cannot export."

        events = self._honeypot_ref.events
        if not events:
            return "📭 No events to export."

        # Export to a timestamped CSV
        export_dir = os.path.join(BASE_DIR, "datasets")
        os.makedirs(export_dir, exist_ok=True)
        filename = f"telegram_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(export_dir, filename)

        try:
            fields = [
                "timestamp", "attacker_ip", "attacker_port", "msg_id",
                "msg_name", "intent", "severity", "honeypot_state",
                "fake_response_type", "anomaly_flag", "anomaly_score",
            ]
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for e in events:
                    row = {k: getattr(e, k, "") for k in fields}
                    writer.writerow(row)

            return (
                f"📦 <b>EXPORT COMPLETE</b>\n\n"
                f"📄 <b>File:</b> <code>{filename}</code>\n"
                f"📊 <b>Events:</b> {len(events)}\n"
                f"📂 <b>Path:</b> <code>datasets/{filename}</code>"
            )
        except Exception as e:
            return f"❌ Export failed: {e}"

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CSV Fallback Reader
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _read_recent_csv_events(self, max_count: int = 20) -> List[dict]:
        """Read recent events from CSV dataset files as fallback."""
        events = []
        datasets_dir = os.path.join(BASE_DIR, "datasets")

        if not os.path.isdir(datasets_dir):
            return events

        csv_files = sorted(
            [f for f in os.listdir(datasets_dir) if f.endswith(".csv")],
            reverse=True,
        )

        for csv_file in csv_files[:3]:  # Check last 3 files
            try:
                filepath = os.path.join(datasets_dir, csv_file)
                with open(filepath, "r") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get("timestamp"):
                            events.append(row)
            except Exception:
                continue

        # Sort by timestamp descending, take the most recent
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return events[:max_count]

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Connection Test
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def test_connection(self) -> dict:
        """Test the Telegram bot connection."""
        if not REQUESTS_AVAILABLE:
            return {"ok": False, "error": "requests library not installed"}
        if not self.bot_token or self.bot_token == "YOUR_BOT_TOKEN_HERE":
            return {"ok": False, "error": "Bot token not configured"}

        url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("ok"):
                bot_info = data["result"]
                return {
                    "ok": True,
                    "bot_name": bot_info.get("first_name", ""),
                    "bot_username": bot_info.get("username", ""),
                }
            else:
                return {"ok": False, "error": data.get("description", "Unknown error")}
        except Exception as e:
            return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    print("📱 Telegram Bot — Test")

    bot = TelegramNotifier()
    print(f"  Enabled: {bot.enabled}")

    result = bot.test_connection()
    print(f"  Connection: {result}")

    if bot.enabled:
        # Test alert
        bot.send_alert({
            "intent": "GPS_SPOOF",
            "msg_name": "SET_GPS_GLOBAL_ORIGIN",
            "severity": 8,
            "attacker_ip": "10.0.0.100",
            "timestamp": datetime.now().isoformat(),
        })
        print("  Test alert queued!")

        # Start interactive mode
        print("  Starting command listener (Ctrl+C to stop)...")
        bot.start_command_listener()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            bot.stop_command_listener()
            print("\n  Stopped.")
