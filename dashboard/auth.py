#!/usr/bin/env python3
"""
TOTP Authentication for Defender Dashboard
Works with Google Authenticator / Microsoft Authenticator

Security improvements:
- Secrets loaded from env vars first, file fallback with warning
- Strict file permissions on secret storage
- Login attempt rate limiting
- Failed attempt logging
- Session expiry (configurable timeout)
"""

import pyotp
import qrcode
import os
import io
import sys
import stat
import time
import base64
import functools
from collections import defaultdict
from flask import session, redirect, url_for, request

# Logger
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.logger import get_logger

logger = get_logger("dashboard.auth")

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
SECRET_FILE = os.path.join(CONFIG_DIR, 'totp_secret.key')


class TOTPManager:
    """Manages TOTP authentication for the defender dashboard."""

    APP_NAME = "MAVLink Honeypot"
    ISSUER = "HoneypotDefender"

    # Session expiry in seconds (default 30 minutes)
    SESSION_EXPIRY_SEC = 1800

    def __init__(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        self.secret = self._load_secret()
        self.totp = pyotp.TOTP(self.secret)

        # Rate limiting for login attempts
        self._attempts: dict = defaultdict(list)  # ip -> [timestamps]
        self._max_attempts = 5
        self._lockout_sec = 60

        # Load rate limits and session expiry from config if available
        try:
            from config import settings
            self._max_attempts = settings.login_max_attempts
            self._lockout_sec = settings.login_lockout_sec
            if hasattr(settings, 'session_expiry_sec'):
                self.SESSION_EXPIRY_SEC = settings.session_expiry_sec
        except ImportError:
            pass

    def _load_secret(self) -> str:
        """
        Load TOTP secret with priority:
        1. TOTP_SECRET env var (most secure)
        2. Existing secret file (fallback with warning)
        3. Generate new secret (first run)
        """
        # Priority 1: Environment variable
        env_secret = os.environ.get("TOTP_SECRET", "").strip()
        if env_secret:
            logger.info("TOTP secret loaded from environment variable")
            return env_secret

        # Also check config
        try:
            from config import settings
            if settings.totp_secret:
                logger.info("TOTP secret loaded from config")
                return settings.totp_secret
        except ImportError:
            pass

        # Priority 2: Existing file
        if os.path.exists(SECRET_FILE):
            logger.warning(
                "TOTP secret loaded from file %s — consider migrating to "
                "TOTP_SECRET env var for better security", SECRET_FILE
            )
            with open(SECRET_FILE, 'r') as f:
                return f.read().strip()

        # Priority 3: Generate new secret
        secret = pyotp.random_base32()

        # Write with restrictive permissions (owner read/write only)
        with open(SECRET_FILE, 'w') as f:
            f.write(secret)
        try:
            os.chmod(SECRET_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            pass  # Windows doesn't support chmod

        logger.info("New TOTP secret generated. Scan QR at /setup to register.")
        logger.warning(
            "Secret stored in %s — set TOTP_SECRET env var for production",
            SECRET_FILE
        )

        return secret

    def check_rate_limit(self, ip: str) -> bool:
        """
        Check if login attempts are rate limited.

        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        # Clean old attempts
        self._attempts[ip] = [
            t for t in self._attempts[ip]
            if now - t < self._lockout_sec
        ]

        if len(self._attempts[ip]) >= self._max_attempts:
            remaining = int(self._lockout_sec - (now - self._attempts[ip][0]))
            logger.warning(
                "Login rate limited for %s — %d attempts in %ds, lockout %ds remaining",
                ip, len(self._attempts[ip]), self._lockout_sec, remaining
            )
            return False

        return True

    def record_attempt(self, ip: str, success: bool):
        """Record a login attempt for rate limiting."""
        self._attempts[ip].append(time.time())
        if success:
            logger.info("Successful login from %s", ip)
            # Clear attempts on success
            self._attempts[ip] = []
        else:
            logger.warning(
                "Failed login attempt from %s (attempt %d/%d)",
                ip, len(self._attempts[ip]), self._max_attempts
            )

    def verify(self, code: str) -> bool:
        """Verify a 6-digit TOTP code."""
        try:
            return self.totp.verify(code, valid_window=1)
        except (ValueError, TypeError) as e:
            logger.debug("TOTP verification error: %s", e)
            return False

    def get_provisioning_uri(self) -> str:
        """Get the URI for QR code generation."""
        return self.totp.provisioning_uri(
            name="defender@honeypot",
            issuer_name=self.ISSUER
        )

    def get_qr_base64(self) -> str:
        """Generate QR code as base64 image for embedding in HTML."""
        uri = self.get_provisioning_uri()
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')

    def is_first_run(self) -> bool:
        """Check if this is a fresh setup (no successful auth yet)."""
        marker = os.path.join(CONFIG_DIR, '.totp_configured')
        return not os.path.exists(marker)

    def mark_configured(self):
        """Mark TOTP as configured after first successful auth."""
        marker = os.path.join(CONFIG_DIR, '.totp_configured')
        with open(marker, 'w') as f:
            f.write('configured')


def login_required(f):
    """Decorator to protect routes with TOTP auth and session expiry."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))

        # Check session expiry
        login_time = session.get('login_time', 0)
        elapsed = time.time() - login_time
        if elapsed > TOTPManager.SESSION_EXPIRY_SEC:
            logger.info("Session expired for %s after %ds",
                       request.remote_addr, int(elapsed))
            session.pop('authenticated', None)
            session.pop('login_time', None)
            # Try to log audit event if audit logger available
            try:
                from dashboard.admin_audit import audit_logger
                audit_logger.log('SESSION_EXPIRED', details={
                    'elapsed_sec': int(elapsed)
                })
            except ImportError:
                pass
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated
