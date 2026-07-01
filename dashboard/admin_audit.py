#!/usr/bin/env python3
"""
Admin Audit Logger — Accountability Logging for Dashboard Actions
Logs all admin access actions (login, logout, data export, config changes)
to a structured JSON audit log for accountability and forensic review.
"""

import os
import json
import time
import hashlib
import functools
from datetime import datetime
from flask import request, session

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.logger import get_logger

logger = get_logger("admin.audit")

AUDIT_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'admin_audit.log'
)


class AdminAuditLogger:
    """Structured audit logger for all admin/dashboard actions."""

    ACTIONS = {
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT',
        'DATA_EXPORT', 'CONFIG_CHANGE', 'SESSION_EXPIRED',
        'API_ACCESS', 'REPORT_GENERATED', 'DATASET_EXPORTED',
        'TOTP_SETUP', 'ROLE_CHANGE', 'SESSION_VERIFY',
    }

    def __init__(self):
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        self._previous_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Get hash of last audit entry for chain integrity."""
        if not os.path.exists(AUDIT_LOG):
            return "0" * 64
        try:
            with open(AUDIT_LOG, 'r') as f:
                lines = f.readlines()
            if lines:
                last = json.loads(lines[-1])
                return last.get('entry_hash', "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def log(self, action: str, user_ip: str = None, details: dict = None):
        """
        Log an admin action with full context.

        Args:
            action: One of ACTIONS (e.g., 'LOGIN_SUCCESS')
            user_ip: IP address of the admin user
            details: Optional dict with extra context
        """
        if user_ip is None:
            try:
                user_ip = request.remote_addr or '0.0.0.0'
            except RuntimeError:
                user_ip = '0.0.0.0'

        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'ip': user_ip,
            'user_agent': '',
            'session_id': '',
            'details': details or {},
        }

        # Capture user agent and session if available
        try:
            entry['user_agent'] = request.headers.get('User-Agent', '')[:200]
            entry['session_id'] = hashlib.sha256(
                str(session.get('_id', '')).encode()
            ).hexdigest()[:16]
        except RuntimeError:
            pass

        # Hash chain for integrity
        content = json.dumps(entry, sort_keys=True)
        chain_input = f"{self._previous_hash}{content}"
        entry_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        entry['entry_hash'] = entry_hash
        entry['previous_hash'] = self._previous_hash
        self._previous_hash = entry_hash

        # Write to audit log
        try:
            with open(AUDIT_LOG, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as ex:
            logger.error("Failed to write audit log: %s", ex)

        # Also log to structured logger
        logger.info(
            "AUDIT: %s from %s — %s",
            action, user_ip, json.dumps(details or {})
        )

    def verify_integrity(self) -> dict:
        """
        Verify the hash chain integrity of the audit log.

        Returns:
            {'valid': bool, 'total_entries': int, 'first_invalid': int or None}
        """
        if not os.path.exists(AUDIT_LOG):
            return {'valid': True, 'total_entries': 0, 'first_invalid': None}

        with open(AUDIT_LOG, 'r') as f:
            lines = f.readlines()

        prev_hash = "0" * 64
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line.strip())
                stored_hash = entry.pop('entry_hash', '')
                stored_prev = entry.pop('previous_hash', '')

                if stored_prev != prev_hash:
                    return {'valid': False, 'total_entries': len(lines),
                            'first_invalid': i + 1}

                content = json.dumps(entry, sort_keys=True)
                expected = hashlib.sha256(
                    f"{prev_hash}{content}".encode()
                ).hexdigest()

                if expected != stored_hash:
                    return {'valid': False, 'total_entries': len(lines),
                            'first_invalid': i + 1}

                prev_hash = stored_hash
            except (json.JSONDecodeError, KeyError):
                return {'valid': False, 'total_entries': len(lines),
                        'first_invalid': i + 1}

        return {'valid': True, 'total_entries': len(lines), 'first_invalid': None}

    def get_recent(self, limit: int = 50) -> list:
        """Get most recent audit entries."""
        if not os.path.exists(AUDIT_LOG):
            return []

        with open(AUDIT_LOG, 'r') as f:
            lines = f.readlines()

        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

        return list(reversed(entries))


# Singleton
audit_logger = AdminAuditLogger()


def audit_action(action: str, details_fn=None):
    """
    Decorator to automatically audit a route action.

    Usage:
        @app.route('/api/export')
        @login_required
        @audit_action('DATA_EXPORT', lambda: {'format': request.args.get('format')})
        def export_data():
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            details = details_fn() if details_fn else {}
            audit_logger.log(action, details=details)
            return f(*args, **kwargs)
        return wrapper
    return decorator
