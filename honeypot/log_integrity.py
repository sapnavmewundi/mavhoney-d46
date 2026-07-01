#!/usr/bin/env python3
"""
MAVLink Honeypot — Log Integrity Protection
Hash-chain integrity for log files, ensuring tampered or deleted entries
are detectable. Each log entry gets a SHA-256 hash of (previous_hash + content).
"""

import os
import json
import hashlib
import time
from datetime import datetime
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.logger import get_logger

logger = get_logger("log_integrity")

GENESIS_HASH = "0" * 64


class IntegrityProtectedLog:
    """
    Hash-chain protected log writer and verifier.

    Each entry includes:
    - Content hash
    - Previous entry hash
    - Entry hash = SHA-256(previous_hash + content_json)

    Tampering with any entry breaks the chain, detectable by verify().
    """

    def __init__(self, log_path: str, log_env: str = "prod"):
        self.log_path = log_path
        self.log_env = log_env
        self._previous_hash = GENESIS_HASH

        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # Resume from last entry if log exists
        if os.path.exists(log_path):
            self._previous_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Get hash of the last entry in the log."""
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
            if lines:
                last = json.loads(lines[-1].strip())
                return last.get('_hash', GENESIS_HASH)
        except Exception:
            pass
        return GENESIS_HASH

    def write(self, data: dict) -> str:
        """
        Write a hash-chain protected log entry.

        Args:
            data: Dictionary of log data to write

        Returns:
            The entry hash
        """
        entry = {
            '_ts': datetime.now().isoformat(),
            '_env': self.log_env,
            '_seq': self._count_entries(),
            **data,
        }

        # Compute hash chain
        content = json.dumps(entry, sort_keys=True, default=str)
        chain_input = f"{self._previous_hash}{content}"
        entry_hash = hashlib.sha256(chain_input.encode()).hexdigest()

        entry['_prev_hash'] = self._previous_hash
        entry['_hash'] = entry_hash
        self._previous_hash = entry_hash

        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry, default=str) + '\n')

        return entry_hash

    def _count_entries(self) -> int:
        """Count existing entries."""
        if not os.path.exists(self.log_path):
            return 0
        try:
            with open(self.log_path, 'r') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def verify(self) -> dict:
        """
        Verify the entire hash chain integrity.

        Returns:
            {
                'valid': bool,
                'total_entries': int,
                'first_invalid': int or None (1-indexed),
                'errors': list of str
            }
        """
        if not os.path.exists(self.log_path):
            return {'valid': True, 'total_entries': 0,
                    'first_invalid': None, 'errors': []}

        with open(self.log_path, 'r') as f:
            lines = f.readlines()

        prev_hash = GENESIS_HASH
        errors = []

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Entry {i + 1}: invalid JSON")
                return {'valid': False, 'total_entries': len(lines),
                        'first_invalid': i + 1, 'errors': errors}

            stored_hash = entry.pop('_hash', '')
            stored_prev = entry.pop('_prev_hash', '')

            # Check chain linkage
            if stored_prev != prev_hash:
                errors.append(
                    f"Entry {i + 1}: chain break — expected prev_hash "
                    f"{prev_hash[:16]}..., got {stored_prev[:16]}..."
                )
                return {'valid': False, 'total_entries': len(lines),
                        'first_invalid': i + 1, 'errors': errors}

            # Recompute hash
            content = json.dumps(entry, sort_keys=True, default=str)
            expected = hashlib.sha256(
                f"{prev_hash}{content}".encode()
            ).hexdigest()

            if expected != stored_hash:
                errors.append(
                    f"Entry {i + 1}: hash mismatch — content tampered"
                )
                return {'valid': False, 'total_entries': len(lines),
                        'first_invalid': i + 1, 'errors': errors}

            prev_hash = stored_hash

        return {
            'valid': True,
            'total_entries': len(lines),
            'first_invalid': None,
            'errors': [],
        }

    def get_entries(self, env_filter: str = None, limit: int = 100) -> list:
        """Get log entries with optional env filter."""
        if not os.path.exists(self.log_path):
            return []

        entries = []
        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if env_filter and entry.get('_env') != env_filter:
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries[-limit:]


class IntegrityMonitor:
    """Monitor multiple integrity-protected logs."""

    def __init__(self, logs_dir: str = None):
        if logs_dir is None:
            logs_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'logs'
            )
        self.logs_dir = logs_dir

    def verify_all(self) -> dict:
        """Verify all integrity-protected logs in the logs directory."""
        results = {}
        for fname in os.listdir(self.logs_dir):
            if fname.endswith('.integrity.log'):
                log_path = os.path.join(self.logs_dir, fname)
                ipl = IntegrityProtectedLog(log_path)
                results[fname] = ipl.verify()
        return results


if __name__ == "__main__":
    import tempfile

    print("Log Integrity — Test")

    # Create a temp log
    tmp = tempfile.mktemp(suffix='.integrity.log')
    ipl = IntegrityProtectedLog(tmp, log_env='test')

    # Write entries
    for i in range(5):
        h = ipl.write({'event': f'test_{i}', 'severity': i})
        print(f"  Entry {i}: hash={h[:16]}...")

    # Verify
    result = ipl.verify()
    print(f"\n  Verification: valid={result['valid']}, "
          f"entries={result['total_entries']}")

    # Tamper with an entry
    with open(tmp, 'r') as f:
        lines = f.readlines()
    if len(lines) > 2:
        entry = json.loads(lines[2])
        entry['event'] = 'TAMPERED'
        lines[2] = json.dumps(entry) + '\n'
        with open(tmp, 'w') as f:
            f.writelines(lines)

    # Verify after tampering
    ipl2 = IntegrityProtectedLog(tmp)
    result2 = ipl2.verify()
    print(f"  After tamper: valid={result2['valid']}, "
          f"first_invalid={result2['first_invalid']}")
    if result2['errors']:
        print(f"  Error: {result2['errors'][0]}")

    os.unlink(tmp)
