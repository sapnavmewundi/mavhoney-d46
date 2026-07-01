#!/usr/bin/env python3
"""
Immutable Daily Log Snapshot
Creates an append-only copy of honeypot logs once every 24 hours.
Each snapshot is accompanied by a SHA256 hash file for integrity verification.
"""

import os
import glob
import json
import hashlib
from datetime import datetime, date


def _snapshot_dir(base_dir: str) -> str:
    d = os.path.join(base_dir, 'logs', 'snapshots')
    os.makedirs(d, exist_ok=True)
    return d


def _today_tag() -> str:
    return date.today().isoformat()


def snapshot_exists_today(base_dir: str) -> bool:
    """Check if today's snapshot already exists."""
    snap = os.path.join(_snapshot_dir(base_dir), f'{_today_tag()}.jsonl')
    return os.path.exists(snap)


def create_daily_snapshot(base_dir: str) -> dict:
    """
    Create an append-only daily snapshot of all honeypot log events.
    Returns dict with path, line count, and sha256 hash.
    Skips if today's snapshot already exists (immutable).
    """
    snap_dir = _snapshot_dir(base_dir)
    tag = _today_tag()
    snap_path = os.path.join(snap_dir, f'{tag}.jsonl')
    hash_path = os.path.join(snap_dir, f'{tag}.sha256')

    # Immutable: never overwrite an existing snapshot
    if os.path.exists(snap_path):
        existing_hash = ''
        if os.path.exists(hash_path):
            existing_hash = open(hash_path).read().strip()
        line_count = sum(1 for _ in open(snap_path))
        return {
            'status': 'already_exists',
            'path': snap_path,
            'date': tag,
            'lines': line_count,
            'sha256': existing_hash,
        }

    # Collect all honeypot log events
    logs_dir = os.path.join(base_dir, 'logs')
    log_files = sorted(glob.glob(os.path.join(logs_dir, 'honeypot_*.log')))
    lines_written = 0
    hasher = hashlib.sha256()

    with open(snap_path, 'w') as out:
        for lf in log_files:
            try:
                with open(lf, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            json.loads(line)  # validate JSON
                        except json.JSONDecodeError:
                            continue
                        out.write(line + '\n')
                        hasher.update((line + '\n').encode())
                        lines_written += 1
            except Exception:
                continue

    sha256_hex = hasher.hexdigest()
    with open(hash_path, 'w') as hf:
        hf.write(sha256_hex + '\n')

    # Make snapshot read-only (immutable)
    try:
        os.chmod(snap_path, 0o444)
        os.chmod(hash_path, 0o444)
    except OSError:
        pass

    return {
        'status': 'created',
        'path': snap_path,
        'date': tag,
        'lines': lines_written,
        'sha256': sha256_hex,
    }


def get_snapshot_history(base_dir: str) -> list:
    """Return list of all existing snapshots with metadata."""
    snap_dir = _snapshot_dir(base_dir)
    snapshots = []
    for f in sorted(glob.glob(os.path.join(snap_dir, '*.jsonl')), reverse=True):
        tag = os.path.basename(f).replace('.jsonl', '')
        hash_file = f.replace('.jsonl', '.sha256')
        sha = ''
        if os.path.exists(hash_file):
            sha = open(hash_file).read().strip()
        line_count = sum(1 for _ in open(f))
        size_kb = round(os.path.getsize(f) / 1024, 1)
        snapshots.append({
            'date': tag,
            'lines': line_count,
            'size_kb': size_kb,
            'sha256': sha,
        })
    return snapshots
