#!/usr/bin/env python3
"""
MAVLink Honeypot — Dataset Exporter
Exports structured datasets for ML training and research reproducibility.
Includes metadata headers with export date, config hash, and data provenance.
"""

import os
import csv
import json
import glob
import hashlib
from datetime import datetime
from collections import defaultdict

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')


class DatasetExporter:
    """Export structured CSV/JSON datasets for ML retraining and analysis."""

    EXPORT_COLUMNS = [
        'timestamp', 'attacker_ip', 'attacker_port', 'msg_id', 'msg_name',
        'intent', 'severity', 'payload_hex', 'session_id',
        'fake_response_type', 'fake_gps_lat', 'fake_gps_lon',
        'fake_altitude', 'fake_battery', 'fake_heading', 'fake_speed',
        'honeypot_state',
    ]

    SESSION_COLUMNS = [
        'session_id', 'attacker_ip', 'start_time', 'end_time',
        'duration_sec', 'packet_count', 'unique_intents',
        'command_diversity', 'avg_severity', 'max_severity',
        'primary_attack_type', 'log_env',
    ]

    def __init__(self):
        os.makedirs(DATASETS_DIR, exist_ok=True)

    def _load_events(self) -> list:
        """Load all events from logs and existing datasets."""
        events = []

        # Load from log files
        log_files = sorted(glob.glob(os.path.join(LOGS_DIR, "*.log")))
        for lf in log_files:
            try:
                with open(lf, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('{'):
                            events.append(json.loads(line))
            except (json.JSONDecodeError, OSError):
                continue

        # Load from existing CSV datasets
        csv_files = sorted(glob.glob(os.path.join(DATASETS_DIR, "*.csv")))
        for cf in csv_files:
            try:
                with open(cf, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        events.append(row)
            except Exception:
                continue

        return events

    def _compute_config_hash(self) -> str:
        """Compute hash of current config for reproducibility."""
        try:
            from config import settings
            config_str = json.dumps(settings.model_dump(), sort_keys=True, default=str)
            return hashlib.sha256(config_str.encode()).hexdigest()[:16]
        except (ImportError, Exception):
            return "none"

    def export_events(
        self,
        output_path: str = None,
        date_range: tuple = None,
        attacker_ip: str = None,
        intent_filter: str = None,
        log_env: str = None,
        format: str = 'csv',
    ) -> str:
        """
        Export filtered event dataset.

        Args:
            output_path: Output file path (auto-generated if None)
            date_range: (start_iso, end_iso) tuple
            attacker_ip: Filter by IP
            intent_filter: Filter by intent type
            log_env: Filter by log environment ('prod' or 'test')
            format: 'csv' or 'json'

        Returns:
            Path to exported file
        """
        events = self._load_events()

        # Apply filters
        filtered = []
        for e in events:
            if attacker_ip and e.get('attacker_ip') != attacker_ip:
                continue
            if intent_filter and e.get('intent') != intent_filter:
                continue
            if log_env and e.get('log_env', 'prod') != log_env:
                continue
            if date_range:
                ts = e.get('timestamp', '')
                if ts < date_range[0] or ts > date_range[1]:
                    continue
            filtered.append(e)

        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            ext = 'json' if format == 'json' else 'csv'
            output_path = os.path.join(
                DATASETS_DIR, f'export_{timestamp}.{ext}'
            )

        config_hash = self._compute_config_hash()
        metadata = {
            'export_date': datetime.now().isoformat(),
            'config_hash': config_hash,
            'total_events': len(filtered),
            'filters': {
                'attacker_ip': attacker_ip,
                'intent': intent_filter,
                'date_range': date_range,
                'log_env': log_env,
            },
            'version': '2.0',
        }

        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump({'metadata': metadata, 'events': filtered},
                          f, indent=2, default=str)
        else:
            # CSV with metadata comment header
            with open(output_path, 'w', newline='') as f:
                f.write(f"# MAVLink Honeypot Dataset Export\n")
                f.write(f"# Date: {metadata['export_date']}\n")
                f.write(f"# Config Hash: {config_hash}\n")
                f.write(f"# Events: {len(filtered)}\n")
                f.write(f"# Version: {metadata['version']}\n")

                writer = csv.DictWriter(f, fieldnames=self.EXPORT_COLUMNS,
                                        extrasaction='ignore')
                writer.writeheader()
                for e in filtered:
                    writer.writerow(e)

        return output_path

    def export_sessions(self, output_path: str = None) -> str:
        """
        Export session-level features for ML training.

        Returns:
            Path to exported CSV
        """
        events = self._load_events()

        # Aggregate by session
        sessions = defaultdict(lambda: {
            'events': [], 'ips': set(), 'intents': set(),
            'msg_ids': set(), 'timestamps': [], 'severities': [],
        })

        for e in events:
            sid = e.get('session_id', 'unknown')
            sessions[sid]['events'].append(e)
            sessions[sid]['ips'].add(e.get('attacker_ip', ''))
            sessions[sid]['intents'].add(e.get('intent', 'UNKNOWN'))
            sessions[sid]['msg_ids'].add(e.get('msg_id', 0))
            sessions[sid]['timestamps'].append(e.get('timestamp', ''))
            try:
                sessions[sid]['severities'].append(int(e.get('severity', 0)))
            except (ValueError, TypeError):
                pass

        rows = []
        for sid, data in sessions.items():
            ts = sorted([t for t in data['timestamps'] if t])
            duration = 0.0
            if len(ts) >= 2:
                try:
                    t0 = datetime.fromisoformat(ts[0])
                    t1 = datetime.fromisoformat(ts[-1])
                    duration = (t1 - t0).total_seconds()
                except (ValueError, TypeError):
                    pass

            sevs = data['severities'] or [0]
            from collections import Counter
            intent_counts = Counter(
                e.get('intent', 'UNKNOWN') for e in data['events']
            )

            rows.append({
                'session_id': sid,
                'attacker_ip': sorted(data['ips'])[0] if data['ips'] else '',
                'start_time': ts[0] if ts else '',
                'end_time': ts[-1] if ts else '',
                'duration_sec': round(duration, 1),
                'packet_count': len(data['events']),
                'unique_intents': len(data['intents']),
                'command_diversity': len(data['msg_ids']),
                'avg_severity': round(sum(sevs) / len(sevs), 2),
                'max_severity': max(sevs),
                'primary_attack_type': intent_counts.most_common(1)[0][0],
                'log_env': data['events'][0].get('log_env', 'prod'),
            })

        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(
                DATASETS_DIR, f'sessions_{timestamp}.csv'
            )

        with open(output_path, 'w', newline='') as f:
            f.write(f"# Session-Level Dataset Export\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# Sessions: {len(rows)}\n")

            writer = csv.DictWriter(f, fieldnames=self.SESSION_COLUMNS)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        return output_path


if __name__ == "__main__":
    print("Dataset Exporter — Test")
    exporter = DatasetExporter()

    # Event export
    path = exporter.export_events()
    print(f"  Events exported to: {path}")

    # Session export
    path = exporter.export_sessions()
    print(f"  Sessions exported to: {path}")
