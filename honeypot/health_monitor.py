#!/usr/bin/env python3
"""
MAVLink Honeypot — Health Monitor / Anti-Compromise
Self-defense module that detects if the honeypot itself is being
compromised, modified, or resource-exhausted.
"""

import os
import sys
import json
import time
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEALTH_FILE = os.path.join(PROJECT_ROOT, 'logs', 'health_status.json')
INTEGRITY_FILE = os.path.join(PROJECT_ROOT, 'logs', 'file_integrity.json')


@dataclass
class HealthAlert:
    """A health/integrity alert."""
    alert_id: str
    severity: str         # INFO, WARNING, CRITICAL
    alert_type: str       # FILE_MODIFIED, HIGH_CPU, HIGH_MEM, OUTBOUND_CONN, PROCESS_SPAWN, CRASH
    message: str
    timestamp: str
    details: dict = field(default_factory=dict)
    acknowledged: bool = False


@dataclass
class HealthStatus:
    """Current health snapshot."""
    status: str = "HEALTHY"          # HEALTHY, DEGRADED, COMPROMISED
    uptime_sec: float = 0
    cpu_percent: float = 0
    memory_percent: float = 0
    disk_percent: float = 0
    open_connections: int = 0
    active_threads: int = 0
    file_integrity: str = "OK"       # OK, MODIFIED, UNKNOWN
    last_check: str = ""
    alerts: List[dict] = field(default_factory=list)
    total_alerts: int = 0
    critical_alerts: int = 0


class HealthMonitor:
    """
    Self-defense module for the honeypot:
    1. File integrity monitoring (hash checks)
    2. Resource monitoring (CPU, memory, disk)
    3. Process monitoring (unexpected children)
    4. Network monitoring (outbound connections)
    5. Heartbeat / watchdog
    """

    # Thresholds
    CPU_WARNING = 80       # %
    CPU_CRITICAL = 95
    MEM_WARNING = 80       # %
    MEM_CRITICAL = 95
    DISK_WARNING = 90      # %
    CONNECTION_WARNING = 50
    CONNECTION_CRITICAL = 200
    CHECK_INTERVAL = 30    # seconds

    # Files to monitor for integrity
    MONITORED_FILES = [
        'honeypot/mavlink_honeypot.py',
        'honeypot/fingerprint.py',
        'honeypot/deception_engine.py',
        'honeypot/database.py',
        'honeypot/geoip_service.py',
        'dashboard/app.py',
        'dashboard/auth.py',
        'config/telegram.json',
    ]

    def __init__(self):
        self.start_time = time.time()
        self.file_hashes: Dict[str, str] = {}
        self.alerts: List[HealthAlert] = []
        self.status = HealthStatus()
        self.monitor_thread = None
        self.running = False
        self._baseline_integrity()
        self._load_alerts()

    def _baseline_integrity(self):
        """Calculate baseline file hashes."""
        saved = self._load_integrity()
        new_hashes = {}

        for rel_path in self.MONITORED_FILES:
            full_path = os.path.join(PROJECT_ROOT, rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    new_hashes[rel_path] = file_hash
                except Exception:
                    new_hashes[rel_path] = "ERROR"

        if saved:
            # Compare with saved baseline
            for path, new_hash in new_hashes.items():
                old_hash = saved.get(path)
                if old_hash and old_hash != new_hash and new_hash != "ERROR":
                    self._add_alert(
                        severity="CRITICAL",
                        alert_type="FILE_MODIFIED",
                        message=f"File integrity violation: {path} has been modified",
                        details={"file": path, "old_hash": old_hash[:16], "new_hash": new_hash[:16]}
                    )

        self.file_hashes = new_hashes
        self._save_integrity()

    def _load_integrity(self) -> dict:
        if os.path.exists(INTEGRITY_FILE):
            try:
                with open(INTEGRITY_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_integrity(self):
        try:
            os.makedirs(os.path.dirname(INTEGRITY_FILE), exist_ok=True)
            with open(INTEGRITY_FILE, 'w') as f:
                json.dump(self.file_hashes, f, indent=2)
        except Exception:
            pass

    def _load_alerts(self):
        if os.path.exists(HEALTH_FILE):
            try:
                with open(HEALTH_FILE, 'r') as f:
                    data = json.load(f)
                self.alerts = [
                    HealthAlert(**a) for a in data.get("alerts", [])[-100:]
                ]
            except Exception:
                pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(HEALTH_FILE), exist_ok=True)
            with open(HEALTH_FILE, 'w') as f:
                json.dump({
                    "status": asdict(self.status),
                    "alerts": [asdict(a) for a in self.alerts[-100:]],
                    "last_updated": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception:
            pass

    def _add_alert(self, severity: str, alert_type: str, message: str,
                   details: dict = None):
        """Add a health alert."""
        alert = HealthAlert(
            alert_id=hashlib.md5(
                f"{alert_type}:{time.time()}".encode()
            ).hexdigest()[:12],
            severity=severity,
            alert_type=alert_type,
            message=message,
            timestamp=datetime.now().isoformat(),
            details=details or {},
        )
        self.alerts.append(alert)
        self.status.total_alerts += 1
        if severity == "CRITICAL":
            self.status.critical_alerts += 1

    # ── Health Checks ──

    def check_resources(self) -> dict:
        """Check CPU, memory, and disk usage."""
        result = {"cpu": 0, "memory": 0, "disk": 0, "alerts": []}

        if not PSUTIL_AVAILABLE:
            return result

        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent

            result["cpu"] = cpu
            result["memory"] = mem
            result["disk"] = disk

            self.status.cpu_percent = cpu
            self.status.memory_percent = mem
            self.status.disk_percent = disk

            if cpu >= self.CPU_CRITICAL:
                self._add_alert("CRITICAL", "HIGH_CPU",
                                f"CPU usage critical: {cpu}%", {"cpu": cpu})
                result["alerts"].append("HIGH_CPU")
            elif cpu >= self.CPU_WARNING:
                self._add_alert("WARNING", "HIGH_CPU",
                                f"CPU usage warning: {cpu}%", {"cpu": cpu})

            if mem >= self.MEM_CRITICAL:
                self._add_alert("CRITICAL", "HIGH_MEM",
                                f"Memory usage critical: {mem}%", {"memory": mem})
                result["alerts"].append("HIGH_MEM")
            elif mem >= self.MEM_WARNING:
                self._add_alert("WARNING", "HIGH_MEM",
                                f"Memory usage warning: {mem}%", {"memory": mem})

            if disk >= self.DISK_WARNING:
                self._add_alert("WARNING", "HIGH_DISK",
                                f"Disk usage warning: {disk}%", {"disk": disk})

        except Exception:
            pass

        return result

    def check_file_integrity(self) -> dict:
        """Re-check file integrity against baseline."""
        modified = []
        missing = []

        for rel_path, baseline_hash in self.file_hashes.items():
            full_path = os.path.join(PROJECT_ROOT, rel_path)

            if not os.path.exists(full_path):
                missing.append(rel_path)
                continue

            try:
                with open(full_path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()

                if current_hash != baseline_hash and baseline_hash != "ERROR":
                    modified.append({
                        "file": rel_path,
                        "old_hash": baseline_hash[:16],
                        "new_hash": current_hash[:16],
                    })
            except Exception:
                pass

        if modified:
            self.status.file_integrity = "MODIFIED"
            for m in modified:
                self._add_alert("CRITICAL", "FILE_MODIFIED",
                                f"File modified: {m['file']}",
                                details=m)
        else:
            self.status.file_integrity = "OK"

        return {
            "integrity": self.status.file_integrity,
            "modified": modified,
            "missing": missing,
            "total_monitored": len(self.file_hashes),
        }

    def check_connections(self) -> dict:
        """Check for unexpected network connections."""
        result = {"total": 0, "outbound": [], "alerts": []}

        if not PSUTIL_AVAILABLE:
            return result

        try:
            connections = psutil.net_connections(kind='inet')
            our_pid = os.getpid()

            outbound = []
            for conn in connections:
                if conn.pid == our_pid and conn.status == 'ESTABLISHED':
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        # Flag unexpected outbound connections
                        if remote_port not in (5760, 5761, 14550, 5000, 5353, 443, 80):
                            outbound.append({
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_port": conn.laddr.port if conn.laddr else 0,
                            })

            result["total"] = len(connections)
            result["outbound"] = outbound
            self.status.open_connections = len(connections)

            if len(outbound) > 0:
                self._add_alert("WARNING", "OUTBOUND_CONN",
                                f"Unexpected outbound connections: {len(outbound)}",
                                {"connections": outbound})
                result["alerts"].append("OUTBOUND_CONN")

            if len(connections) >= self.CONNECTION_CRITICAL:
                self._add_alert("CRITICAL", "CONNECTION_FLOOD",
                                f"Connection count critical: {len(connections)}",
                                {"count": len(connections)})

        except Exception:
            pass

        return result

    def check_processes(self) -> dict:
        """Check for unexpected child processes."""
        result = {"children": [], "alerts": []}

        if not PSUTIL_AVAILABLE:
            return result

        try:
            current = psutil.Process(os.getpid())
            children = current.children(recursive=True)

            expected_names = {'python', 'python3', 'flask', 'gunicorn'}

            for child in children:
                try:
                    name = child.name().lower()
                    if not any(exp in name for exp in expected_names):
                        result["children"].append({
                            "pid": child.pid,
                            "name": child.name(),
                            "cmdline": ' '.join(child.cmdline()[:3]),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            if result["children"]:
                self._add_alert("CRITICAL", "PROCESS_SPAWN",
                                f"Unexpected child processes: {len(result['children'])}",
                                {"processes": result["children"]})
                result["alerts"].append("PROCESS_SPAWN")

        except Exception:
            pass

        return result

    # ── Full Health Check ──

    def run_full_check(self) -> dict:
        """Run all health checks and return comprehensive status."""
        self.status.uptime_sec = round(time.time() - self.start_time, 1)
        self.status.active_threads = threading.active_count()
        self.status.last_check = datetime.now().isoformat()

        resources = self.check_resources()
        integrity = self.check_file_integrity()
        connections = self.check_connections()
        processes = self.check_processes()

        # Determine overall status
        if self.status.critical_alerts > 0:
            self.status.status = "COMPROMISED"
        elif self.status.total_alerts > 5:
            self.status.status = "DEGRADED"
        else:
            self.status.status = "HEALTHY"

        self.status.alerts = [asdict(a) for a in self.alerts[-10:]]
        self._save()

        return {
            "status": self.status.status,
            "uptime_sec": self.status.uptime_sec,
            "uptime_human": self._format_uptime(self.status.uptime_sec),
            "resources": resources,
            "integrity": integrity,
            "connections": connections,
            "processes": processes,
            "alerts_total": self.status.total_alerts,
            "alerts_critical": self.status.critical_alerts,
        }

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    # ── Background Monitor ──

    def start_monitoring(self):
        """Start background health monitoring thread."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.running = False

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                self.run_full_check()
            except Exception:
                pass
            time.sleep(self.CHECK_INTERVAL)

    # ── Update Baseline ──

    def update_baseline(self):
        """Update file integrity baseline (after authorized changes)."""
        self.file_hashes = {}
        for rel_path in self.MONITORED_FILES:
            full_path = os.path.join(PROJECT_ROOT, rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        self.file_hashes[rel_path] = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    self.file_hashes[rel_path] = "ERROR"
        self._save_integrity()
        return {"updated": len(self.file_hashes), "files": list(self.file_hashes.keys())}

    # ── Dashboard Data ──

    def get_status(self) -> dict:
        """Get current health status for dashboard."""
        return asdict(self.status)

    def get_alerts(self, limit: int = 50) -> List[dict]:
        """Get recent alerts."""
        return [asdict(a) for a in self.alerts[-limit:]]

    def get_stats(self) -> dict:
        """Get health monitoring statistics."""
        alert_types = {}
        for a in self.alerts:
            alert_types[a.alert_type] = alert_types.get(a.alert_type, 0) + 1

        return {
            "status": self.status.status,
            "uptime_sec": round(time.time() - self.start_time, 1),
            "total_alerts": self.status.total_alerts,
            "critical_alerts": self.status.critical_alerts,
            "alert_types": alert_types,
            "file_integrity": self.status.file_integrity,
            "monitored_files": len(self.file_hashes),
        }


if __name__ == "__main__":
    print("🛡️  Health Monitor — Test")

    monitor = HealthMonitor()

    # Run full check
    result = monitor.run_full_check()
    print(f"  Status: {result['status']}")
    print(f"  Uptime: {result['uptime_human']}")
    print(f"  CPU: {result['resources']['cpu']}%")
    print(f"  Memory: {result['resources']['memory']}%")
    print(f"  Integrity: {result['integrity']['integrity']}")
    print(f"  Monitored files: {result['integrity']['total_monitored']}")
    print(f"  Alerts: {result['alerts_total']} ({result['alerts_critical']} critical)")

    stats = monitor.get_stats()
    print(f"\n  Stats: {stats}")
