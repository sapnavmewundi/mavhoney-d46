#!/usr/bin/env python3
"""
Real-Time Web Dashboard for MAVLink Honeypot
Live attack monitoring, analytics, and dataset management
"""

from flask import Flask, render_template, jsonify, send_file, request, session, redirect, url_for
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False
import json
import csv
import secrets
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import os
import glob
import sys
import time
import hashlib
import hmac as _hmac
import re

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Load .env FIRST so all modules see the env vars ──
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_file = os.path.join(_project_root, '.env')
if os.path.exists(_env_file):
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file, override=True)
    except ImportError:
        # Manual fallback if python-dotenv not installed
        with open(_env_file) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _v = _line.split('=', 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

from dashboard.auth import TOTPManager, login_required
from dashboard.admin_audit import audit_logger
from honeypot.logger import get_logger

logger = get_logger("dashboard")

app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static')

# ── Security: Stable session key from config (not random per restart) ──
try:
    from config import settings
    _secret = settings.flask_secret_key or secrets.token_hex(32)
    if not settings.flask_secret_key:
        logger.warning(
            "⚠️  FLASK_SECRET_KEY not set — using random key. "
            "Sessions and HMAC signatures will reset on restart. "
            "Set FLASK_SECRET_KEY in .env for production."
        )
except ImportError:
    _secret = secrets.token_hex(32)
app.secret_key = _secret

# ── Security: Secure session cookies ──
_is_prod = os.environ.get('HONEYPOT_ENV', 'dev').lower() == 'prod'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_is_prod,  # Enforce HTTPS cookies in production
)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

if CORS_AVAILABLE:
    CORS(app)

# ── Security: Response Headers Middleware ──
@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Access-Control-Expose-Headers'] = 'X-HMAC-SHA256, X-Signed-At'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org; "
        "connect-src 'self'"
    )
    # API responses: short-lived cache to reduce duplicate fetches from multiple tabs
    if request.path.startswith('/api/') and response.content_type and 'json' in response.content_type:
        response.headers['Cache-Control'] = 'private, max-age=5'
    elif request.path in ('/login', '/setup'):
        response.headers['Cache-Control'] = 'no-store'
    return response

# TOTP Authentication
totp_manager = TOTPManager()

# Paths - use absolute paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

# ── Config Checksum Verification ──
def _compute_config_checksum() -> dict:
    """Compute SHA256 checksums for config files on startup."""
    checksums = {}
    for fname in ('config.py', '.env'):
        fpath = os.path.join(BASE_DIR, fname)
        if os.path.exists(fpath):
            h = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()
            checksums[fname] = h
    return checksums

_config_checksums_baseline = _compute_config_checksum()
_config_verified_at = datetime.now().isoformat()

def _verify_config_integrity() -> dict:
    """Verify config files haven't changed since startup."""
    current = _compute_config_checksum()
    mismatches = []
    for fname, baseline_hash in _config_checksums_baseline.items():
        cur_hash = current.get(fname, '')
        if cur_hash != baseline_hash:
            mismatches.append(fname)
    return {
        'status': 'VERIFIED' if not mismatches else 'TAMPERED',
        'baseline_at': _config_verified_at,
        'checked_at': datetime.now().isoformat(),
        'files': {f: {'sha256': h, 'match': f not in mismatches} for f, h in _config_checksums_baseline.items()},
        'mismatches': mismatches,
    }


def _hmac_sign(payload: str) -> str:
    """HMAC-SHA256 sign a payload string using the Flask secret key."""
    key = app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key
    return _hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


class DashboardAnalytics:
    """Analytics engine for dashboard"""
    
    def __init__(self):
        self.cache_timeout = 5  # seconds
        self.last_update = 0
        self.cached_data = {}
        # Event caching — avoid re-reading log files every 3s
        self._events_cache = None
        self._events_cache_time = 0
        self._events_cache_ttl = 10  # seconds
        # Profile caching
        self._profiles_cache = None
        self._profiles_cache_time = 0
        self._profiles_cache_ttl = 30  # seconds
        # ML model cache
        self._ml_model = None
        self._ml_model_loaded = False
    
    def get_latest_events(self, limit=50):
        """Get latest attack events from ALL logs. Use limit=0 for all events.
        Results are cached for 10s to avoid re-reading 1+MB of log files."""
        import time as _time
        now = _time.time()
        if self._events_cache is not None and (now - self._events_cache_time) < self._events_cache_ttl:
            cached = self._events_cache
            return cached if limit == 0 else cached[:limit]

        log_files = sorted(glob.glob(os.path.join(LOGS_DIR, "honeypot_*.log")), reverse=True)
        
        if not log_files:
            return []
        
        events = []
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entry = json.loads(line)
                                # Only include actual attack events (must have attacker_ip)
                                if 'attacker_ip' in entry:
                                    events.append(entry)
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logger.warning(f"Error reading {log_file}: {e}")
                continue
        
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)
        self._events_cache = sorted_events
        self._events_cache_time = now
        return sorted_events if limit == 0 else sorted_events[:limit]
    
    def get_attacker_profiles(self):
        """Aggregate attacker profiles from events (cached for 30s)."""
        import time as _time
        now = _time.time()
        if self._profiles_cache is not None and (now - self._profiles_cache_time) < self._profiles_cache_ttl:
            return self._profiles_cache

        events = self.get_latest_events(limit=1000)
        
        profiles = defaultdict(lambda: {
            'ip': '',
            'first_seen': None,
            'last_seen': None,
            'total_packets': 0,
            'attack_types': Counter(),
            'severity_scores': [],
            'sessions': set(),
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None,
        })
        
        for event in events:
            ip = event.get('attacker_ip')
            if not ip:
                continue  # Skip non-attack entries
            profile = profiles[ip]
            
            profile['ip'] = ip
            ts = event.get('timestamp', '')
            if not profile['first_seen'] or ts < profile['first_seen']:
                profile['first_seen'] = ts
            if not profile['last_seen'] or ts > profile['last_seen']:
                profile['last_seen'] = ts
            
            profile['total_packets'] += 1
            profile['attack_types'][event.get('intent', 'UNKNOWN')] += 1
            profile['severity_scores'].append(event.get('severity', 0))
            profile['sessions'].add(event.get('session_id', 'unknown'))
            
            # Get geo data if available in event
            if 'country' in event:
                profile['country'] = event.get('country', 'Unknown')
            if 'city' in event:
                profile['city'] = event.get('city', 'Unknown')
            if 'latitude' in event:
                profile['latitude'] = event.get('latitude')
            if 'longitude' in event:
                profile['longitude'] = event.get('longitude')
        
        # Real IP geolocation using ip-api.com (free, no API key)
        import requests as _req
        
        # Convert to list and calculate averages
        result = []
        for ip, data in profiles.items():
            # Real geo lookup if not already present
            if data['latitude'] is None:
                try:
                    resp = _req.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org", timeout=3)
                    geo = resp.json()
                    if geo.get('status') == 'success':
                        data['latitude'] = geo.get('lat', 0)
                        data['longitude'] = geo.get('lon', 0)
                        data['country'] = geo.get('country', 'Unknown')
                        data['city'] = geo.get('city', 'Unknown')
                except Exception:
                    data['latitude'] = 0
                    data['longitude'] = 0
            
            result.append({
                'ip': ip,
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'total_packets': data['total_packets'],
                'attack_types': dict(data['attack_types']),
                'avg_severity': sum(data['severity_scores']) / len(data['severity_scores']) if data['severity_scores'] else 0,
                'unique_sessions': len(data['sessions']),
                'threat_level': self._classify_threat(data['severity_scores'], data['attack_types']),
                'country': data['country'],
                'city': data['city'],
                'latitude': data['latitude'],
                'longitude': data['longitude'],
            })
        
        result = sorted(result, key=lambda x: x['avg_severity'], reverse=True)
        self._profiles_cache = result
        self._profiles_cache_time = now
        return result
    
    def _classify_threat(self, severities, attack_types):
        """Classify threat level"""
        avg_sev = sum(severities) / len(severities) if severities else 0
        high_threat = any(t in ['HIJACK', 'GPS_SPOOF'] for t in attack_types.keys())
        
        if avg_sev >= 8 or high_threat:
            return "CRITICAL"
        elif avg_sev >= 6:
            return "HIGH"
        elif avg_sev >= 4:
            return "MEDIUM"
        return "LOW"
    
    def get_statistics(self):
        """Get overall statistics"""
        events = self.get_latest_events(limit=0)  # Count ALL events for accurate total
        
        if not events:
            return {
                'total_attacks': 0,
                'unique_attackers': 0,
                'active_sessions': 0,
                'avg_severity': 0,
                'attack_by_type': {},
                'timeline': []
            }
        
        unique_ips = set(e.get('attacker_ip', 'unknown') for e in events)
        active_sessions = set(e.get('session_id', 'unknown') for e in events)
        attack_types = Counter(e.get('intent', 'UNKNOWN') for e in events)
        
        # Timeline data (last 24 hours, hourly buckets)
        now = datetime.now()
        timeline = defaultdict(int)
        for event in events:
            try:
                dt = datetime.fromisoformat(event['timestamp'])
                hour_bucket = dt.replace(minute=0, second=0, microsecond=0)
                timeline[hour_bucket.isoformat()] += 1
            except (ValueError, KeyError):
                continue
        
        return {
            'total_attacks': len(events),
            'unique_attackers': len(unique_ips),
            'active_sessions': len(active_sessions),
            'avg_severity': sum(e.get('severity', 0) for e in events) / len(events),
            'attack_by_type': dict(attack_types),
            'timeline': sorted([{'time': k, 'count': v} for k, v in timeline.items()],
                             key=lambda x: x['time'])
        }
    
    def _enrich_anomaly_scores(self, events):
        """Enrich events that lack anomaly_score with computed scores.
        
        Uses the trained IsolationForest model if available, otherwise
        falls back to a deterministic severity×intent heuristic.
        """
        import hashlib, math

        # Intent risk weights for the heuristic fallback
        intent_weights = {
            'HIJACK': 0.95, 'GPS_SPOOF': 0.9, 'CONTROL': 0.85,
            'MISSION_INJECT': 0.8, 'DOS_FLOOD': 0.7, 'DISRUPT': 0.7,
            'RECON': 0.3, 'UNKNOWN': 0.4, 'PASSIVE': 0.2,
        }

        # Load trained model (cached)
        if not self._ml_model_loaded:
            ml_dir = os.path.join(BASE_DIR, 'ml')
            model_path = os.path.join(ml_dir, 'trained_model.pkl')
            if os.path.exists(model_path):
                try:
                    import pickle
                    with open(model_path, 'rb') as f:
                        self._ml_model = pickle.load(f)
                except Exception as ex:
                    logger.debug(f"Could not load ML model: {ex}")
                    self._ml_model = None
            self._ml_model_loaded = True
        model = self._ml_model

        for e in events:
            if e.get('anomaly_score', 0) != 0:
                continue  # already has a score

            severity = e.get('severity', 1)
            intent = e.get('intent', 'UNKNOWN')
            msg_id = e.get('msg_id', 0)

            if model is not None:
                try:
                    # Build feature vector matching training pipeline
                    import numpy as np
                    intent_map = {'RECON': 0, 'CONTROL': 1, 'HIJACK': 2,
                                  'GPS_SPOOF': 3, 'DOS_FLOOD': 4, 'DISRUPT': 5,
                                  'MISSION_INJECT': 6, 'UNKNOWN': 7, 'PASSIVE': 8}
                    intent_num = intent_map.get(intent, 7)
                    features = np.array([[severity, 1.0, msg_id, intent_num]])
                    raw = model.decision_function(features)[0]
                    # Normalise IsolationForest score to [0, 1]
                    score = round(1.0 / (1.0 + math.exp(raw * 5)), 4)
                    is_anomaly = score > 0.6
                except Exception as ex:
                    # Fall through to heuristic
                    logger.debug(f"ML prediction failed: {ex}")
                    score = None

                if score is not None:
                    e['anomaly_score'] = score
                    e['anomaly_flag'] = is_anomaly
                    continue

            # Heuristic fallback: deterministic score from severity + intent
            # Use a hash of timestamp+ip for consistent per-event jitter
            seed_str = f"{e.get('timestamp','')}{e.get('attacker_ip','')}{msg_id}"
            jitter = (int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16) % 100) / 1000.0
            weight = intent_weights.get(intent, 0.4)
            base_score = (severity / 10.0) * 0.6 + weight * 0.4
            score = round(min(max(base_score + jitter - 0.05, 0.01), 0.99), 4)
            is_anomaly = score > 0.55 and severity >= 5

            e['anomaly_score'] = score
            e['anomaly_flag'] = is_anomaly

    def get_ml_analytics(self):
        """Get ML model analytics from event logs."""
        events = self.get_latest_events(limit=0)
        ml_dir = os.path.join(BASE_DIR, 'ml')

        # --- Model status ---
        anomaly_model_path = os.path.join(ml_dir, 'trained_model.pkl')
        skill_model_path = os.path.join(ml_dir, 'skill_model.pkl')
        anomaly_model_exists = os.path.exists(anomaly_model_path)
        skill_model_exists = os.path.exists(skill_model_path)

        anomaly_model_info = {}
        if anomaly_model_exists:
            stat = os.stat(anomaly_model_path)
            anomaly_model_info = {
                'loaded': True,
                'algorithm': 'IsolationForest',
                'file_size_kb': round(stat.st_size / 1024, 1),
                'last_trained': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        else:
            anomaly_model_info = {'loaded': False, 'algorithm': 'IsolationForest'}

        skill_model_info = {}
        if skill_model_exists:
            stat = os.stat(skill_model_path)
            skill_model_info = {
                'loaded': True,
                'algorithm': 'RandomForest',
                'file_size_kb': round(stat.st_size / 1024, 1),
                'last_trained': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        else:
            skill_model_info = {'loaded': False, 'algorithm': 'RandomForest'}

        # --- Enrich events without anomaly scores ---
        self._enrich_anomaly_scores(events)

        # --- Anomaly stats from events ---
        anomaly_events = [e for e in events if e.get('anomaly_flag', False)]
        total_events = len(events)
        total_anomalies = len(anomaly_events)
        anomaly_rate = round((total_anomalies / total_events * 100), 2) if total_events > 0 else 0

        scores = [e.get('anomaly_score', 0) for e in events if e.get('anomaly_score', 0) != 0]
        score_stats = {}
        if scores:
            score_stats = {
                'min': round(min(scores), 4),
                'max': round(max(scores), 4),
                'avg': round(sum(scores) / len(scores), 4),
            }

        # Anomalies by intent
        anomaly_by_intent = {}
        for e in anomaly_events:
            intent = e.get('intent', 'UNKNOWN')
            anomaly_by_intent[intent] = anomaly_by_intent.get(intent, 0) + 1

        # Score timeline (all events with scores)
        score_timeline = []
        for e in events:
            s = e.get('anomaly_score', 0)
            if s != 0:
                score_timeline.append({
                    'timestamp': e.get('timestamp', ''),
                    'score': s,
                    'is_anomaly': e.get('anomaly_flag', False),
                    'intent': e.get('intent', 'UNKNOWN'),
                    'msg_name': e.get('msg_name', 'Unknown'),
                    'attacker_ip': e.get('attacker_ip', ''),
                    'severity': e.get('severity', 0),
                })
        score_timeline = score_timeline[-100:]  # last 100 points

        # Recent anomalies
        recent_anomalies = anomaly_events[-20:]

        # --- Skill classification from fingerprints ---
        skill_data = {'distribution': {}, 'profiles': []}
        fp_file = os.path.join(BASE_DIR, 'logs', 'fingerprints.json')
        if os.path.exists(fp_file):
            try:
                with open(fp_file, 'r') as f:
                    fps = json.load(f)
                skill_dist = {}
                for fp in fps.values():
                    level = fp.get('skill_level', 'UNKNOWN')
                    skill_dist[level] = skill_dist.get(level, 0) + 1
                    skill_data['profiles'].append({
                        'session_id': fp.get('session_id', ''),
                        'ip': fp.get('ip', ''),
                        'skill_level': level,
                        'threat_score': fp.get('threat_score', 0),
                        'actions': fp.get('total_actions', 0),
                    })
                skill_data['distribution'] = skill_dist
            except Exception as e:
                logger.debug(f"Handled error: {e}")

        return {
            'models': {
                'anomaly_detector': anomaly_model_info,
                'skill_classifier': skill_model_info,
            },
            'anomaly_stats': {
                'total_events': total_events,
                'total_anomalies': total_anomalies,
                'anomaly_rate': anomaly_rate,
                'score_stats': score_stats,
                'by_intent': anomaly_by_intent,
            },
            'score_timeline': score_timeline,
            'recent_anomalies': recent_anomalies,
            'skill_classification': skill_data,
        }

    def get_datasets(self):
        """List available datasets"""
        datasets = []
        for filepath in glob.glob(os.path.join(DATASETS_DIR, "*.csv")):
            try:
                stat = os.stat(filepath)
                datasets.append({
                    'filename': os.path.basename(filepath),
                    'filepath': filepath,
                    'size_mb': round(stat.st_size / (1024*1024), 2),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'records': self._count_csv_rows(filepath)
                })
            except Exception as e:
                print(f"Error processing dataset {filepath}: {e}")
                continue
        
        return sorted(datasets, key=lambda x: x['modified'], reverse=True)
    
    def _count_csv_rows(self, filepath):
        """Count rows in CSV"""
        try:
            with open(filepath, 'r') as f:
                return sum(1 for line in f) - 1  # Exclude header
        except Exception:
            return 0


analytics = DashboardAnalytics()


# ─── Auth Routes ─────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    """TOTP login page with rate limiting."""
    if session.get('authenticated'):
        return redirect(url_for('index'))
    
    error = None
    show_qr = totp_manager.is_first_run()
    qr_code = totp_manager.get_qr_base64() if show_qr else None
    
    if request.method == 'POST':
        client_ip = request.remote_addr or '0.0.0.0'

        # Rate limit check
        if not totp_manager.check_rate_limit(client_ip):
            error = 'Too many attempts. Please wait before trying again.'
            return render_template('login.html', error=error, show_qr=show_qr, qr_code=qr_code)

        code = request.form.get('code', '')
        if totp_manager.verify(code):
            totp_manager.record_attempt(client_ip, success=True)
            session['authenticated'] = True
            session['login_time'] = time.time()
            totp_manager.mark_configured()
            audit_logger.log('LOGIN_SUCCESS', user_ip=client_ip)
            return redirect(url_for('index'))
        else:
            totp_manager.record_attempt(client_ip, success=False)
            audit_logger.log('LOGIN_FAILED', user_ip=client_ip)
            error = 'Invalid code. Try again.'
            show_qr = totp_manager.is_first_run()
            qr_code = totp_manager.get_qr_base64() if show_qr else None
    
    return render_template('login.html', error=error, show_qr=show_qr, qr_code=qr_code)


@app.route('/setup')
def setup_totp():
    """Show QR code for TOTP setup"""
    qr_code = totp_manager.get_qr_base64()
    return render_template('login.html', show_qr=True, qr_code=qr_code)


@app.route('/logout')
def logout():
    audit_logger.log('LOGOUT')
    session.pop('authenticated', None)
    session.pop('login_time', None)
    return redirect(url_for('login'))


# ─── Dashboard Routes ────────────────────────────────────

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/verify')
@login_required
def verify_page():
    """Drag-and-drop STIX verification page"""
    return render_template('verify.html')


@app.route('/api/stats')
@login_required
def api_stats():
    """Get overall statistics"""
    return jsonify(analytics.get_statistics())


@app.route('/api/events')
@login_required
def api_events():
    """Get latest attack events"""
    limit = int(request.args.get('limit', 1000))
    return jsonify(analytics.get_latest_events(limit))


@app.route('/api/attackers')
@login_required
def api_attackers():
    """Get attacker profiles"""
    return jsonify(analytics.get_attacker_profiles())


@app.route('/api/datasets')
@login_required
def api_datasets():
    """List available datasets"""
    return jsonify(analytics.get_datasets())


@app.route('/api/dataset/download/<filename>')
@login_required
def download_dataset(filename):
    """Download dataset file with path traversal protection."""
    # Sanitize: strip path separators, reject traversal attempts
    safe_name = os.path.basename(filename)
    if safe_name != filename or '..' in filename:
        return jsonify({'error': 'Invalid filename'}), 400
    filepath = os.path.join(DATASETS_DIR, safe_name)
    # Verify the resolved path is still inside DATASETS_DIR
    if not os.path.realpath(filepath).startswith(os.path.realpath(DATASETS_DIR)):
        return jsonify({'error': 'Access denied'}), 403
    if os.path.exists(filepath) and safe_name.endswith('.csv'):
        return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404


@app.route('/api/system/status')
@login_required
def system_status():
    """Get system status with uptime, datasets, model info, daily snapshot, and historical summary."""
    import time as _time
    events = analytics.get_latest_events(limit=0)
    now = datetime.now()
    # Historical summary from events
    today_events = [e for e in events if e.get('timestamp', '').startswith(now.strftime('%Y-%m-%d'))]
    # Uptime from health module
    uptime_sec = 0
    uptime_human = 'unknown'
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from health_monitor import HealthMonitor
        h = HealthMonitor()
        result = h.run_full_check()
        uptime_sec = result.get('uptime_sec', 0)
        uptime_human = result.get('uptime_human', 'unknown')
    except Exception:
        pass
    # Drone state from state machine (if available)
    drone_state = 'NORMAL'
    try:
        state_file = os.path.join(LOGS_DIR, 'honeypot_state.json')
        if os.path.exists(state_file):
            with open(state_file) as f:
                drone_state = json.load(f).get('state', 'NORMAL')
    except Exception:
        pass
    # Dataset size (total CSV rows)
    dataset_size = 0
    csv_files = glob.glob(os.path.join(DATASETS_DIR, '*.csv'))
    for cf in csv_files:
        try:
            dataset_size += sum(1 for _ in open(cf)) - 1  # minus header
        except Exception:
            pass
    # ML model version
    model_version = 'unknown'
    model_evaluated_at = ''
    model_path = os.path.join(BASE_DIR, 'ml', 'trained_model.pkl')
    if os.path.exists(model_path):
        mtime = os.path.getmtime(model_path)
        model_version = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
        model_evaluated_at = datetime.fromtimestamp(mtime).isoformat()
    # Daily log snapshot
    snapshot_info = {}
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from daily_snapshot import create_daily_snapshot
        snapshot_info = create_daily_snapshot(BASE_DIR)
    except Exception as e:
        snapshot_info = {'status': 'error', 'detail': str(e)}
    return jsonify({
        'status': 'online',
        'timestamp': now.isoformat(),
        'honeypot_state': 'ACTIVE',
        'drone_state': drone_state,
        'logs_count': len(glob.glob(os.path.join(LOGS_DIR, 'honeypot_*.log'))),
        'datasets_count': len(csv_files),
        'dataset_size': dataset_size,
        'model_version': model_version,
        'model_evaluated_at': model_evaluated_at,
        'uptime_sec': uptime_sec,
        'uptime_human': uptime_human,
        'daily_snapshot': snapshot_info,
        'historical': {
            'total_all_time': len(events),
            'total_today': len(today_events),
            'unique_ips_today': len(set(e.get('attacker_ip', '') for e in today_events)),
        }
    })


# ─── Intelligence API ────────────────────────────────────

@app.route('/api/geo_intel')
@login_required
def geo_intel():
    """Get attacker geolocation intelligence — merges real intel + event profiles"""
    attackers_list = []
    seen_ips = set()

    # 1. Real attacker intel from attacker_intel.json
    intel_file = os.path.join(BASE_DIR, 'logs', 'attacker_intel.json')
    if os.path.exists(intel_file):
        try:
            with open(intel_file, 'r') as f:
                data = json.load(f)
            for entry in data.values():
                ip = entry.get('ip', '')
                if ip and entry.get('lat') and entry.get('lon'):
                    seen_ips.add(ip)
                    attackers_list.append(entry)
        except Exception as e:
            logger.debug(f"Handled error: {e}")

    # 2. Event-derived attacker profiles (diverse simulated geo)
    try:
        profiles = analytics.get_attacker_profiles()
        for p in profiles:
            ip = p.get('ip', '')
            if ip in seen_ips:
                continue
            lat = p.get('latitude')
            lon = p.get('longitude')
            if lat is None or lon is None:
                continue
            seen_ips.add(ip)
            attackers_list.append({
                'ip': ip,
                'lat': lat,
                'lon': lon,
                'city': p.get('city', 'Unknown'),
                'country': p.get('country', 'Unknown'),
                'isp': 'Unknown',
                'attack_count': p.get('total_packets', 0),
                'vpn_detected': False,
                'first_seen': p.get('first_seen', ''),
                'last_seen': p.get('last_seen', ''),
            })
    except Exception:
        pass

    return jsonify({"total_attackers": len(attackers_list), "attackers": attackers_list})


@app.route('/api/fingerprints')
@login_required
def fingerprints():
    """Get attacker behavioral fingerprints"""
    fp_file = os.path.join(BASE_DIR, 'logs', 'fingerprints.json')
    if os.path.exists(fp_file):
        try:
            with open(fp_file, 'r') as f:
                data = json.load(f)
            return jsonify({
                "total": len(data),
                "fingerprints": list(data.values())
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total": 0, "fingerprints": []})


@app.route('/api/deception_scores')
@login_required
def deception_scores():
    """Get deception effectiveness scores"""
    scores_file = os.path.join(BASE_DIR, 'logs', 'deception_scores.json')
    if os.path.exists(scores_file):
        try:
            with open(scores_file, 'r') as f:
                data = json.load(f)
            profiles = list(data.values())
            avg_score = round(sum(p.get('score', 0) for p in profiles) / len(profiles), 1) if profiles else 0
            return jsonify({
                "average_score": avg_score,
                "total_profiles": len(profiles),
                "profiles": profiles
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"average_score": 0, "total_profiles": 0, "profiles": []})


@app.route('/api/ml_analytics')
@login_required
def api_ml_analytics():
    """Get ML model analytics and anomaly detection results"""
    return jsonify(analytics.get_ml_analytics())


# ─── New Feature API Routes ─────────────────────────────

@app.route('/api/campaigns')
@login_required
def api_campaigns():
    """Get attack campaigns from correlation engine"""
    campaigns_file = os.path.join(BASE_DIR, 'logs', 'campaigns.json')
    if os.path.exists(campaigns_file):
        try:
            with open(campaigns_file, 'r') as f:
                data = json.load(f)
            campaigns = list(data.values())
            active = sum(1 for c in campaigns if c.get('status') == 'ACTIVE')
            return jsonify({
                "total": len(campaigns),
                "active": active,
                "campaigns": sorted(campaigns,
                                    key=lambda c: c.get('last_seen', ''),
                                    reverse=True)
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total": 0, "active": 0, "campaigns": []})


@app.route('/api/adaptive')
@login_required
def api_adaptive():
    """Get adaptive deception strategies"""
    strategies_file = os.path.join(BASE_DIR, 'logs', 'adaptive_strategies.json')
    if os.path.exists(strategies_file):
        try:
            with open(strategies_file, 'r') as f:
                data = json.load(f)
            strategies = list(data.values())
            return jsonify({
                "total": len(strategies),
                "strategies": strategies,
                "strategy_distribution": _count_field(strategies, 'strategy'),
                "personality_distribution": _count_field(strategies, 'personality'),
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total": 0, "strategies": []})


@app.route('/api/fleet')
@login_required
def api_fleet():
    """Get decoy fleet status"""
    fleet_file = os.path.join(BASE_DIR, 'logs', 'fleet_state.json')
    if os.path.exists(fleet_file):
        try:
            with open(fleet_file, 'r') as f:
                data = json.load(f)
            drones = list(data.values())
            return jsonify({
                "fleet_size": len(drones),
                "drones": drones,
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"fleet_size": 0, "drones": []})


@app.route('/api/fleet/analysis')
@login_required
def api_fleet_analysis():
    """Get fleet target analysis"""
    fleet_file = os.path.join(BASE_DIR, 'logs', 'fleet_state.json')
    if os.path.exists(fleet_file):
        try:
            with open(fleet_file, 'r') as f:
                data = json.load(f)
            total_attacks = sum(d.get('attacks_received', 0) for d in data.values())
            analysis = []
            for did, d in data.items():
                attacks = d.get('attacks_received', 0)
                analysis.append({
                    "drone_id": d.get('drone_id', did),
                    "callsign": d.get('callsign', ''),
                    "model": d.get('model', ''),
                    "attacks_received": attacks,
                    "attack_share_pct": round(attacks / total_attacks * 100, 1) if total_attacks else 0,
                })
            return jsonify({
                "total_attacks": total_attacks,
                "drones": sorted(analysis, key=lambda x: x['attacks_received'], reverse=True),
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total_attacks": 0, "drones": []})


@app.route('/api/sessions')
@login_required
def api_sessions():
    """List recorded attack sessions with risk scores and flags."""
    sessions_dir = os.path.join(BASE_DIR, 'logs', 'sessions')
    sessions = []
    # Also build sessions from events if session dir is empty
    if os.path.exists(sessions_dir):
        try:
            for filename in sorted(os.listdir(sessions_dir), reverse=True)[:50]:
                if not filename.endswith('.json'):
                    continue
                filepath = os.path.join(sessions_dir, filename)
                with open(filepath, 'r') as f:
                    data = json.load(f)
                sessions.append({
                    'session_id': data.get('session_id'),
                    'attacker_ip': data.get('attacker_ip'),
                    'start_time': data.get('start_time'),
                    'duration_sec': data.get('duration_sec', 0),
                    'total_events': data.get('total_events', 0),
                    'attack_types': data.get('attack_types', []),
                    'peak_severity': data.get('peak_severity', 0),
                    'skill_level': data.get('skill_level', 'unknown'),
                    'risk_score': data.get('risk_score', data.get('peak_severity', 0) * 10),
                    'country': data.get('country', 'Unknown'),
                    'asn': data.get('asn', 'Unknown'),
                    'replay_detected': data.get('replay_detected', False),
                    'fuzz_detected': data.get('fuzz_detected', False),
                    'anomaly_flag': data.get('anomaly_flag', False),
                })
        except Exception as e:
            logger.debug(f"Handled error: {e}")

    # Build virtual sessions from events if no session files
    if not sessions:
        events = analytics.get_latest_events(limit=0)
        sess_map = defaultdict(list)
        for e in events:
            sid = e.get('session_id', 'unknown')
            sess_map[sid].append(e)
        for sid, evts in sorted(sess_map.items(), key=lambda x: x[1][-1].get('timestamp', ''), reverse=True)[:50]:
            evts_sorted = sorted(evts, key=lambda x: x.get('timestamp', ''))
            first, last = evts_sorted[0], evts_sorted[-1]
            severities = [e.get('severity', 0) for e in evts]
            types = list(set(e.get('intent', 'UNKNOWN') for e in evts))
            try:
                dur = (datetime.fromisoformat(last.get('timestamp', '')) - datetime.fromisoformat(first.get('timestamp', ''))).total_seconds()
            except Exception:
                dur = 0
            peak = max(severities) if severities else 0
            risk = min(100, int(peak * 10 + len(evts) * 0.5))
            sessions.append({
                'session_id': sid,
                'attacker_ip': first.get('attacker_ip', 'unknown'),
                'start_time': first.get('timestamp', ''),
                'duration_sec': round(dur),
                'total_events': len(evts),
                'attack_types': types,
                'peak_severity': peak,
                'skill_level': first.get('skill_level', 'medium'),
                'risk_score': risk,
                'country': first.get('country', 'Unknown'),
                'asn': first.get('asn', 'Unknown'),
                'replay_detected': any(e.get('replay_detected', False) for e in evts),
                'fuzz_detected': any(e.get('fuzz_detected', False) for e in evts),
                'anomaly_flag': any(e.get('anomaly_flag', False) for e in evts),
            })
    return jsonify({'total': len(sessions), 'sessions': sessions})


@app.route('/api/sessions/<session_id>/replay')
@login_required
def api_session_replay(session_id):
    """Get session events for replay — built from event logs."""
    # Security: prevent path traversal via session_id
    if not re.match(r'^[a-zA-Z0-9_\-]+$', session_id):
        return jsonify({'error': 'Invalid session ID'}), 400
    try:
        log_dir = os.path.join(BASE_DIR, 'logs')
        log_files = sorted(glob.glob(os.path.join(log_dir, 'honeypot_*.log')))
        session_events = []
        for lf in log_files:
            try:
                with open(lf, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                            if evt.get('session_id', '') == session_id:
                                session_events.append(evt)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue

        if not session_events:
            return jsonify({"error": "Session not found"}), 404

        # Sort by timestamp
        session_events.sort(key=lambda x: x.get('timestamp', ''))

        # ━━━ ML Explainability: Feature Contribution Scoring ━━━
        # Decompose the threat classification into weighted feature contributions
        # so investigators can see WHY a session was flagged, not just THAT it was.

        n = len(session_events)
        severities = [e.get('severity', 0) for e in session_events]
        intents = [e.get('intent', 'UNKNOWN') for e in session_events]
        msg_names = [e.get('msg_name', '') for e in session_events]

        # 1. Replay Detection Score (weight: 0.20)
        #    Check for duplicate (msg_name, payload_hex) tuples — replayed packets
        payload_tuples = [(e.get('msg_name', ''), e.get('payload_hex', '')) for e in session_events]
        unique_payloads = len(set(payload_tuples))
        replay_ratio = 1 - (unique_payloads / max(n, 1))
        replay_score = min(replay_ratio * 2.5, 1.0)  # amplify: 40% duplication → 1.0

        # 2. Payload Entropy Anomaly (weight: 0.15)
        #    High entropy payloads suggest fuzzing or crafted exploits
        import math
        entropy_scores = []
        for e in session_events:
            phex = e.get('payload_hex', '')
            if phex and len(phex) >= 4:
                data = bytes.fromhex(phex) if all(c in '0123456789abcdef' for c in phex.lower()) else b''
                if data:
                    freq = {}
                    for b in data:
                        freq[b] = freq.get(b, 0) + 1
                    entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq.values())
                    max_entropy = math.log2(256)
                    entropy_scores.append(entropy / max_entropy)  # normalize to 0-1
        avg_entropy = sum(entropy_scores) / max(len(entropy_scores), 1)
        entropy_anomaly = min(avg_entropy * 1.5, 1.0)  # amplify high entropy

        # 3. Command Order Violations (weight: 0.20)
        #    Aggressive commands without prerequisites indicate skilled attack
        PREREQUISITES = {'COMMAND_LONG', 'MISSION_ITEM', 'SET_POSITION_TARGET_GLOBAL_INT', 'PARAM_SET'}
        RECON_COMMANDS = {'HEARTBEAT', 'PARAM_REQUEST_READ', 'PARAM_REQUEST_LIST', 'REQUEST_DATA_STREAM'}
        seen_recon = any(m in RECON_COMMANDS for m in msg_names)
        violations = sum(1 for m in msg_names if m in PREREQUISITES and not seen_recon)
        order_score = min(violations / max(n * 0.3, 1), 1.0)

        # 4. Packet Rate Spike (weight: 0.15)
        #    High packet count in short time indicates injection/DoS
        timestamps = [e.get('timestamp', '') for e in session_events]
        rate_score = 0.0
        if len(timestamps) >= 2:
            try:
                from datetime import datetime as _dt
                t_first = _dt.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                t_last = _dt.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                duration = max((t_last - t_first).total_seconds(), 0.1)
                pps = n / duration
                # >10 pps = concerning, >50 = extreme
                rate_score = min(pps / 50.0, 1.0)
            except Exception:
                rate_score = 0.1  # assume low if parsing fails

        # 5. Severity Escalation (weight: 0.15)
        #    Sessions that escalate from low to high severity are more dangerous
        if severities:
            peak = max(severities)
            avg_sev = sum(severities) / len(severities)
            escalation = peak / 10.0  # normalize peak to 0-1
            # Bonus for escalation pattern (low→high)
            if len(severities) >= 3:
                first_third = sum(severities[:n//3]) / max(n//3, 1)
                last_third = sum(severities[-(n//3):]) / max(n//3, 1)
                if last_third > first_third:
                    escalation = min(escalation * 1.3, 1.0)
            severity_score = escalation
        else:
            severity_score = 0.0

        # 6. Attacker Skill Probability (weight: 0.15)
        #    Based on diversity of attack types and command sophistication
        unique_intents = set(intents) - {'UNKNOWN', 'RECON'}
        unique_commands = len(set(msg_names))
        ADVANCED_INTENTS = {'HIJACK', 'GPS_SPOOF', 'INJECT', 'CONTROL'}
        has_advanced = len(unique_intents & ADVANCED_INTENTS) > 0
        skill_score = min((len(unique_intents) * 0.25) + (0.3 if has_advanced else 0) + (unique_commands / 20.0), 1.0)

        # ━━━ Weighted aggregation ━━━
        WEIGHTS = {
            'replay_detection': 0.20,
            'entropy_anomaly': 0.15,
            'command_order': 0.20,
            'packet_rate': 0.15,
            'severity_escalation': 0.15,
            'attacker_skill': 0.15,
        }
        scores = {
            'replay_detection': round(replay_score, 3),
            'entropy_anomaly': round(entropy_anomaly, 3),
            'command_order': round(order_score, 3),
            'packet_rate': round(rate_score, 3),
            'severity_escalation': round(severity_score, 3),
            'attacker_skill': round(skill_score, 3),
        }
        total_risk = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
        total_risk = round(min(total_risk, 1.0), 3)

        # Classify risk level
        if total_risk >= 0.7:
            risk_level = 'CRITICAL'
        elif total_risk >= 0.4:
            risk_level = 'HIGH'
        else:
            risk_level = 'LOW'

        # Sort contributions by value descending for display
        contributions = sorted(
            [{'feature': k, 'score': v, 'weighted': round(v * WEIGHTS[k], 3)} for k, v in scores.items()],
            key=lambda x: x['weighted'],
            reverse=True,
        )

        # Feature human-readable labels
        LABELS = {
            'replay_detection': 'Replay Detection',
            'entropy_anomaly': 'Payload Entropy',
            'command_order': 'Command Order',
            'packet_rate': 'Packet Rate Spike',
            'severity_escalation': 'Severity Escalation',
            'attacker_skill': 'Attacker Skill',
        }
        for c in contributions:
            c['label'] = LABELS.get(c['feature'], c['feature'])

        explainability = {
            'risk_score': total_risk,
            'risk_level': risk_level,
            'contributions': contributions,
            'weights': WEIGHTS,
            'methodology': 'Weighted multi-feature decomposition (IEEE TIFS explainable ML)',
        }

        # Build summary
        timestamps_clean = [e.get('timestamp', '') for e in session_events]
        attack_types = list(set(e.get('intent', '') for e in session_events if e.get('intent')))
        attacker_ips = list(set(e.get('attacker_ip', '') for e in session_events if e.get('attacker_ip')))

        return jsonify({
            'session_id': session_id,
            'events': session_events,
            'count': len(session_events),
            'peak_severity': max(severities) if severities else 0,
            'skill_level': risk_level,
            'first_seen': timestamps_clean[0] if timestamps_clean else None,
            'last_seen': timestamps_clean[-1] if timestamps_clean else None,
            'attack_types': attack_types,
            'attacker_ips': attacker_ips,
            'explainability': explainability,
        })
    except Exception as e:
        logger.debug(f"Handled error: {e}")
        return jsonify({"error": "Session not found"}), 404


@app.route('/api/sessions/<session_id>/verify')
@login_required
def api_session_verify(session_id):
    """Verify the integrity of a session by hashing its events from the log."""
    # Security: prevent path traversal via session_id
    if not re.match(r'^[a-zA-Z0-9_\-]+$', session_id):
        return jsonify({'error': 'Invalid session ID'}), 400
    # Ensure hashes directory exists
    hashes_dir = os.path.join(BASE_DIR, 'logs', 'session_hashes')
    os.makedirs(hashes_dir, exist_ok=True)
    hash_file = os.path.join(hashes_dir, f'{session_id}.sha256')

    try:
        # Read events directly from log files (bypass analytics/ML layer for speed)
        log_dir = os.path.join(BASE_DIR, 'logs')
        log_files = sorted(glob.glob(os.path.join(log_dir, 'honeypot_*.log')))
        session_events = []
        for lf in log_files:
            try:
                with open(lf, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                            if evt.get('session_id', '') == session_id:
                                session_events.append(evt)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue

        if not session_events:
            return jsonify({'error': 'No events found for this session'}), 404

        # Sort deterministically and compute hash
        session_events_sorted = sorted(session_events, key=lambda x: x.get('timestamp', ''))
        canonical = json.dumps(session_events_sorted, sort_keys=True, default=str)
        current_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

        # Check for stored hash
        stored_hash = None
        if os.path.exists(hash_file):
            with open(hash_file, 'r') as f:
                stored_hash = f.read().strip()
        else:
            # First verification — store the hash as baseline
            with open(hash_file, 'w') as f:
                f.write(current_hash)
            stored_hash = current_hash

        is_valid = current_hash == stored_hash
        status = 'VERIFIED' if is_valid else 'TAMPERED'

        # Log to admin audit
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        audit_logger.log('SESSION_VERIFY', user_ip=client_ip, details={
            'session_id': session_id,
            'result': status,
            'events_count': len(session_events),
            'current_hash': current_hash[:16] + '...',
            'stored_hash': stored_hash[:16] + '...',
        })

        result = {
            'session_id': session_id,
            'valid': is_valid,
            'status': status,
            'current_hash': current_hash,
            'stored_hash': stored_hash,
            'events_count': len(session_events),
            'verified_at': datetime.now().isoformat(),
        }

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report')
@login_required
def api_generate_report():
    """Generate and serve an HTML threat intelligence report"""
    try:
        sys.path.insert(0, BASE_DIR)
        from report_generator import generate_report
        report_path = generate_report()
        return send_file(report_path, mimetype='text/html')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/telegram/test')
@login_required
def api_telegram_test():
    """Test Telegram bot connection"""
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from telegram_bot import TelegramNotifier
        bot = TelegramNotifier()
        result = bot.test_connection()
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Advanced Module APIs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route('/api/canaries')
@login_required
def api_canaries():
    """Get canary token data"""
    canary_file = os.path.join(BASE_DIR, 'logs', 'canary_tokens.json')
    if os.path.exists(canary_file):
        try:
            with open(canary_file, 'r') as f:
                data = json.load(f)
            tokens = list(data.values())
            triggered = sum(1 for t in tokens if t.get('triggered'))
            return jsonify({
                "total": len(tokens),
                "triggered": triggered,
                "trigger_rate": round(triggered / len(tokens) * 100, 1) if tokens else 0,
                "tokens": tokens
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total": 0, "triggered": 0, "trigger_rate": 0, "tokens": []})


@app.route('/api/mitre')
@login_required
def api_mitre():
    """Get MITRE ATT&CK mapping data"""
    mitre_file = os.path.join(BASE_DIR, 'logs', 'mitre_mapping.json')
    if os.path.exists(mitre_file):
        try:
            with open(mitre_file, 'r') as f:
                data = json.load(f)
            profiles = data.get("profiles", {})
            return jsonify({
                "total_profiled": len(profiles),
                "global_techniques": data.get("global_techniques", {}),
                "global_tactics": data.get("global_tactics", {}),
                "profiles": profiles,
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total_profiled": 0, "global_techniques": {}, "global_tactics": {}, "profiles": {}})


@app.route('/api/mitre/navigator')
@login_required
def api_mitre_navigator():
    """Export ATT&CK Navigator layer"""
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from mitre_mapper import MITREMapper
        mapper = MITREMapper()
        layer = mapper.generate_navigator_layer()
        return jsonify(layer)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/fuzzing')
@login_required
def api_fuzzing():
    """Get protocol fuzzing detection data"""
    fuzz_file = os.path.join(BASE_DIR, 'logs', 'fuzz_detections.json')
    if os.path.exists(fuzz_file):
        try:
            with open(fuzz_file, 'r') as f:
                data = json.load(f)
            profiles = list(data.values())
            fuzzers = [p for p in profiles if p.get('is_fuzzing')]
            return jsonify({
                "total_analyzed": len(profiles),
                "confirmed_fuzzers": len(fuzzers),
                "profiles": profiles,
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total_analyzed": 0, "confirmed_fuzzers": 0, "profiles": []})


@app.route('/api/tarpit')
@login_required
def api_tarpit():
    """Get tarpit statistics"""
    tarpit_file = os.path.join(BASE_DIR, 'logs', 'tarpit_stats.json')
    if os.path.exists(tarpit_file):
        try:
            with open(tarpit_file, 'r') as f:
                data = json.load(f)
            sessions = list(data.values())
            total_wasted = sum(s.get('wasted_time_sec', 0) for s in sessions)
            return jsonify({
                "active_tarpits": len(sessions),
                "total_time_wasted_sec": round(total_wasted, 1),
                "total_time_wasted_min": round(total_wasted / 60, 1),
                "sessions": sessions,
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"active_tarpits": 0, "total_time_wasted_sec": 0, "total_time_wasted_min": 0, "sessions": []})


@app.route('/api/health')
@login_required
def api_health():
    """Get honeypot health status including CPU/RAM."""
    result = {'status': 'UNKNOWN'}
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from health_monitor import HealthMonitor
        monitor = HealthMonitor()
        result = monitor.run_full_check()
    except Exception as e:
        result['error'] = str(e)
    # Add CPU/RAM info
    try:
        import psutil
        result['cpu_percent'] = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        result['ram_total_gb'] = round(mem.total / (1024**3), 1)
        result['ram_used_gb'] = round(mem.used / (1024**3), 1)
        result['ram_percent'] = mem.percent
        result['disk_percent'] = psutil.disk_usage('/').percent
    except ImportError:
        result['cpu_percent'] = 0
        result['ram_percent'] = 0
        result['ram_total_gb'] = 0
        result['ram_used_gb'] = 0
        result['disk_percent'] = 0
    # Config integrity check
    result['config_integrity'] = _verify_config_integrity()
    # Daily snapshot history
    try:
        from daily_snapshot import get_snapshot_history
        result['snapshots'] = get_snapshot_history(BASE_DIR)[:7]  # last 7 days
    except Exception:
        result['snapshots'] = []
    return jsonify(result)


@app.route('/api/biometrics')
@login_required
def api_biometrics():
    """Get behavioral biometrics data"""
    bio_file = os.path.join(BASE_DIR, 'logs', 'biometrics.json')
    if os.path.exists(bio_file):
        try:
            with open(bio_file, 'r') as f:
                data = json.load(f)
            operators = data.get("operators", {})
            multi_ip = sum(1 for o in operators.values() if len(o.get('associated_ips', [])) > 1)
            automated = sum(1 for o in operators.values() if o.get('is_automated'))
            return jsonify({
                "total_operators": len(operators),
                "multi_ip": multi_ip,
                "automated": automated,
                "human": len(operators) - automated,
                "operators": list(operators.values()),
                "ip_mapping": data.get("ip_mapping", {}),
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"total_operators": 0, "multi_ip": 0, "automated": 0, "human": 0, "operators": [], "ip_mapping": {}})


@app.route('/api/predictions')
@login_required
def api_predictions():
    """Get threat predictions for all attackers"""
    pred_file = os.path.join(BASE_DIR, 'logs', 'threat_predictions.json')
    if os.path.exists(pred_file):
        try:
            with open(pred_file, 'r') as f:
                data = json.load(f)
            predictions = data.get("predictions", {})
            near_critical = sum(
                1 for p in predictions.values()
                if 0 <= p.get('time_to_critical_sec', -1) < 60
            )
            return jsonify({
                "active_attackers": len(predictions),
                "near_critical": near_critical,
                "transition_matrix": data.get("transitions", {}),
                "predictions": list(predictions.values()),
            })
        except Exception as e:
            logger.debug(f"Handled error: {e}")
    return jsonify({"active_attackers": 0, "near_critical": 0, "transition_matrix": {}, "predictions": []})


@app.route('/api/cves')
@login_required
def api_cves():
    """Get CVE probe data"""
    cve_file = os.path.join(BASE_DIR, 'logs', 'cve_probes.json')
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'honeypot'))
        from cve_simulator import CVESimulator
        sim = CVESimulator()
        return jsonify({
            "served_version": sim.get_version_string(),
            "fake_cves": sim.get_cve_database(),
            "attacker_profiles": sim.get_all_profiles(),
            "stats": sim.get_stats(),
        })
    except Exception:
        return jsonify({
            "served_version": "Unknown",
            "fake_cves": [],
            "attacker_profiles": [],
            "stats": {},
        })


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# New Security Feature APIs (Phase 1-6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route('/api/replay_stats')
@login_required
def api_replay_stats():
    """Get replay detection statistics."""
    try:
        from honeypot.replay_detector import ReplayDetector
        rd = ReplayDetector()
        stats = rd.get_stats()
        return jsonify(stats)
    except ImportError:
        return jsonify({
            'total_checked': 0, 'replays_detected': 0,
            'tracked_sessions': 0, 'window_size': 1000,
            'status': 'module_not_loaded'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})


@app.route('/api/command_order')
@login_required
def api_command_order():
    """Get command order anomaly statistics."""
    try:
        from honeypot.command_order_detector import CommandOrderDetector
        cod = CommandOrderDetector()
        stats = cod.get_stats()
        return jsonify(stats)
    except ImportError:
        return jsonify({
            'total_checked': 0, 'anomalies_detected': 0,
            'burst_detections': 0, 'missing_prereqs': 0,
            'tracked_sessions': 0, 'status': 'module_not_loaded'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})


@app.route('/api/log_integrity')
@login_required
def api_log_integrity():
    """Verify log integrity across all protected log files."""
    try:
        from honeypot.log_integrity import IntegrityMonitor
        monitor = IntegrityMonitor(LOGS_DIR)
        results = monitor.verify_all()
        # Also check admin audit log
        audit_path = os.path.join(LOGS_DIR, 'admin_audit.log')
        audit_valid = True
        audit_entries = 0
        if os.path.exists(audit_path):
            try:
                with open(audit_path, 'r') as f:
                    lines = f.readlines()
                audit_entries = len(lines)
                # Check last entry has valid JSON
                if lines:
                    import json as _json
                    _json.loads(lines[-1].strip())
            except Exception:
                audit_valid = False

        all_valid = all(r.get('valid', True) for r in results.values()) and audit_valid
        return jsonify({
            'overall_valid': all_valid,
            'files_checked': len(results) + (1 if os.path.exists(audit_path) else 0),
            'integrity_logs': results,
            'audit_log': {
                'exists': os.path.exists(audit_path),
                'valid': audit_valid,
                'entries': audit_entries,
            },
            'status': 'ok'
        })
    except ImportError:
        return jsonify({
            'overall_valid': True, 'files_checked': 0,
            'integrity_logs': {}, 'status': 'module_not_loaded'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})


@app.route('/api/audit_trail')
@login_required
def api_audit_trail():
    """Get recent admin audit events."""
    try:
        limit = int(request.args.get('limit', 20))
        audit_path = os.path.join(LOGS_DIR, 'admin_audit.log')
        entries = []
        if os.path.exists(audit_path):
            with open(audit_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        # Return most recent first
        entries = entries[-limit:]
        entries.reverse()
        return jsonify({
            'entries': entries,
            'total': len(entries),
            'status': 'ok'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'entries': [], 'status': 'error'})


@app.route('/api/session_expiry_info')
@login_required
def api_session_expiry():
    """Get current session expiry info."""
    login_time = session.get('login_time', 0)
    from config import settings
    expiry_sec = getattr(settings, 'session_expiry_sec', 1800)
    elapsed = time.time() - login_time if login_time else 0
    remaining = max(0, expiry_sec - elapsed)
    return jsonify({
        'expiry_sec': expiry_sec,
        'elapsed_sec': round(elapsed),
        'remaining_sec': round(remaining),
        'login_time': login_time,
    })


def _count_field(items: list, field: str) -> dict:
    """Count occurrences of a field value."""
    counts = defaultdict(int)
    for item in items:
        counts[item.get(field, 'UNKNOWN')] += 1
    return dict(counts)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Additional Dashboard APIs (Checklist Completion)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route('/api/alerts')
@login_required
def api_alerts():
    """Get high-risk alerts with deduplication (same IP + intent → single alert with count)."""
    events = analytics.get_latest_events(limit=500)
    # Deduplicate: group by (attacker_ip, intent)
    dedup = {}  # (ip, intent) -> aggregated alert
    for e in events:
        sev = int(e.get('severity', 0))
        score = float(e.get('anomaly_score', 0))
        if sev >= 7 or score > 0.7:
            ip = e.get('attacker_ip', '')
            intent = e.get('intent', 'UNKNOWN')
            key = (ip, intent)
            level = 'CRITICAL' if sev >= 9 or score > 0.9 else 'HIGH'
            if key not in dedup:
                dedup[key] = {
                    'first_seen': e.get('timestamp', ''),
                    'last_seen': e.get('timestamp', ''),
                    'attacker_ip': ip,
                    'intent': intent,
                    'max_severity': sev,
                    'max_anomaly': round(score, 3),
                    'level': level,
                    'count': 1,
                    'session_ids': [e.get('session_id', '')],
                }
            else:
                dedup[key]['count'] += 1
                dedup[key]['last_seen'] = e.get('timestamp', '')
                dedup[key]['max_severity'] = max(dedup[key]['max_severity'], sev)
                dedup[key]['max_anomaly'] = max(dedup[key]['max_anomaly'], round(score, 3))
                if level == 'CRITICAL':
                    dedup[key]['level'] = 'CRITICAL'
                sid = e.get('session_id', '')
                if sid and sid not in dedup[key]['session_ids']:
                    dedup[key]['session_ids'].append(sid)
    alerts = sorted(dedup.values(), key=lambda a: a['last_seen'], reverse=True)[:50]
    return jsonify({
        'total': len(alerts),
        'critical': sum(1 for a in alerts if a['level'] == 'CRITICAL'),
        'high': sum(1 for a in alerts if a['level'] == 'HIGH'),
        'deduplicated': True,
        'alerts': alerts,
    })


@app.route('/api/command_frequency')
@login_required
def api_command_frequency():
    """Get MAVLink command type frequency counts."""
    events = analytics.get_latest_events(limit=0)
    cmd_counts = Counter()
    for e in events:
        msg = e.get('msg_name', e.get('command', 'UNKNOWN'))
        cmd_counts[msg] += 1
    # Sort by frequency descending
    sorted_cmds = sorted(cmd_counts.items(), key=lambda x: x[1], reverse=True)
    return jsonify({
        'total_commands': sum(cmd_counts.values()),
        'unique_commands': len(cmd_counts),
        'commands': [{'name': k, 'count': v} for k, v in sorted_cmds],
    })


@app.route('/api/ml_eval')
@login_required
def api_ml_eval():
    """Get ML evaluation metrics (accuracy, precision, recall, F1) and rule-vs-ML comparison."""
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, 'ml'))
        from evaluator import MLEvaluator
        evaluator = MLEvaluator()
        events = evaluator.load_dataset()
        if events:
            results = evaluator.evaluate(events)
            return jsonify(results)
        # Fallback: evaluate from live events
        live_events = analytics.get_latest_events(limit=500)
        if live_events:
            results = evaluator.evaluate(live_events)
            return jsonify(results)
        return jsonify({'error': 'No events available for evaluation'})
    except ImportError:
        return jsonify({'error': 'ML evaluator not available'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/stix_export')
@login_required
def api_stix_export():
    """Generate a STIX 2.1 JSON bundle from attack events (HMAC-signed)."""
    import uuid as _uuid
    events = analytics.get_latest_events(limit=0)
    now = datetime.now().isoformat() + 'Z'
    objects = []
    # Identity for the honeypot
    honeypot_id = 'identity--' + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, 'mavlink-honeypot'))
    objects.append({
        'type': 'identity',
        'spec_version': '2.1',
        'id': honeypot_id,
        'created': now,
        'modified': now,
        'name': 'MAVLink Honeypot',
        'identity_class': 'system',
    })
    # Group events by attacker IP
    ip_events = defaultdict(list)
    for e in events:
        ip = e.get('attacker_ip', '')
        if ip:
            ip_events[ip].append(e)
    for ip, evts in ip_events.items():
        # Threat actor
        actor_id = 'threat-actor--' + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, ip))
        objects.append({
            'type': 'threat-actor',
            'spec_version': '2.1',
            'id': actor_id,
            'created': now,
            'modified': now,
            'name': f'Attacker {ip}',
            'threat_actor_types': ['unknown'],
        })
        # Indicator (observed data)
        indicator_id = 'indicator--' + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, f'{ip}-indicator'))
        attack_types = list(set(e.get('intent', 'UNKNOWN') for e in evts))
        objects.append({
            'type': 'indicator',
            'spec_version': '2.1',
            'id': indicator_id,
            'created': now,
            'modified': now,
            'name': f'MAVLink attack from {ip}',
            'pattern': f"[ipv4-addr:value = '{ip}']",
            'pattern_type': 'stix',
            'valid_from': evts[0].get('timestamp', now),
            'description': f'Attack types: {", ".join(attack_types)}. Events: {len(evts)}.',
        })
    bundle = {
        'type': 'bundle',
        'id': 'bundle--' + str(_uuid.uuid4()),
        'objects': objects,
    }
    # HMAC-sign the bundle (computed on bundle WITHOUT signature fields)
    payload = json.dumps(bundle, separators=(',', ':'), sort_keys=True)
    signature = _hmac_sign(payload)
    # Embed signature IN the response so downloaded file is self-verifying
    bundle['x_hmac_sha256'] = signature
    bundle['x_signed_at'] = now
    resp = jsonify(bundle)
    resp.headers['X-HMAC-SHA256'] = signature
    resp.headers['X-Signed-At'] = now
    return resp


@app.route('/api/stix_verify', methods=['POST'])
@login_required
def api_stix_verify():
    """Verify the HMAC signature of a STIX bundle."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        stix_content = data.get('content', '')
        expected_hmac = data.get('hmac', '')

        if not stix_content:
            return jsonify({'error': 'STIX content is required'}), 400

        # Parse the bundle
        bundle = json.loads(stix_content)

        # Auto-extract embedded HMAC if not provided separately
        if not expected_hmac:
            expected_hmac = bundle.get('x_hmac_sha256', '')
        if not expected_hmac:
            return jsonify({'error': 'No HMAC found. Provide it or use a file with embedded x_hmac_sha256.'}), 400

        # Strip signature fields before computing (HMAC was computed WITHOUT them)
        clean_bundle = {k: v for k, v in bundle.items() if k not in ('x_hmac_sha256', 'x_signed_at')}
        payload = json.dumps(clean_bundle, separators=(',', ':'), sort_keys=True)
        computed = _hmac_sign(payload)

        is_valid = _hmac.compare_digest(computed, expected_hmac)

        return jsonify({
            'valid': is_valid,
            'computed_hmac': computed[:16] + '...',
            'expected_hmac': expected_hmac[:16] + '...',
            'status': 'VERIFIED' if is_valid else 'TAMPERED',
            'verified_at': datetime.now().isoformat(),
        })
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON in STIX content'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stix_info', methods=['POST'])
@login_required
def api_stix_info():
    """Inspect a STIX bundle and return summary information."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        stix_content = data.get('content', '')
        if not stix_content:
            return jsonify({'error': 'content is required'}), 400

        bundle = json.loads(stix_content)
        objects = bundle.get('objects', [])

        # Count by type
        type_counts = {}
        for obj in objects:
            obj_type = obj.get('type', 'unknown')
            type_counts[obj_type] = type_counts.get(obj_type, 0) + 1

        # Extract threat actors
        actors = []
        for obj in objects:
            if obj.get('type') == 'threat-actor':
                actors.append({
                    'name': obj.get('name', 'Unknown'),
                    'types': obj.get('threat_actor_types', []),
                })

        # Extract indicators
        indicators = []
        for obj in objects:
            if obj.get('type') == 'indicator':
                indicators.append({
                    'name': obj.get('name', ''),
                    'pattern': obj.get('pattern', ''),
                    'description': obj.get('description', '')[:100],
                })

        # File hash
        file_hash = hashlib.sha256(stix_content.encode()).hexdigest()

        return jsonify({
            'bundle_id': bundle.get('id', 'unknown'),
            'spec_version': bundle.get('spec_version', 'unknown'),
            'total_objects': len(objects),
            'type_counts': type_counts,
            'threat_actors': actors[:20],
            'indicators': indicators[:20],
            'file_hash': file_hash,
            'size_bytes': len(stix_content),
        })
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON in STIX content'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Create directories
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(DATASETS_DIR, exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'config'), exist_ok=True)
    os.makedirs(os.path.join(LOGS_DIR, 'snapshots'), exist_ok=True)

    # Config checksum verification on startup
    cfg_status = _verify_config_integrity()
    cfg_icon = '✅' if cfg_status['status'] == 'VERIFIED' else '⚠️'
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   🖥️  MAVLink Honeypot Dashboard                        ║
║   🌐 http://localhost:5000                               ║
║   🔐 TOTP Authentication: ENABLED                        ║
║   {'📱 First run — scan QR at /setup' if totp_manager.is_first_run() else '✅ TOTP configured — open /login'}                         ║
║   {cfg_icon} Config integrity: {cfg_status['status']}                       ║
╚══════════════════════════════════════════════════════════╝
""")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
