#!/usr/bin/env python3
"""
Database Backend for MAVLink Honeypot
SQLite-based persistent storage for attack events and attacker profiles
"""

import sqlite3
import json
import threading
from datetime import datetime
from typing import List, Dict, Optional
from contextlib import contextmanager


class HoneypotDatabase:
    """SQLite database for honeypot data persistence"""
    
    def __init__(self, db_path: str = "honeypot.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor"""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def _init_database(self):
        """Initialize database schema"""
        with self.get_cursor() as cursor:
            # Attack events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    attacker_ip TEXT NOT NULL,
                    attacker_port INTEGER,
                    msg_id INTEGER,
                    msg_name TEXT,
                    intent TEXT,
                    severity INTEGER,
                    payload_hex TEXT,
                    session_id TEXT,
                    honeypot_state TEXT,
                    packet_rate REAL,
                    country TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Attacker profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    total_packets INTEGER DEFAULT 0,
                    attack_types TEXT,  -- JSON
                    avg_severity REAL DEFAULT 0,
                    threat_level TEXT,
                    country TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    command_sequence TEXT,  -- JSON
                    is_blocked BOOLEAN DEFAULT FALSE,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    attacker_ip TEXT NOT NULL,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    total_messages INTEGER DEFAULT 0,
                    attack_patterns TEXT,  -- JSON
                    honeypot_states TEXT,  -- JSON list of states during session
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON attack_events(attacker_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON attack_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_intent ON attack_events(intent)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_profiles_ip ON attacker_profiles(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(session_id)')
    
    # ===== Attack Events =====
    
    def log_attack_event(self, event: Dict) -> int:
        """Log an attack event to the database"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO attack_events 
                (timestamp, attacker_ip, attacker_port, msg_id, msg_name, intent, 
                 severity, payload_hex, session_id, honeypot_state, packet_rate,
                 country, city, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('timestamp', datetime.now().isoformat()),
                event.get('attacker_ip'),
                event.get('attacker_port'),
                event.get('msg_id'),
                event.get('msg_name'),
                event.get('intent'),
                event.get('severity'),
                event.get('payload_hex'),
                event.get('session_id'),
                event.get('honeypot_state'),
                event.get('packet_rate'),
                event.get('country'),
                event.get('city'),
                event.get('latitude'),
                event.get('longitude')
            ))
            return cursor.lastrowid
    
    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent attack events"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT * FROM attack_events 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_events_by_ip(self, ip: str) -> List[Dict]:
        """Get all events from a specific IP"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT * FROM attack_events 
                WHERE attacker_ip = ?
                ORDER BY timestamp DESC
            ''', (ip,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_events_by_intent(self, intent: str, limit: int = 100) -> List[Dict]:
        """Get events by attack intent"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT * FROM attack_events 
                WHERE intent = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (intent, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== Attacker Profiles =====
    
    def update_attacker_profile(self, profile: Dict):
        """Update or create an attacker profile"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO attacker_profiles 
                (ip, first_seen, last_seen, total_packets, attack_types, 
                 avg_severity, threat_level, country, city, latitude, longitude, 
                 command_sequence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    total_packets = excluded.total_packets,
                    attack_types = excluded.attack_types,
                    avg_severity = excluded.avg_severity,
                    threat_level = excluded.threat_level,
                    country = COALESCE(excluded.country, country),
                    city = COALESCE(excluded.city, city),
                    latitude = COALESCE(excluded.latitude, latitude),
                    longitude = COALESCE(excluded.longitude, longitude),
                    command_sequence = excluded.command_sequence,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                profile.get('ip'),
                profile.get('first_seen'),
                profile.get('last_seen'),
                profile.get('total_packets', 0),
                json.dumps(profile.get('attack_types', {})),
                profile.get('avg_severity', 0),
                profile.get('threat_level', 'LOW'),
                profile.get('country'),
                profile.get('city'),
                profile.get('latitude'),
                profile.get('longitude'),
                json.dumps(profile.get('command_sequence', []))
            ))
    
    def get_all_profiles(self) -> List[Dict]:
        """Get all attacker profiles"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT * FROM attacker_profiles 
                ORDER BY avg_severity DESC
            ''')
            profiles = []
            for row in cursor.fetchall():
                profile = dict(row)
                profile['attack_types'] = json.loads(profile.get('attack_types', '{}'))
                profile['command_sequence'] = json.loads(profile.get('command_sequence', '[]'))
                profiles.append(profile)
            return profiles
    
    def get_profile_by_ip(self, ip: str) -> Optional[Dict]:
        """Get a specific attacker profile"""
        with self.get_cursor() as cursor:
            cursor.execute('SELECT * FROM attacker_profiles WHERE ip = ?', (ip,))
            row = cursor.fetchone()
            if row:
                profile = dict(row)
                profile['attack_types'] = json.loads(profile.get('attack_types', '{}'))
                profile['command_sequence'] = json.loads(profile.get('command_sequence', '[]'))
                return profile
            return None
    
    def block_attacker(self, ip: str, blocked: bool = True):
        """Mark an attacker as blocked"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                UPDATE attacker_profiles SET is_blocked = ? WHERE ip = ?
            ''', (blocked, ip))
    
    # ===== Sessions =====
    
    def start_session(self, session_id: str, attacker_ip: str) -> int:
        """Start a new session"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO sessions (session_id, attacker_ip)
                VALUES (?, ?)
            ''', (session_id, attacker_ip))
            return cursor.lastrowid
    
    def end_session(self, session_id: str, total_messages: int, attack_patterns: List[str]):
        """End a session"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                UPDATE sessions SET 
                    end_time = CURRENT_TIMESTAMP,
                    total_messages = ?,
                    attack_patterns = ?,
                    is_active = FALSE
                WHERE session_id = ?
            ''', (total_messages, json.dumps(attack_patterns), session_id))
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active sessions"""
        with self.get_cursor() as cursor:
            cursor.execute('''
                SELECT * FROM sessions WHERE is_active = TRUE
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    # ===== Statistics =====
    
    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        with self.get_cursor() as cursor:
            stats = {}
            
            # Total attacks
            cursor.execute('SELECT COUNT(*) as count FROM attack_events')
            stats['total_attacks'] = cursor.fetchone()['count']
            
            # Unique attackers
            cursor.execute('SELECT COUNT(DISTINCT attacker_ip) as count FROM attack_events')
            stats['unique_attackers'] = cursor.fetchone()['count']
            
            # Active sessions
            cursor.execute('SELECT COUNT(*) as count FROM sessions WHERE is_active = TRUE')
            stats['active_sessions'] = cursor.fetchone()['count']
            
            # Average severity
            cursor.execute('SELECT AVG(severity) as avg FROM attack_events')
            stats['avg_severity'] = cursor.fetchone()['avg'] or 0
            
            # Attacks by type
            cursor.execute('''
                SELECT intent, COUNT(*) as count 
                FROM attack_events 
                GROUP BY intent
            ''')
            stats['attack_by_type'] = {row['intent']: row['count'] for row in cursor.fetchall()}
            
            # Timeline (last 24 hours, hourly)
            cursor.execute('''
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, COUNT(*) as count
                FROM attack_events
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            ''')
            stats['timeline'] = [
                {'time': row['hour'], 'count': row['count']} 
                for row in cursor.fetchall()
            ]
            
            return stats
    
    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
_db_instance = None

def get_database(db_path: str = "honeypot.db") -> HoneypotDatabase:
    """Get or create database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = HoneypotDatabase(db_path)
    return _db_instance


if __name__ == "__main__":
    # Test database
    db = get_database("test_honeypot.db")
    
    # Log test event
    event_id = db.log_attack_event({
        'attacker_ip': '192.168.1.100',
        'attacker_port': 12345,
        'msg_id': 76,
        'msg_name': 'COMMAND_LONG',
        'intent': 'CONTROL',
        'severity': 6,
        'payload_hex': 'deadbeef',
        'session_id': 'test123',
        'honeypot_state': 'NORMAL',
        'packet_rate': 10.5
    })
    print(f"Logged event ID: {event_id}")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    db.close()
    print("Database test completed!")
