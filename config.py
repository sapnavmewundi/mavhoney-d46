#!/usr/bin/env python3
"""
MAVLink Honeypot — Central Configuration
Uses Pydantic BaseSettings for type-safe config with .env file support.

Usage:
    from config import settings
    print(settings.listen_port)
    if settings.feature_ml_detection:
        ...
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class HoneypotSettings(BaseSettings):
    """
    All configuration in one place. Values are loaded in this priority order:
    1. Environment variables (highest priority)
    2. .env file
    3. Defaults defined here (lowest priority)
    """

    model_config = {
        "env_file": os.path.join(_BASE_DIR, ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    # ── Environment ──
    honeypot_env: str = Field("dev", description="dev | test | prod")

    # ── Paths ──
    base_dir: str = Field(default=_BASE_DIR)
    logs_dir: str = Field(default=os.path.join(_BASE_DIR, "logs"))
    datasets_dir: str = Field(default=os.path.join(_BASE_DIR, "datasets"))
    config_dir: str = Field(default=os.path.join(_BASE_DIR, "config"))

    # ── Network ──
    honeypot_listen_port: int = Field(5760, description="TCP port the honeypot listens on")
    honeypot_sitl_port: int = Field(5761, description="SITL forward port")
    dashboard_port: int = Field(5000, description="Dashboard HTTP port")
    dashboard_host: str = Field("0.0.0.0", description="Dashboard bind address")

    # ── Security ──
    flask_secret_key: Optional[str] = Field(
        None, description="Flask session secret. Auto-generated if not set."
    )
    totp_secret: Optional[str] = Field(
        None, description="TOTP secret for dashboard auth. Auto-generated if not set."
    )

    # ── Feature Flags ──
    feature_ml_detection: bool = Field(True, description="Enable ML anomaly detection")
    feature_geoip: bool = Field(True, description="Enable GeoIP lookups")
    feature_telegram: bool = Field(False, description="Enable Telegram bot alerts")
    feature_advanced_fingerprint: bool = Field(True, description="Enable advanced fingerprinting")
    feature_canary_tokens: bool = Field(True, description="Enable canary token engine")
    feature_mitre_mapper: bool = Field(True, description="Enable MITRE ATT&CK mapping")
    feature_fuzz_detector: bool = Field(True, description="Enable protocol fuzzing detection")
    feature_tarpit: bool = Field(True, description="Enable attacker tarpit")
    feature_health_monitor: bool = Field(True, description="Enable health monitoring")
    feature_biometrics: bool = Field(True, description="Enable behavioral biometrics")
    feature_threat_predictor: bool = Field(True, description="Enable threat prediction")
    feature_cve_simulator: bool = Field(True, description="Enable fake CVE simulation")
    feature_correlation_engine: bool = Field(True, description="Enable attack correlation")
    feature_adaptive_deception: bool = Field(True, description="Enable adaptive deception")
    feature_decoy_fleet: bool = Field(True, description="Enable decoy drone fleet")
    feature_session_recorder: bool = Field(True, description="Enable session recording")

    # ── Telegram ──
    telegram_bot_token: Optional[str] = Field(None, description="Telegram bot API token")
    telegram_chat_id: Optional[str] = Field(None, description="Telegram chat ID for alerts")

    # ── Logging ──
    log_level: str = Field("INFO", description="Log level: DEBUG | INFO | WARNING | ERROR")
    log_file: str = Field(
        default=os.path.join(_BASE_DIR, "logs", "honeypot.log"),
        description="Log file path",
    )
    log_max_bytes: int = Field(10_485_760, description="Max log file size (10MB default)")
    log_backup_count: int = Field(5, description="Number of rotated log files to keep")

    # ── Rate Limiting ──
    rate_limit_packets: int = Field(100, description="Max packets per rate window")
    rate_limit_window_sec: int = Field(5, description="Rate limit window in seconds")
    max_connections_per_ip: int = Field(10, description="Max concurrent connections per IP")
    login_max_attempts: int = Field(5, description="Max login attempts before lockout")
    login_lockout_sec: int = Field(60, description="Login lockout duration in seconds")

    # ── Honeypot Behavior ──
    session_timeout_sec: int = Field(60, description="Idle session timeout")
    block_duration_sec: int = Field(300, description="IP block duration after rate limit")
    max_payload_bytes: int = Field(280, description="Max accepted packet payload size")


# Singleton — import this everywhere
settings = HoneypotSettings()
