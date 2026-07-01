#!/usr/bin/env python3
"""
MAVLink Honeypot — Centralized Logging

Usage:
    from logger import get_logger
    logger = get_logger("honeypot.core")
    logger.info("Honeypot started on port %d", port)
    logger.warning("Rate limit exceeded for %s", ip)
    logger.error("Failed to parse packet: %s", err)
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler


# ── Default Config (overridden when config.py is available) ──
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_LOG_FILE = os.path.join(_BASE_DIR, "logs", "honeypot.log")
_DEFAULT_LEVEL = "INFO"
_DEFAULT_MAX_BYTES = 10_485_760  # 10MB
_DEFAULT_BACKUP_COUNT = 5

_configured = False
_root_logger_name = "mavhoney"


class ColorFormatter(logging.Formatter):
    """Colored console output for readability."""

    COLORS = {
        logging.DEBUG: "\033[36m",      # Cyan
        logging.INFO: "\033[32m",       # Green
        logging.WARNING: "\033[33m",    # Yellow
        logging.ERROR: "\033[31m",      # Red
        logging.CRITICAL: "\033[41m",   # Red background
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def _setup_root_logger() -> None:
    """Configure the root honeypot logger once."""
    global _configured
    if _configured:
        return

    # Try to load config; fall back to defaults
    try:
        sys.path.insert(0, _BASE_DIR)
        from config import settings
        log_level = settings.log_level
        log_file = settings.log_file
        max_bytes = settings.log_max_bytes
        backup_count = settings.log_backup_count
    except ImportError:
        log_level = _DEFAULT_LEVEL
        log_file = _DEFAULT_LOG_FILE
        max_bytes = _DEFAULT_MAX_BYTES
        backup_count = _DEFAULT_BACKUP_COUNT

    root = logging.getLogger(_root_logger_name)
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Prevent double-adding handlers on reload
    if root.handlers:
        _configured = True
        return

    # ── Console Handler (colored) ──
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(ColorFormatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(console)

    # ── File Handler (rotating) ──
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(file_handler)
    except (OSError, PermissionError) as e:
        root.warning("Could not open log file %s: %s", log_file, e)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a named logger under the honeypot namespace.

    Args:
        name: Logger name, e.g. "honeypot.core", "dashboard", "fingerprint"

    Returns:
        Configured logging.Logger instance
    """
    _setup_root_logger()
    return logging.getLogger(f"{_root_logger_name}.{name}")
