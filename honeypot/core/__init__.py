"""
honeypot.core — Modular MAVLink honeypot internals.

Extracted from the monolithic mavlink_honeypot.py for independent
testability, cleaner documentation, and easier onboarding.
"""

from honeypot.core.session_manager import (
    AttackEvent,
    AttackerProfile,
    ConnectionSandbox,
)
from honeypot.core.protocol import MAVLinkProtocol
from honeypot.core.semantic_analyzer import (
    MAVLINK_SEMANTICS,
    ATTACK_PATTERNS,
    SemanticAnalyzer,
)
from honeypot.core.state_machine import HoneypotStateMachine
from honeypot.core.response_generator import ResponseGenerator

__all__ = [
    "AttackEvent",
    "AttackerProfile",
    "ConnectionSandbox",
    "MAVLinkProtocol",
    "MAVLINK_SEMANTICS",
    "ATTACK_PATTERNS",
    "SemanticAnalyzer",
    "HoneypotStateMachine",
    "ResponseGenerator",
]
