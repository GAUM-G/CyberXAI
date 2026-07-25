"""Deterministic baseline IDS rules for Step 9."""

from .detector import (
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_FAILURE_WINDOW_SECONDS,
    RULE_ENGINE_VERSION,
    RuleBasedDetector,
    RuleFinding,
)

__all__ = [
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_FAILURE_WINDOW_SECONDS",
    "RULE_ENGINE_VERSION",
    "RuleBasedDetector",
    "RuleFinding",
]
