"""Stable 2.x API for decisions. Parsing and compilation are internal."""
from .engine import RuleEngine
from .model import Decision, Result, Trace, PolicyError, ENGINE_VERSION

__version__ = ENGINE_VERSION
__all__ = ["RuleEngine", "Decision", "Result", "Trace", "PolicyError"]
