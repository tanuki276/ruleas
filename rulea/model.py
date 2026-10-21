"""Immutable public decision data."""
from dataclasses import dataclass
from enum import Enum
from typing import Tuple

ENGINE_VERSION = "2.0.0"


class PolicyError(ValueError):
    """A policy cannot be parsed or validated."""


class Result(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Trace:
    expression: str
    value: bool


@dataclass(frozen=True)
class Decision:
    result: Result
    rule: str
    reason: str
    policy_version: str
    policy_hash: str
    trace: Tuple[Trace, ...] = ()
    decisions: Tuple["Decision", ...] = ()
    engine_version: str = ENGINE_VERSION

    @property
    def allowed(self):
        return self.result is Result.ALLOW

    def __bool__(self):
        return self.allowed

    def to_dict(self):
        return {
            "result": self.result.value, "rule": self.rule, "reason": self.reason,
            "policy_version": self.policy_version, "policy_hash": self.policy_hash,
            "engine_version": self.engine_version,
            "trace": [{"expression": t.expression, "value": t.value} for t in self.trace],
            "decisions": [d.to_dict() for d in self.decisions],
        }
