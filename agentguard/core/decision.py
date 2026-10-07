from dataclasses import dataclass, field
from enum import StrEnum


class Effect(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    policy_result: Effect
    risk_score: int
    reasons: tuple[str, ...] = field(default_factory=tuple)
    strong_approval: bool = False


class GuardError(RuntimeError):
    """A guard infrastructure failure; execution is stopped."""


class GuardDenied(GuardError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__("Action denied: " + "; ".join(decision.reasons))
