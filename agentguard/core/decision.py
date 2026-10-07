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


class ApprovalPending(GuardDenied):
    """Not run yet: a human has been asked. Retry the same call after they approve."""

    def __init__(self, decision: Decision, request_id: str):
        self.request_id = request_id
        GuardError.__init__(
            self,
            f"Approval pending (request {request_id}); retry the same call after approval: "
            + "; ".join(decision.reasons),
        )
        self.decision = decision
