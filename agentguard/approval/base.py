from dataclasses import dataclass
from queue import Empty, Queue
from threading import Thread
from typing import Protocol

from agentguard.core.action import Action
from agentguard.core.decision import Decision


@dataclass(frozen=True)
class Approval:
    approved: bool
    approved_by: str = "unknown"
    strong: bool = False


class ApprovalProvider(Protocol):
    def request(self, action: Action, decision: Decision) -> Approval: ...


def request_bounded(provider, action, decision, timeout: float) -> Approval:
    """Late responses never authorize execution. Providers are trusted host code."""
    queue = Queue(maxsize=1)

    def request():
        try:
            queue.put(provider.request(action.model_copy(deep=True), decision))
        except Exception:
            queue.put(Approval(False))

    Thread(target=request, daemon=True).start()
    try:
        answer = queue.get(timeout=timeout)
        if not isinstance(answer, Approval) or type(answer.approved) is not bool:
            return Approval(False)
        if answer.approved and (not answer.approved_by or answer.approved_by == "unknown"):
            return Approval(False)
        if decision.strong_approval and answer.strong is not True:
            return Approval(False)
        return answer
    except Empty:
        return Approval(False)
