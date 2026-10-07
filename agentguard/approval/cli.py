import getpass
import json
import os
import select
import sys
import threading
import time

from agentguard.approval.base import Approval
from agentguard.risk.secrets import redact


class CLIApproval:
    """Approve one action using a terminal. No session-wide grants or reauthentication."""

    def __init__(self, timeout: float = 30):
        self.timeout = timeout
        self._lock = threading.Lock()

    def request(self, action, decision):
        if not sys.stdin.isatty() or decision.strong_approval:
            return Approval(False)
        if not self._lock.acquire(blocking=False):
            return Approval(False)
        try:
            print("\nAGENTGUARD APPROVAL REQUEST", file=sys.stderr)
            print(json.dumps(redact(action.model_dump()), indent=2), file=sys.stderr)
            print(f"Risk: {decision.risk_score}/100", file=sys.stderr)
            print("; ".join(redact(list(decision.reasons))), file=sys.stderr)
            print("[A] Approve once / [R] Reject: ", end="", file=sys.stderr, flush=True)
            deadline = time.monotonic() + self.timeout
            answer = ""
            if os.name == "nt":
                import msvcrt

                while msvcrt.kbhit():
                    msvcrt.getwch()
                while time.monotonic() < deadline:
                    if msvcrt.kbhit():
                        answer = msvcrt.getwch().lower()
                        break
                    time.sleep(0.05)
            elif select.select([sys.stdin], [], [], max(0, deadline - time.monotonic()))[0]:
                answer = sys.stdin.readline().strip().lower()
            return Approval(answer == "a", getpass.getuser())
        finally:
            self._lock.release()
