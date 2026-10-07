"""Approval through a shared queue: dashboard, API, Slack or webhook approvers."""

import asyncio
import logging
import threading
import time

from agentguard.approval.base import Approval
from agentguard.approval.store import ApprovalStore

log = logging.getLogger(__name__)


class QueueApproval:
    """Ask humans through an ApprovalStore without holding the agent hostage.

    - An active grant for the call (approved earlier, or "allow this tool for 10 minutes")
      approves immediately.
    - Otherwise a request is queued (an identical pending call reuses it) and notifiers run.
    - The provider waits up to ``wait`` seconds for a decision. If none arrives, the call
      raises ``ApprovalPending`` with the request ID. Retrying the same call after approval
      succeeds through the grant. ``wait=0`` (default) never blocks the agent.

    Keep the Guard's ``approval_timeout`` above ``wait``.
    """

    def __init__(self, store, *, wait=0.0, request_ttl=3600.0, notifiers=(), poll_interval=0.25):
        if wait < 0 or request_ttl <= 0:
            raise ValueError("wait must be >= 0 and request_ttl > 0")
        self.store = store if isinstance(store, ApprovalStore) else ApprovalStore(store)
        self.timeout = wait
        self.request_ttl = request_ttl
        self.notifiers = tuple(notifiers)
        self.poll_interval = poll_interval

    def request(self, action, decision):
        grant = self.store.use_grant(action, decision)
        if grant:
            return _granted(grant)
        request, created = self.store.submit(action, decision, ttl=self.request_ttl)
        if request["status"] == "rejected":
            return Approval(False)  # The same call was recently rejected.
        if created and self.notifiers:
            threading.Thread(
                target=self._notify, args=(request,), name="agentguard-notify", daemon=True
            ).start()
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            status = (self.store.get(request["id"]) or {}).get("status")
            if status == "approved":
                grant = self.store.use_grant(action, decision)
                return _granted(grant) if grant else Approval(False)
            if status in {"rejected", "expired"}:
                return Approval(False)
            time.sleep(min(self.poll_interval, max(0.0, deadline - time.monotonic())))
        return Approval(False, pending_id=request["id"])

    def status(self, request_id):
        """pending, approved, rejected or expired (None if unknown)."""
        request = self.store.get(request_id)
        return request["status"] if request else None

    def wait_for(self, request_id, timeout):
        """Block until the request is decided or ``timeout`` passes. Returns its status."""
        deadline = time.monotonic() + timeout
        while (status := self.status(request_id)) == "pending" and time.monotonic() < deadline:
            time.sleep(self.poll_interval)
        return status

    async def await_decision(self, request_id, timeout):
        """Async ``wait_for``: lets other tasks run while a human decides."""
        deadline = time.monotonic() + timeout
        while (status := self.status(request_id)) == "pending" and time.monotonic() < deadline:
            await asyncio.sleep(self.poll_interval)
        return status

    def _notify(self, request):
        for notifier in self.notifiers:
            try:
                notifier.notify(request)
            except Exception:
                log.warning("AgentGuard approval notifier %r failed", notifier, exc_info=True)


def _granted(grant):
    return Approval(
        True,
        approved_by=f"{grant['approved_by']} (grant {grant['id']})",
        strong=bool(grant["strong"]),
    )
