"""Ship audit events to other systems. The local log stays the record of truth.

Exporters receive each event after it is durably written. Failures are logged and never
stop the agent. Pass exporters to ``AuditLogger(..., exporters=[...])``.
"""

import hashlib
import hmac
import json
import logging
import queue
import threading
import time

import httpx

log = logging.getLogger(__name__)

# Flat, primitive fields, so OpenTelemetry and JSON log handlers can index them.
INDEXED = (
    "event_id",
    "action_id",
    "stage",
    "tool",
    "capability",
    "agent_id",
    "session_id",
    "evaluated_decision",
    "final_decision",
    "risk_score",
    "execution_status",
    "approved_by",
    "mode",
)


class LoggingExporter:
    """Emit each event as a Python log record.

    Attach any handler: OpenTelemetry's ``LoggingHandler``, ``SysLogHandler`` for a SIEM,
    or a JSON formatter. Records carry ``agentguard.<field>`` attributes and the full event
    as JSON in ``agentguard.event``.
    """

    def __init__(self, logger="agentguard.audit", level=logging.INFO):
        self.logger = logging.getLogger(logger) if isinstance(logger, str) else logger
        self.level = level

    def export(self, event: dict) -> None:
        extra = {f"agentguard.{k}": event[k] for k in INDEXED if event.get(k) is not None}
        extra["agentguard.event"] = json.dumps(event, sort_keys=True)
        decision = event.get("final_decision") or event.get("evaluated_decision") or ""
        self.logger.log(
            self.level,
            "agentguard %s %s %s",
            event.get("stage", "event"),
            event.get("tool", ""),
            decision,
            extra=extra,
        )


class HttpExporter:
    """POST each event as JSON from a background thread (e.g. Splunk HEC, a log collector).

    ``transform`` reshapes the body, e.g. ``lambda e: {"event": e}`` for Splunk HEC.
    ``secret`` adds ``X-AgentGuard-Signature: sha256=<hmac of "timestamp.body">``.
    When the bounded queue is full, events are dropped and counted in ``dropped``.
    """

    def __init__(
        self,
        url,
        *,
        headers=None,
        transform=None,
        secret=None,
        timeout=5.0,
        max_queue=1000,
        client=None,
    ):
        self.url, self.headers = url, dict(headers or {})
        self.transform = transform or (lambda event: event)
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.dropped = 0
        self.failed = 0
        self._queue = queue.Queue(maxsize=max_queue)
        self._client = client or httpx.Client(timeout=timeout, trust_env=False)
        self._worker = threading.Thread(target=self._run, name="agentguard-export", daemon=True)
        self._worker.start()

    def export(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until queued events are sent. Returns False on timeout."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        return not self._queue.unfinished_tasks

    def _run(self):
        while True:
            event = self._queue.get()
            try:
                body = json.dumps(self.transform(event), sort_keys=True).encode()
                headers = {"Content-Type": "application/json", **self.headers}
                if self.secret:
                    timestamp = str(int(time.time()))
                    digest = hmac.new(self.secret, timestamp.encode() + b"." + body, hashlib.sha256)
                    headers["X-AgentGuard-Timestamp"] = timestamp
                    headers["X-AgentGuard-Signature"] = "sha256=" + digest.hexdigest()
                self._client.post(self.url, content=body, headers=headers).raise_for_status()
            except Exception:
                self.failed += 1
                log.warning("AgentGuard HTTP export to %s failed", self.url, exc_info=True)
            finally:
                self._queue.task_done()
