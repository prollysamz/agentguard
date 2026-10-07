import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import portalocker

from agentguard.audit.chain import GENESIS, event_hash, sign
from agentguard.audit.reader import read_unlocked
from agentguard.audit.segments import (
    lock_path,
    read_head,
    rotated_segments,
    segment_path,
    write_head,
)
from agentguard.core.decision import GuardError
from agentguard.risk.secrets import redact

log = logging.getLogger(__name__)


class AuditLogger:
    """Append-only, hash-chained JSONL audit log.

    Appends check a checkpoint file (``<log>.head``) instead of re-reading the whole log:
    the file size must match and the last event must verify. ``verify-log`` still checks
    every event. ``max_bytes`` rotates to numbered segments that continue the chain.
    ``signing_key`` adds an HMAC-SHA256 signature to each event. ``exporters`` receive
    each event after it is durably written.
    """

    def __init__(self, path, *, max_bytes=None, signing_key=None, exporters=()):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self.key = signing_key.encode() if isinstance(signing_key, str) else signing_key
        self.exporters = tuple(exporters)
        self._thread_lock = threading.Lock()  # File locks may not exclude threads.

    def _checked_head(self):
        """The checkpoint, verified against the file; rebuilt from a full read if missing."""
        head = read_head(self.path)
        size = self.path.stat().st_size if self.path.exists() else 0
        if head is None:
            events = read_unlocked(self.path, self.key)  # Legacy log or first use.
            current = self.path.read_bytes() if self.path.exists() else b""
            last_offset = current.rfind(b"\n", 0, max(len(current) - 1, 0)) + 1 if current else 0
            return {
                "version": 1,
                "count": len(events),
                "last_hash": events[-1]["event_hash"] if events else GENESIS,
                "size": size,
                "last_offset": last_offset,
                "segments": len(rotated_segments(self.path)),
            }
        if size != head["size"]:
            raise ValueError("Audit log size does not match its checkpoint")
        if size:
            with self.path.open("rb") as stream:
                stream.seek(head["last_offset"])
                last = json.loads(stream.read().decode("utf-8"))
            if last.get("event_hash") != head["last_hash"] or event_hash(last) != head["last_hash"]:
                raise ValueError("Last audit event does not match its checkpoint")
        return head

    def append(self, payload: dict) -> dict:
        try:
            with self._thread_lock, portalocker.Lock(str(lock_path(self.path)), timeout=5):
                head = self._checked_head()
                event = {
                    **redact(payload),
                    "event_id": "evt_" + uuid4().hex,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "previous_hash": head["last_hash"],
                }
                event["event_hash"] = event_hash(event)
                if self.key is not None:
                    event["signature"] = sign(self.key, event["event_hash"])
                line = (json.dumps(event, ensure_ascii=True, allow_nan=False) + "\n").encode()
                if self.max_bytes and head["size"] and head["size"] + len(line) > self.max_bytes:
                    head["segments"] += 1
                    os.replace(self.path, segment_path(self.path, head["segments"]))
                    head["size"] = 0
                with self.path.open("ab") as stream:
                    stream.write(line)
                    stream.flush()
                    os.fsync(stream.fileno())
                head.update(
                    count=head["count"] + 1,
                    last_hash=event["event_hash"],
                    last_offset=head["size"],
                    size=head["size"] + len(line),
                )
                write_head(self.path, head)
        except Exception as exc:
            raise GuardError("Audit unavailable or corrupt; execution stopped") from exc
        for exporter in self.exporters:
            try:
                exporter.export(event)
            except Exception:  # The local log is the record; export is best effort.
                log.warning("AgentGuard audit exporter %r failed", exporter, exc_info=True)
        return event
