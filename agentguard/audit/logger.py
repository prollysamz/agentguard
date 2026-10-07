import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import portalocker

from agentguard.audit.chain import GENESIS, event_hash
from agentguard.audit.reader import read_unlocked
from agentguard.core.decision import GuardError
from agentguard.risk.secrets import redact


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, payload: dict) -> dict:
        try:
            with portalocker.Lock(str(self.path) + ".lock", timeout=5):
                events = read_unlocked(self.path)
                event = {
                    **redact(payload),
                    "event_id": "evt_" + uuid4().hex,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "previous_hash": events[-1]["event_hash"] if events else GENESIS,
                }
                event["event_hash"] = event_hash(event)
                with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(event, ensure_ascii=True, allow_nan=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                return event
        except Exception as exc:
            raise GuardError("Audit unavailable or corrupt; execution stopped") from exc
