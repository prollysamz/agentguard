import json
from pathlib import Path

import portalocker

from agentguard.audit.chain import verify_events


def read_unlocked(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    if raw and not raw.endswith("\n"):
        raise ValueError("Truncated audit event")
    events = [json.loads(line) for line in raw.splitlines()]
    verify_events(events)
    return events


def read_log(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    with portalocker.Lock(str(path) + ".lock", timeout=5):
        return read_unlocked(path)
