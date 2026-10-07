import json
from pathlib import Path

import portalocker

from agentguard.audit.chain import GENESIS, verify_events
from agentguard.audit.segments import lock_path, read_head, rotated_segments


def read_segment(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    if raw and not raw.endswith("\n"):
        raise ValueError(f"Truncated audit event in {path.name}")
    return [json.loads(line) for line in raw.splitlines()]


def read_unlocked(path: Path, key: bytes | None = None) -> list[dict]:
    """Read and verify every segment in order, then check the checkpoint, if present."""
    events, previous = [], GENESIS
    for segment in [*rotated_segments(path), path]:
        chunk = read_segment(segment)
        try:
            previous = verify_events(chunk, previous, key)
        except ValueError as exc:
            raise ValueError(f"{exc} in {segment.name}") from None
        events.extend(chunk)
    head = read_head(path)
    if head is not None and (head["count"] != len(events) or head["last_hash"] != previous):
        # Catches a removed tail or a rewritten chain when the checkpoint is intact.
        raise ValueError("Audit log does not match its checkpoint (truncated or rewritten)")
    return events


def read_log(path: str | Path, key: bytes | None = None) -> list[dict]:
    """Verified events from the log and its rotated segments. key checks HMAC signatures."""
    path = Path(path)
    if not path.exists() and not rotated_segments(path):
        raise FileNotFoundError(path)
    with portalocker.Lock(str(lock_path(path)), timeout=5):
        return read_unlocked(path, key)
