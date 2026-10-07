"""File layout: the active log, rotated segments and the checkpoint ("head") file."""

import json
import os
import re
from pathlib import Path


def head_path(path: Path) -> Path:
    return path.with_name(path.name + ".head")


def lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def segment_path(path: Path, index: int) -> Path:
    """audit.jsonl -> audit.000001.jsonl"""
    return path.with_name(f"{path.stem}.{index:06d}{path.suffix}")


def rotated_segments(path: Path) -> list[Path]:
    pattern = re.compile(re.escape(path.stem) + r"\.(\d{6})" + re.escape(path.suffix) + "$")
    found = []
    for candidate in path.parent.glob(f"{path.stem}.*{path.suffix}"):
        match = pattern.match(candidate.name)
        if match:
            found.append((int(match.group(1)), candidate))
    return [p for _, p in sorted(found)]


def read_head(path: Path) -> dict | None:
    try:
        return json.loads(head_path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def write_head(path: Path, head: dict) -> None:
    target = head_path(path)
    temporary = target.with_name(target.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(head, sort_keys=True))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)
