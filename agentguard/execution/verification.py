import hashlib
from pathlib import Path

from agentguard.core.decision import GuardError
from agentguard.execution.filesystem import is_link


class WorkspaceVerifier:
    """Detect unexpected persistent changes within a small, isolated workspace."""

    def __init__(self, root: str | Path, max_files: int = 1000, max_bytes: int = 10_000_000):
        self.root = Path(root).resolve(strict=True)
        self.max_files, self.max_bytes = max_files, max_bytes

    def _snapshot(self):
        found, size = {}, 0
        for path in self.root.rglob("*"):
            if is_link(path):
                raise GuardError("Verification workspace contains a link")
            if path.is_file():
                size += path.stat().st_size
                if len(found) >= self.max_files or size > self.max_bytes:
                    raise GuardError("Verification workspace exceeds snapshot limits")
                found[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        return found

    def before(self, action):
        return self._snapshot()

    def after(self, action, before, result):
        after = self._snapshot()
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        expected = set()
        if action.capability in {"filesystem.write", "filesystem.delete"}:
            expected.add(str(Path(action.arguments["path"]).resolve()))
        if changed - expected:
            raise GuardError("Unexpected workspace file modifications")
        return {"status": "verified", "changed_files": len(changed)}
