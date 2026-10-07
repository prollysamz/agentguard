from pathlib import Path

from agentguard.core.decision import GuardError


class FilesystemExecutor:
    capabilities = frozenset({"filesystem.read", "filesystem.write", "filesystem.delete"})

    def __init__(self, root: str | Path, max_bytes: int = 1_000_000):
        self.root = Path(root).resolve(strict=True)
        self.max_bytes = max_bytes

    def _path(self, value: str) -> Path:
        raw = Path(value)
        if not raw.is_absolute():
            raw = self.root / raw
        path = raw.resolve()
        if path == self.root or not path.is_relative_to(self.root):
            raise GuardError("Filesystem target outside permitted root")
        # Reject existing links, including Windows junctions where available.
        for part in (raw, *raw.parents):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise GuardError("Linked filesystem target rejected")
        return path

    def execute(self, action):
        path = self._path(action.arguments["path"])
        if action.capability == "filesystem.read":
            with path.open("rb") as stream:
                data = stream.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise GuardError("File exceeds output limit")
            return data.decode("utf-8")
        if action.capability == "filesystem.write":
            data = action.arguments["content"].encode("utf-8")
            if len(data) > self.max_bytes:
                raise GuardError("File exceeds write limit")
            # Parent creation is deliberately explicit and outside this operation.
            path.write_bytes(data)
            return {"bytes_written": len(data)}
        if action.capability == "filesystem.delete":
            path.unlink()  # Files only; never recursive deletion.
            return {"deleted": True}
        raise GuardError("Unsupported filesystem capability")
