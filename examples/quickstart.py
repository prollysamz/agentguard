"""AgentGuard quickstart. Run it from any directory: python quickstart.py"""

from pathlib import Path

from agentguard import Guard, GuardDenied

workspace = Path("workspace")
workspace.mkdir(exist_ok=True)
(workspace / "notes.txt").write_text("hello from the workspace\n", encoding="utf-8")

guard = Guard(
    {
        "version": 1,
        "defaults": {"effect": "deny"},
        "rules": [
            {"capability": "filesystem.read", "paths": ["./workspace/**"], "effect": "allow"},
            {"capability": "shell.execute", "effect": "ask"},
        ],
    },
    audit="quickstart-audit.jsonl",  # Keep the audit log outside the agent's workspace.
)


@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    return Path(path).read_text(encoding="utf-8")


@guard.tool(capability="shell.execute")
def run(cmd: str) -> str:
    """Run a shell command. Never reached here: shell asks, and no approver is set."""
    raise AssertionError("unreachable")


# Give the agent only the guarded functions. Each call is checked, then audited.
print(read_file("workspace/notes.txt"), end="")

for name, arguments in [("read_file", {"path": "~/.ssh/id_rsa"}), ("run", {"cmd": "ls"})]:
    try:
        guard.call(name, arguments)  # The same path an agent framework uses.
    except GuardDenied as exc:
        print(f"Denied {name}: {'; '.join(exc.decision.reasons)}")

print("Decisions:", guard.summary)
