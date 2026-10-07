import sys
from pathlib import Path

import pytest

from agentguard import GuardDenied, GuardError
from agentguard.core.action import Action, Context
from agentguard.execution import (
    FilesystemExecutor,
    NetworkExecutor,
    ShellExecutor,
    WorkspaceVerifier,
)


def action(tmp_path, capability, arguments):
    return Action(
        agent_id="test",
        session_id="session",
        tool="test",
        capability=capability,
        arguments=arguments,
        context=Context(working_directory=str(tmp_path)),
    )


def test_filesystem_executor_replaces_function(make_guard, tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    guard = make_guard([{"capability": "filesystem.write", "effect": "allow"}])

    @guard.tool(
        capability="filesystem.write",
        sandboxed=True,
        executor=FilesystemExecutor(workspace),
        verifier=WorkspaceVerifier(workspace),
    )
    def write_file(path: str, content: str):
        pytest.fail("Original callback must never execute")

    assert write_file(str(workspace / "hello.txt"), "hello") == {"bytes_written": 5}
    assert (workspace / "hello.txt").read_text() == "hello"


def test_filesystem_write_preserves_filename_case(make_guard, tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    guard = make_guard(
        [{"capability": "filesystem.write", "paths": [str(workspace / "**")], "effect": "allow"}]
    )

    @guard.tool(
        capability="filesystem.write",
        executor=FilesystemExecutor(workspace),
        verifier=WorkspaceVerifier(workspace),
    )
    def write_file(path: str, content: str):
        pytest.fail("Original callback must never execute")

    write_file("work/MyModule.py", "x = 1")
    assert [p.name for p in workspace.iterdir()] == ["MyModule.py"]


def test_filesystem_executor_rejects_escape_and_large_file(tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    executor = FilesystemExecutor(workspace, max_bytes=4)
    (workspace / "large").write_text("12345")
    with pytest.raises(GuardError, match="outside"):
        executor.execute(
            action(
                workspace, "filesystem.write", {"path": str(tmp_path / "escaped"), "content": "x"}
            )
        )
    with pytest.raises(GuardError, match="limit"):
        executor.execute(action(workspace, "filesystem.read", {"path": str(workspace / "large")}))
    assert not (tmp_path / "escaped").exists()


def test_link_escape_denied(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("private")
    try:
        (root / "linked").symlink_to(outside)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(GuardError):
        FilesystemExecutor(root).execute(
            action(root, "filesystem.read", {"path": str(root / "linked")})
        )


def test_verification_halts_after_extra_modification(make_guard, tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    guard = make_guard([{"capability": "filesystem.write", "effect": "allow"}])

    @guard.tool(capability="filesystem.write", verifier=WorkspaceVerifier(workspace))
    def write_file(path: str, content: str):
        Path(path).write_text(content)
        (workspace / "unapproved.txt").write_text("unapproved")

    with pytest.raises(GuardError, match="session halted"):
        write_file(str(workspace / "approved.txt"), "hello")
    assert (workspace / "unapproved.txt").exists()  # Detection does not roll back.
    with pytest.raises(GuardDenied, match="halted"):
        write_file(str(workspace / "approved.txt"), "again")


def test_shell_exact_allowlist_and_environment_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_TEST_CREDENTIAL", "do-not-inherit")
    executor = ShellExecutor(
        tmp_path,
        {
            "check": [
                sys.executable,
                "-c",
                "import os; print(os.getenv('AGENTGUARD_TEST_CREDENTIAL', 'absent'))",
            ]
        },
    )
    result = executor.execute(action(tmp_path, "shell.execute", {"cmd": "check"}))
    assert result["output"].strip() == "absent"
    with pytest.raises(GuardError, match="allowlist"):
        executor.execute(action(tmp_path, "shell.execute", {"cmd": "check && whoami"}))


@pytest.mark.parametrize(
    "code,timeout,limit,message",
    [
        ("import time; time.sleep(5)", 0.1, 1024, "timed out"),
        ("print('x' * 100000)", 5, 100, "output limit"),
        ("raise SystemExit(2)", 5, 1024, "exit code"),
    ],
)
def test_shell_limits(tmp_path, code, timeout, limit, message):
    executor = ShellExecutor(
        tmp_path, {"test": [sys.executable, "-c", code]}, timeout=timeout, max_output_bytes=limit
    )
    with pytest.raises(GuardError, match=message):
        executor.execute(action(tmp_path, "shell.execute", {"cmd": "test"}))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://evil.test",
        "https://example.com:8443",
        "https://user:pass@example.com",
    ],
)
def test_network_rejects_before_connection(tmp_path, url):
    with pytest.raises(GuardError):
        NetworkExecutor(["example.com"]).execute(action(tmp_path, "network.request", {"url": url}))


def test_network_rejects_private_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))]
    )
    with pytest.raises(GuardError, match="Non-public"):
        NetworkExecutor(["example.com"]).execute(
            action(tmp_path, "network.request", {"url": "https://example.com"})
        )
