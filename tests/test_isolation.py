import os
import shutil
import socket
import subprocess
import sys
import threading

import httpcore
import httpx
import pytest

from agentguard import GuardError
from agentguard.core.action import Action, Context
from agentguard.execution import ContainerExecutor, NetworkExecutor
from agentguard.execution.egress import EgressProxy
from agentguard.execution.pinning import PinnedBackend, resolve_public


def action(tmp_path, capability, arguments):
    return Action(
        agent_id="t",
        session_id="s",
        tool="t",
        capability=capability,
        arguments=arguments,
        context=Context(working_directory=str(tmp_path)),
    )


# ------------------------------------------------------------------ DNS pinning


def test_dns_rebinding_cannot_redirect_a_pinned_request(tmp_path, monkeypatch):
    answers = iter(["93.184.215.14", "127.0.0.1"])  # Public at check, private afterwards.

    def resolve(host, port, *args, **kwargs):
        return [(2, 1, 6, "", (next(answers), port))]

    connected = []

    def connect(self, host, port, *args, **kwargs):
        connected.append(host)
        raise httpcore.ConnectError("stop here")

    monkeypatch.setattr("socket.getaddrinfo", resolve)
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    with pytest.raises(httpx.ConnectError):
        NetworkExecutor(["example.com"]).execute(
            action(tmp_path, "network.request", {"url": "https://example.com/"})
        )
    assert connected == ["93.184.215.14"]  # The checked address; DNS was asked once.


def test_resolution_rejects_any_private_address(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 443)), (2, 1, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(GuardError, match="Non-public"):
        resolve_public("example.com", 443)


def test_pinned_backend_refuses_other_hosts():
    with pytest.raises(httpcore.ConnectError, match="unpinned"):
        PinnedBackend("example.com", ["93.184.215.14"]).connect_tcp("evil.test", 443)


# ------------------------------------------------------------------ egress proxy


@pytest.fixture
def upstream():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def echo():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                return
            client.sendall(client.recv(100).upper())
            client.close()

    threading.Thread(target=echo, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def request(proxy, raw):
    host, port = proxy.host, proxy.port
    connection = socket.create_connection((host, port), timeout=5)
    connection.sendall(raw)
    return connection, connection.recv(200).decode().split("\r\n")[0]


def test_egress_proxy_tunnels_only_allowed_destinations(upstream):
    events = []
    proxy = EgressProxy(
        ["localhost"], ports=(upstream,), allow_private=True, on_decision=events.append
    )
    proxy.start()
    try:
        connection, status = request(
            proxy, f"CONNECT localhost:{upstream} HTTP/1.1\r\n\r\n".encode()
        )
        assert status == "HTTP/1.1 200 Connection Established"
        connection.sendall(b"ping")
        assert connection.recv(10) == b"PING"
        assert request(proxy, f"CONNECT evil.test:{upstream} HTTP/1.1\r\n\r\n".encode())[
            1
        ].startswith("HTTP/1.1 403")
        assert request(proxy, b"CONNECT localhost:22 HTTP/1.1\r\n\r\n")[1].startswith(
            "HTTP/1.1 403"
        )
        assert request(proxy, b"GET http://localhost/ HTTP/1.1\r\n\r\n")[1].startswith(
            "HTTP/1.1 405"
        )
    finally:
        proxy.stop()
    assert [e["final_decision"] for e in events] == ["allow", "deny", "deny", "deny"]


def test_egress_proxy_refuses_private_addresses_by_default(upstream):
    proxy = EgressProxy(["localhost"], ports=(upstream,))
    proxy.start()
    try:
        status = request(proxy, f"CONNECT localhost:{upstream} HTTP/1.1\r\n\r\n".encode())[1]
        assert status.startswith("HTTP/1.1 403")
    finally:
        proxy.stop()


# ------------------------------------------------------------------ containers


def test_container_command_line_is_locked_down(tmp_path):
    executor = ContainerExecutor(
        "python:3.12-slim",
        {"test": ["python", "-m", "pytest", "-q"]},
        workspace=tmp_path,
        engine=sys.executable,  # Any existing executable; argv is only built here.
        runtime="runsc",
        environment={"CI": "1"},
    )
    argv = executor.build_argv(("python", "-m", "pytest", "-q"), "agentguard-test")
    joined = " ".join(argv)
    for flag in (
        "--rm",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
        "--pids-limit 128",
        "--memory 512m",
        "--runtime runsc",
        "--pull never",
        "--env CI=1",
    ):
        assert flag in joined
    assert f"{tmp_path.resolve()}:/workspace:ro" in joined
    assert argv[-5:] == ["python:3.12-slim", "python", "-m", "pytest", "-q"]
    with pytest.raises(GuardError, match="allowlist"):
        executor.execute(action(tmp_path, "shell.execute", {"cmd": "rm -rf /"}))


@pytest.mark.parametrize(
    "options,message",
    [
        ({"image": "Bad Image!"}, "image"),
        ({"workspace_mode": "rwx"}, "workspace_mode"),
        ({"engine": "definitely-not-a-container-engine"}, "not found"),
    ],
)
def test_container_configuration_is_validated(tmp_path, options, message):
    settings = {"image": "alpine:3.20", "engine": sys.executable, **options}
    image = settings.pop("image")
    with pytest.raises(ValueError, match=message):
        ContainerExecutor(image, {"x": ["true"]}, **settings)


def _linux_docker():
    engine = shutil.which("docker")
    if not engine:
        return None
    try:
        kind = subprocess.run(
            [engine, "info", "--format", "{{.OSType}}"], capture_output=True, text=True, timeout=20
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return engine if kind == "linux" else None


docker = pytest.mark.skipif(_linux_docker() is None, reason="Needs a running Linux Docker engine")


@pytest.fixture(scope="module")
def alpine():
    subprocess.run([_linux_docker(), "pull", "-q", "alpine:3.20"], check=True, timeout=300)
    return "alpine:3.20"


def run_in(container, tmp_path, script, **options):
    executor = ContainerExecutor(
        container, {"run": ["sh", "-c", script]}, workspace=tmp_path, check=False, **options
    )
    return executor.execute(action(tmp_path, "shell.execute", {"cmd": "run"}))


@docker
def test_container_runs_unprivileged_without_network(tmp_path, alpine):
    result = run_in(alpine, tmp_path, "id -u; wget -q -T 3 -O- https://example.com || echo NO-NET")
    assert result["output"].splitlines()[0] == "65534"
    assert "NO-NET" in result["output"]


@docker
def test_container_filesystem_is_read_only_unless_allowed(tmp_path, alpine):
    blocked = run_in(alpine, tmp_path, "touch /etc/x 2>&1; touch /workspace/x 2>&1; echo done")
    assert "Read-only file system" in blocked["output"] and not (tmp_path / "x").exists()
    allowed = run_in(alpine, tmp_path, "touch /workspace/made && echo ok", workspace_mode="rw")
    assert allowed["output"].strip() == "ok" or (tmp_path / "made").exists()


@docker
def test_container_timeout_kills_the_container(tmp_path, alpine):
    with pytest.raises(GuardError, match="timed out"):
        run_in(alpine, tmp_path, "sleep 60", timeout=3)
    remaining = subprocess.run(
        [_linux_docker(), "ps", "-q", "--filter", "name=agentguard-"],
        capture_output=True,
        text=True,
        timeout=20,
    ).stdout.strip()
    assert remaining == ""


def test_container_engine_receives_no_secrets_from_host(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-forward")
    executor = ContainerExecutor("alpine:3.20", {"x": ["true"]}, engine=sys.executable)
    assert "AWS_SECRET_ACCESS_KEY" not in " ".join(executor.build_argv(("true",), "n"))
    assert "do-not-forward" not in os.environ.get("PATH", "")
