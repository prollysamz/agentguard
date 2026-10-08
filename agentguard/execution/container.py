"""Run allowlisted commands inside a locked-down container (Docker or Podman, optionally
with gVisor). This is OS-level isolation for code you do not trust, such as a repository's
test suite or build scripts.

Defaults: no network, read-only root filesystem, every Linux capability dropped,
no-new-privileges, an unprivileged user, memory/CPU/process limits, a small noexec /tmp,
and the workspace mounted read-only. Pass ``workspace_mode="rw"`` to let commands write
to the workspace, and ``runtime="runsc"`` to use gVisor's user-space kernel.
"""

import os
import re
import shutil

# The engine CLI is trusted, configured host software; see BoundedRunner.
import subprocess  # nosec B404
import uuid
from pathlib import Path

from agentguard.execution.shell import OS_PATHS, BoundedRunner, _command

IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,254}$")
# Host variables the engine CLI needs to find its daemon and configuration.
ENGINE_ENV = (
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_RUNTIME_DIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST",
    "PATH",
)


class ContainerExecutor(BoundedRunner):
    capabilities = frozenset({"shell.execute", "repository.write"})

    def __init__(
        self,
        image: str,
        commands: dict[str, list[str]],
        *,
        workspace: str | Path | None = None,
        workspace_mode: str = "ro",
        engine: str = "docker",
        runtime: str | None = None,
        network: str = "none",
        user: str = "65534:65534",
        memory: str = "512m",
        cpus: str = "1",
        pids: int = 128,
        tmpfs_size: str = "64m",
        environment: dict[str, str] | None = None,
        pull: str = "never",
        timeout: float = 60,
        max_output_bytes: int = 65536,
        check: bool = True,
    ):
        super().__init__(timeout=timeout, max_output_bytes=max_output_bytes, check=check)
        if not IMAGE.match(image):
            raise ValueError("Invalid container image reference")
        if workspace_mode not in {"ro", "rw"}:
            raise ValueError("workspace_mode must be ro or rw")
        if pull not in {"never", "missing", "always"}:
            raise ValueError("pull must be never, missing or always")
        located = shutil.which(engine) if not Path(engine).is_absolute() else engine
        if not located or not Path(located).is_file():
            raise ValueError(f"Container engine {engine!r} not found")
        self.engine = str(Path(located).resolve())
        self.image = image
        self.commands = {k: tuple(v) for k, v in commands.items()}
        if not self.commands or any(not argv for argv in self.commands.values()):
            raise ValueError("Each command needs a non-empty argv")
        self.workspace = Path(workspace).resolve(strict=True) if workspace else None
        self.workspace_mode = workspace_mode
        self.runtime, self.network, self.user = runtime, network, user
        self.memory, self.cpus, self.pids, self.tmpfs_size = memory, cpus, pids, tmpfs_size
        self.environment = dict(environment or {})
        self.pull = pull

    def build_argv(self, argv, name):
        """The full engine command line for one allowlisted argv."""
        command = [
            self.engine,
            "run",
            "--rm",
            "--name",
            name,
            "--pull",
            self.pull,
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            self.user,
            "--memory",
            self.memory,
            "--memory-swap",
            self.memory,
            "--cpus",
            self.cpus,
            "--pids-limit",
            str(self.pids),
            "--tmpfs",
            # A private in-container tmpfs, not the host /tmp.
            f"/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_size}",  # nosec B108
            "--init",
        ]
        if self.runtime:
            command += ["--runtime", self.runtime]
        if self.workspace:
            command += [
                "--volume",
                f"{self.workspace}:/workspace:{self.workspace_mode}",
                "--workdir",
                "/workspace",
            ]
        for key, value in self.environment.items():
            command += ["--env", f"{key}={value}"]
        return [*command, self.image, *argv]

    def execute(self, action):
        argv = _command(action, self.commands)
        name = "agentguard-" + uuid.uuid4().hex[:16]
        env = {k: os.environ[k] for k in (*OS_PATHS, *ENGINE_ENV) if k in os.environ}

        def stop_container():
            # Killing the CLI does not stop the container; stop it by its unique name.
            # Engine path and a generated name only.
            subprocess.run(  # nosec B603
                [self.engine, "kill", name], capture_output=True, timeout=15, check=False
            )

        return self._run(
            self.build_argv(argv, name), cwd=self.workspace, env=env, on_abort=stop_container
        )
