import os
import signal

# Commands are fixed argv lists from trusted configuration, never run through a shell.
import subprocess  # nosec B404
import threading
from pathlib import Path

from agentguard.core.decision import GuardError

# Windows Store Python needs these OS paths; omitting SystemDrive can create a literal
# %SystemDrive% directory in cwd. PATH and credentials are never inherited.
OS_PATHS = ("SystemRoot", "WINDIR", "SystemDrive", "ProgramData", "TEMP", "TMP")


class BoundedRunner:
    """Run an argv with a timeout, a combined-output cap and process-tree cleanup."""

    def __init__(self, *, timeout, max_output_bytes, check):
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        # check=False returns nonzero exits (e.g. failing tests) instead of raising.
        self.check = check

    @staticmethod
    def _kill(process):
        if os.name == "nt":
            # Absolute taskkill path and a numeric PID; no untrusted input.
            subprocess.run(  # nosec B603
                [
                    str(
                        Path(os.environ.get("SystemRoot", r"C:\Windows"))
                        / "System32"
                        / "taskkill.exe"
                    ),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # macOS reports EPERM when the group has already exited (only zombies left).
                pass
        if process.poll() is None:
            process.kill()

    def _run(self, argv, *, cwd, env, on_abort=None):
        """``on_abort`` runs after a timeout or output overflow (e.g. to stop a container)."""
        output = bytearray()
        overflow = threading.Event()
        # Allowlisted argv with shell=False; the model only chooses which entry.
        process = subprocess.Popen(  # nosec B603
            argv,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
        )

        def abort():
            self._kill(process)
            if on_abort is not None:
                on_abort()

        def collect():
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                remaining = self.max_output_bytes - len(output)
                output.extend(chunk[: max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    abort()
                    break

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            process.wait(timeout=self.timeout)
            reader.join(timeout=1)
            if reader.is_alive():
                abort()
                raise GuardError("Subprocess output stream did not close")
            if overflow.is_set():
                raise GuardError("Command exceeded output limit")
            if process.returncode and self.check:
                raise GuardError(f"Command failed with exit code {process.returncode}")
            return {
                "returncode": process.returncode,
                "output": output.decode("utf-8", errors="replace"),
            }
        except subprocess.TimeoutExpired as exc:
            abort()
            raise GuardError("Command timed out") from exc
        finally:
            if process.poll() is None:
                self._kill(process)
            process.wait(timeout=5)
            reader.join(timeout=1)
            if not reader.is_alive():
                process.stdout.close()


def _command(action, commands):
    argv = commands.get(action.arguments.get("cmd", action.arguments.get("command")))
    if argv is None:
        raise GuardError("Command is not in the exact execution allowlist")
    return argv


class ShellExecutor(BoundedRunner):
    """Exact command-to-argv mapping. This is a restricted runner, not an OS sandbox."""

    capabilities = frozenset({"shell.execute", "repository.write"})

    def __init__(
        self,
        root: str | Path,
        commands: dict[str, list[str]],
        *,
        timeout: float = 10,
        max_output_bytes: int = 65536,
        environment: dict[str, str] | None = None,
        check: bool = True,
    ):
        super().__init__(timeout=timeout, max_output_bytes=max_output_bytes, check=check)
        self.root = Path(root).resolve(strict=True)
        self.commands = {k: tuple(v) for k, v in commands.items()}
        for argv in self.commands.values():
            if not argv or not Path(argv[0]).is_absolute() or not Path(argv[0]).is_file():
                raise ValueError("Each command needs an existing absolute executable path")
        self.environment = dict(environment or {})

    def execute(self, action):
        argv = _command(action, self.commands)
        env = {k: os.environ[k] for k in OS_PATHS if k in os.environ}
        env.update(self.environment)
        return self._run(argv, cwd=self.root, env=env)
