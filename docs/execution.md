# Controlled execution

A plain guarded function is trusted Python: AgentGuard decides *whether* it runs, not
*what* it does. An executor replaces the function with a narrow implementation of its
capability. A verifier checks the workspace afterwards.

| Component | Controls | Assumes |
| --- | --- | --- |
| `FilesystemExecutor(root, max_bytes=1_000_000)` | Confined to `root`; rejects symlinks, junctions and other reparse points on the path; bounded reads and writes; deletes files only | No hostile concurrent changes to the workspace |
| `ShellExecutor(root, commands, timeout=10, max_output_bytes=65536, environment=None, check=True)` | Only exact command strings, each mapped to a fixed argv with an absolute executable; no shell; filtered environment; timeout; bounded output | The allowlisted programs and scripts are trusted |
| `NetworkExecutor(domains, timeout=10, max_bytes=65536)` | HTTPS GET on port 443 only; its own domain allowlist; resolves once, rejects private addresses and connects only to the checked addresses; no redirects or proxies; bounded response | TLS and the allowlisted servers are trustworthy |
| `ContainerExecutor(image, commands, ...)` | Allowlisted commands in a container with no network, read-only root, no capabilities, an unprivileged user and resource limits; optional gVisor | The engine and image are trusted; see [Isolation](isolation.md) |
| `WorkspaceVerifier(root, max_files=1000, max_bytes=10_000_000)` | Hashes files before and after; only the requested write/delete target may change | Small, isolated workspace |

```python
import sys
from agentguard.execution import ShellExecutor

tests = ShellExecutor(
    "./workspace",
    {"run_tests": [sys.executable, "-m", "pytest", "-q"]},
    timeout=120,
    check=False,        # return failing exit codes as results instead of halting
)

@guard.tool(capability="shell.execute", executor=tests)
def run(cmd: str) -> dict:
    """Run an allowlisted command: run_tests."""
    raise AssertionError("The executor runs instead")
```

## Failure behavior

- An executor or verifier failure halts the session: further calls are denied.
- Side effects that already happened are **not** rolled back.
- A verifier failure withholds the result and records the failure.
- Keep audit logs **outside** a verified workspace, or the log write itself is a change.

## Writing your own

An executor has a `capabilities` frozenset and `execute(action)`. A verifier has
`before(action)` returning a snapshot and `after(action, before, result)` returning a dict
for the audit log. Both receive deep copies of the normalized action, with arguments under
their canonical names.

!!! warning "Not a sandbox"
    Executors narrow behavior; they are not OS isolation. A test runner executes repository
    code, timeouts may not stop detached child processes, and the working directory does not
    restrict file access. For untrusted workloads, run tools in a container or VM with an
    egress proxy. See the [threat model](security.md).
