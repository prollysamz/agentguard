# Isolation

Policy and risk decide **whether** a call runs. Isolation limits **what it can do** if it
runs and turns out to be malicious: a test suite from an untrusted repository, a build
script, or a command an agent was tricked into. AgentGuard provides three layers.

## Containers

`ContainerExecutor` runs allowlisted commands in Docker or Podman, optionally under
[gVisor](https://gvisor.dev) for a user-space kernel.

```python
from agentguard.execution import ContainerExecutor

tests = ContainerExecutor(
    "python:3.12-slim",
    {"run_tests": ["python", "-m", "pytest", "-q"]},
    workspace="./workspace",       # mounted at /workspace, read-only by default
    runtime="runsc",               # gVisor; omit for the engine's default runtime
    timeout=300,
    check=False,                   # return failing tests as results
)

@guard.tool(capability="shell.execute", executor=tests)
def run(cmd: str) -> dict:
    """Run an allowlisted command: run_tests."""
    raise AssertionError("The container runs instead")
```

| Default | Meaning |
| --- | --- |
| `network="none"` | No network at all |
| `--read-only` root, `--tmpfs /tmp` (`noexec`, 64 MB) | Nothing outside the workspace and `/tmp` is writable |
| `--cap-drop ALL`, `no-new-privileges` | No Linux capabilities; setuid binaries cannot escalate |
| `user` = `nobody` (`65534:65534`) | Not root. With `workspace_mode="rw"`, the host's own uid:gid so files stay writable (never root) |
| `memory="512m"`, `cpus="1"`, `pids=128` | Resource limits, no swap |
| `workspace_mode="ro"` | The workspace is read-only unless you pass `"rw"` |
| `pull="never"` | Only images already present locally run |
| `--init`, `--rm`, unique name | Child processes are reaped; the container is removed; a timeout or output overflow kills it by name |

Only an exact allowlisted command name selects an argv; the model never supplies the
command line. Environment variables reach the container only through `environment=`.

!!! note "What containers do not solve"
    A container shares the host kernel unless you use gVisor or a VM-based runtime. The
    workspace you mount is reachable. Images must be trusted and pinned (for example by
    digest). Follow your engine's hardening guide (rootless mode, user namespaces).

## DNS pinning

`NetworkExecutor` resolves the host once, requires **every** address to be public, and
connects to exactly those addresses, while TLS still verifies the certificate for the
hostname. A DNS server that answers with a public address for the check and a private one
for the connection (DNS rebinding) cannot redirect the request. Redirects and environment
proxies are disabled.

## Egress proxy

For tools that need some network access (a package install, a documentation fetch), run
the allowlisting proxy and make it the only way out:

```sh
agentguard egress-proxy --allow pypi.org --allow files.pythonhosted.org --port 3128 \
  --audit egress.jsonl
```

Point the tool at it with `HTTPS_PROXY=http://127.0.0.1:3128`. The proxy:

- accepts only `CONNECT host:port`, for allowlisted domains and ports (443 by default);
- resolves each host once, refuses non-public addresses, and tunnels to the checked address;
- answers everything else with `403`, `405` or `502`, and records each decision in the
  audit log when `--audit` is set.

It cannot inspect TLS, so a client could present a different SNI or `Host` to a server it
is allowed to reach (domain fronting on shared CDNs). Use it together with network
isolation, for example a container network whose only route is the proxy, so tools cannot
bypass it.

```python
from agentguard.execution.egress import EgressProxy

proxy = EgressProxy(["pypi.org", "files.pythonhosted.org"], on_decision=guard.audit.append)
host, port = proxy.start()      # background thread; proxy.stop() when done
```
