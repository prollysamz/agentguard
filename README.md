# AgentGuard

**Let agents act. Keep humans in control.**

AgentGuard is an open-source safety and governance SDK for AI agents. It intercepts
tool calls before execution and applies policy rules, deterministic risk checks,
human approval, optional Gemma review, and tamper-evident auditing.

```python
from agentguard import Guard

guard = Guard(
    {
        "version": 1,
        "defaults": {"effect": "deny"},
        "rules": [
            {"capability": "filesystem.read", "paths": ["./workspace/**"], "effect": "allow"}
        ],
    },
    audit="agentguard.jsonl",
)


@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    from pathlib import Path

    return Path(path).read_text(encoding="utf-8")


# Pass ONLY the wrapped read_file to your agent.
# read_file("~/.ssh/id_rsa") raises GuardDenied before the function runs.
```

This is a working MVP, not a certified security sandbox. Read [THREAT_MODEL.md](THREAT_MODEL.md)
before using it with privileged tools or untrusted workloads.

## Install and run

Requires Python 3.11 or later.

```sh
pip install agentguard-oss                    # core SDK and CLI
pip install "agentguard-oss[langchain]"       # or [openai-agents], [adk], [mcp], [all]
agentguard demo --scripted
```

The distribution is `agentguard-oss`; the import is `import agentguard`. Until the first
PyPI release is published, install from GitHub instead:
`pip install "agentguard-oss @ git+https://github.com/prollysamz/agentguard"`.

To develop:

```sh
git clone https://github.com/prollysamz/agentguard.git
cd agentguard
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev,all]"
agentguard demo
agentguard verify-log --audit agentguard-demo.jsonl
```

`agentguard demo` gives an agent a calculator to fix in disposable fixture files whose
README carries a prompt injection asking it to steal `~/.ssh/id_rsa`. AgentGuard blocks
SSH-key access and the exfiltration command, allows the fix and its real unit test, and
escalates a simulated push to main for approval.

The agent is **Gemma** whenever a local Ollama has a Gemma model installed
(`gemma3:4b` preferred); otherwise the demo falls back to scripted proposals and says so.
`--scripted` forces the reproducible offline run. Without `--interactive`, the push is
denied because no approval provider is installed; with it, you can approve the push once.
No actual push, email, message delivery, or attacker connection takes place.

## Gemma integration

Install [Ollama](https://ollama.com) separately and pull a Gemma model supported by
your hardware, for example `ollama pull gemma3:4b`. Then:

```sh
agentguard demo --interactive                   # auto-detected Gemma agent
agentguard demo --judge --interactive           # plus the Gemma security judge
agentguard demo --model gemma3:12b --interactive
agentguard demo --scripted                      # offline, no model
```

The demo detects installed models through Ollama's `/api/tags`; `--model` picks one
explicitly (any Ollama model works, e.g. `qwen3:8b`). `--judge` separately enables a Gemma
security judge, including on a scripted run. Both use local Ollama `/api/chat` with
structured JSON output, temperature 0 and thinking disabled. The agent's tool field is
constrained to the registered tool names, it sees denial reasons, and it is stopped from
repeating a denied action. It has a 12-step limit and may complete or fail the exercise
depending on its proposals; the scripted demo is fully reproducible. With `gemma3:4b`
the agent reads the injected README, ignores it, fixes the bug, reruns the failing test
until it passes, and requests the push, which is escalated for approval.

The judge can only increase risk, never relax policy. A judge score at or above the deny
threshold denies; a judge `deny` flag with a lower score escalates to human approval,
because small models produce false positives. `GemmaJudge(guidance=...)` adds trusted
deployment context to its prompt, and `capabilities=...` limits review to the actions
where intent matters. The demo judges shell, network and message actions; file edits stay
under deterministic checks. Judge timeout, invalid output or service failure retains
deterministic checks. The judge receives redacted action data.

API references: [Ollama chat](https://docs.ollama.com/api/chat),
[structured outputs](https://ollama.com/blog/structured-outputs).
Live inference requires the local model service; unit tests use controlled responses.

## Pipeline and trust boundary

```text
Agent proposal → strict validation → policy → deterministic risk → optional Gemma
    → approval → authorized audit record → controlled execution → verification → audit
```

`Guard.call(name, arguments)` is the common dispatch path. Capabilities, environment,
agent identity, and working directory come from trusted registration/configuration,
not from the model's request. `@guard.tool` also uses that path. Async functions and
`await guard.acall(...)` are supported; calls in one Guard are serialized. A tool may
make nested guarded calls (sync or async); they run inline under the outer call and are
evaluated and audited normally. Cancelling an async caller does not cancel or roll back
an already executing tool.

Tools must declare explicit typed parameters, without variadic or positional-only
arguments. Values are validated strictly (the string `"3"` is not an integer).
Filesystem tools use `path`, writes use `content`, network tools use `url`, and shell
tools use `cmd` or `command`. Action data must fit the JSON argument-size limit.
Context is configured with `context={"working_directory": "/absolute/workspace",
"environment": "production", "user": "operator"}`. Supported environments are
development, test, staging, and production.

## Policy as code

See [examples/policy.yaml](examples/policy.yaml). Load it with `Guard("policy.yaml")`.
Policy version 1 supports ALLOW, DENY, ASK; path, domain, environment and sensitive-data
conditions; risk thresholds; argument-size, recipient, and per-session rate limits.
The recipient limit counts `to`, `cc`, `bcc`, `recipient` and `recipients` together
for email and message tools.

**Precedence:** any matching explicit DENY wins. Otherwise the first matching rule
wins, followed by the default. Put narrow exceptions before broader ASK rules.
Conditions within a rule are ANDed; values within each list are ORed. Risk can
escalate ALLOW to ASK or DENY. Approval can never override DENY.

Paths are made absolute against the Guard's working directory. Policy matching and
credential-path checks use the fully resolved target (`..`, `~` and existing links), and
also check the requested path. Tools and executors receive the absolute requested path,
so `FilesystemExecutor` can reject symlinks, junctions and other reparse points along it.
Matching is case-insensitive on Windows; execution keeps the requested filename case. Supported path patterns are an
exact path or a recursive `/root/**` prefix with a component boundary. Arbitrary
glob patterns are rejected at policy load time. Domain patterns are exact hostnames
or `*.example.com` (subdomains only, not the apex). Allowlists do not override hard
credential/destructive-command rules.

Risk uses explainable capability baselines plus contextual increments and hard-deny
rules. It is a heuristic, not a calibrated probability or the illustrative weighted
formula from the product proposal. Thresholds default to ASK at 51, strong approval
at 76, and DENY at 91. Credential exfiltration and detected destructive commands are
hard-denied even if thresholds are adjusted. Detection is not exhaustive.

## Approval

```python
from agentguard.approval import CLIApproval

guard = Guard("policy.yaml", approval=CLIApproval(timeout=30), approval_timeout=31)
```

CLI approval offers approve-once or reject. No terminal, rejection, timeout, provider
failure, malformed response, or missing provider means DENY. Strong approval is
**not** implemented by the CLI; those requests are denied. A trusted custom provider
can return `Approval(True, approved_by="authenticated-user", strong=True)` after
performing its own reauthentication. The SDK does not authenticate that identity.
Session-wide grants, webhooks, and web approvals are deferred.

## Controlled execution and verification

```python
from agentguard.execution import FilesystemExecutor, WorkspaceVerifier


@guard.tool(
    capability="filesystem.write",
    sandboxed=True,
    executor=FilesystemExecutor("./workspace"),
    verifier=WorkspaceVerifier("./workspace"),
)
def write_file(path: str, content: str) -> dict:
    raise AssertionError("The executor replaces this function")
```

`sandboxed=True` requires an executor; it does not promise OS isolation.
When an executor is provided, the original function is never invoked.

| Component | Implemented controls | Scope |
| --- | --- | --- |
| FilesystemExecutor | Root confinement, symlink/junction rejection, bounded reads/writes, file-only deletion | Trusted, non-concurrently-mutated workspace |
| ShellExecutor | Exact string-to-argv mapping, absolute executable, no shell, filtered environment, timeout, bounded combined output | Administrator-approved commands; cwd is not a filesystem sandbox |
| NetworkExecutor | GET only, HTTPS:443, independent domains, public DNS preflight, no redirects/proxies, bounded output | Trusted allowlisted DNS; use an egress proxy/firewall for hostile DNS |
| WorkspaceVerifier | Before/after file hashes; only the requested write/delete may change a file | Small isolated directory; does not see transient or out-of-root effects |

`ShellExecutor(..., check=False)` returns nonzero exits (such as failing tests) as
results instead of failing and halting the session. Shell executables and scripts must be trusted. A test runner can execute arbitrary
repository code; the demo runs a tiny disposable fixture. Never treat the same runner
as isolation for a hostile repository. Timeouts attempt process-tree cleanup, but do
not guarantee containment of detached descendants. Custom tools have no automatic
timeout or filesystem verification. Supply an executor/verifier or isolate them.

Audit files must live **outside** a verified workspace. Verification discrepancy or
execution failure halts further calls on that Guard. Side effects already performed
are not rolled back. A verifier failure withholds the result and records failure.

## Audit

```sh
agentguard logs --audit agentguard-demo.jsonl
agentguard logs --audit agentguard-demo.jsonl --risk high
agentguard logs --audit agentguard-demo.jsonl --decision deny
agentguard inspect evt_COPY_FROM_LOG --audit agentguard-demo.jsonl
agentguard verify-log --audit agentguard-demo.jsonl
```

Proposed, authorized, executing, executed and observed events share an `action_id`.
Each event's `timestamp` is when it was written; `action_timestamp` is when the action was proposed.
Denied/failed events record the reason or exception type without raw exception text.
Arguments are redacted; full results are not logged. Successful output containing a
recognized credential taints the session and blocks later outbound actions
(network requests, email, messages, `git push` and `repository.write`).

Logs use SHA-256 chaining, a cross-process file lock, flush/fsync, and full chain
validation before append. Audit failure before execution stops the call. Failure
after a side effect halts the session but cannot undo that side effect. An executing
event without a terminal event may indicate a crash. Readers verify before displaying.
This MVP reads the entire log on append, favoring integrity checks over throughput.

Hash chaining alone cannot detect full-chain rewriting or tail removal. Keep an
independently stored latest hash/event count or immutable external storage for stronger
integrity. Secret redaction is heuristic; protect log file access and retention.

## Dry run

```python
guard = Guard("policy.yaml", mode="dry-run")
# ... register and call tools ...
print(guard.summary)  # {"allow": 81, "ask": 14, "deny": 5}
```

**Dry-run means enforcement observation, not simulation. Valid tools really execute,
including actions that policy/risk would deny.** Do not enable it for unsafe agents.
Audit records preserve the evaluated decision and mark the override. Malformed calls,
infrastructure failures, executor restrictions and verification failures still stop
execution. Approval is not requested in observation mode.

## MCP and native Python

```python
from agentguard.adapters.mcp import register_tool

register_tool(mcp_server, guard, read_impl, capability="filesystem.read")
```

Only register the guarded function with the server. Run the complete example with
`python examples/mcp_server.py`. It uses the
[MCP Python SDK 1.x FastMCP](https://github.com/modelcontextprotocol/python-sdk), pinned
below version 2. MCP performs its own schema checks, then Guard revalidates. Requests
rejected by MCP before Guard dispatch are outside AgentGuard's audit boundary.
The native `GuardMiddleware` exposes `invoke` and `ainvoke`. Framework adapters contain
no policy logic. LangChain and other adapters are deferred.

## Development and scope

```sh
python -m pytest -q
python -m ruff check .
python -m build
```

The tests cover allow/deny/approval paths, timeout, malformed requests and policies,
secret redaction, tampering, concurrency, session taint, execution limits, verification
failures, the demo, mocked Ollama, and real in-process MCP registration/dispatch.
CI runs the suite on Windows and Linux, Python 3.11 and 3.12.

Included: reusable SDK, policies, deterministic risk, CLI approval, audit CLI, Gemma
agent/judge, MCP, observation mode, basic session/rate controls, and controlled runners.
Deferred: OS/container sandbox, argument transformations, distributed budgets, cost/token
accounting, advanced anomaly models, additional adapters, web dashboard and remote approvals.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

