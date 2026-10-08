# AgentGuard threat model

## Assets and trust

Assets include files, credentials, external systems, human authority, tool budgets and
audit records. The model, retrieved pages, repository documents and model-produced tool
arguments are untrusted. Host application code, tool registration, executors, policy,
approval providers, Python runtime and operating system are trusted.

AgentGuard is an interception boundary for cooperative applications. It cannot stop an
agent that is also given an unwrapped tool, direct Python execution, unrestricted shell,
or another path to host resources. Private Python attributes are not a security boundary.
The agent must not control registration, capability labels, context, policy or the Guard
object. Policy/configuration should not be writable through agent tools.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Prompt injection into a tool proposal | Strict argument validation, policy, shell-aware command analysis, hard-deny rules, optional judge | Shell is too expressive to analyze completely; obfuscation asks rather than being decoded; interpreter code is recognized by keywords only |
| Accidental destructive operations | Dangerous command detection; exact command runner; filesystem scope | Approved executables may perform arbitrary operations |
| Credential exfiltration | gitleaks rules on RE2, credential-store paths, validated PII detectors, outbound payload inspection, session taint | Encoded, fragmented or novel secret formats and unstructured personal data are not detected |
| Unauthorized file access | Canonical path matching; confined filesystem executor with link rejection; read-only container workspaces | Plain Python tools can race link changes (TOCTOU); hardlinks are not detected |
| Unapproved communication | Domain rules, approval, HTTPS executor with pinned public DNS, allowlisting egress proxy, no-network containers | The proxy cannot see inside TLS (domain fronting); plain tools can open their own connections unless isolated |
| Privilege escalation | Dangerous-command rules, exact-command runners, containers without capabilities or setuid | Host privileges remain available to trusted tool implementations; containers share the host kernel unless gVisor or a VM runtime is used |
| Excessive use | Per-session, per-agent or global call rates (Redis for multiple processes), request/output sizes, command timeouts | Fixed-window Redis limits allow boundary bursts; no custom-tool timeout, token/cost accounting or hard child-process limits |
| Unexpected modifications | Optional workspace hash verifier; halt on failure | Cannot undo effects or observe transient, network, metadata or out-of-root changes |
| Approval failure or replay | Token-authenticated approvers (hashed), grants bound to agent, environment and scope with expiry, signed Slack/webhook traffic, CSRF-protected dashboard | A stolen approver token can approve until removed; grants widen what runs without asking; custom providers must authenticate humans themselves |
| Audit manipulation | Hash chain, checkpoint, file lock, fsync, optional HMAC signatures, export off-host | Without a signing key, a fully rewritten chain and checkpoint is undetectable; a key holder can forge; deleting all copies is not prevented |

## Fail-closed behavior

Unknown tools, unknown capabilities, malformed arguments/policy, policy/risk exceptions,
approval rejection/unavailability/timeout, insufficient strong approval and audit failure
before execution do not reach the tool. Invalid policy prevents Guard construction.
Tool, executor or verifier failures halt the session. Optional Gemma failure retains
deterministic evaluation; Gemma never removes a denial or reduces risk.

Dry-run explicitly disables policy/risk enforcement for valid requests. It is an adoption
diagnostic mode with real side effects, not a safe preview. Never use it to evaluate
untrusted dangerous commands against valuable systems.

## Execution boundaries

The plain decorator validates and authorizes a call, then executes trusted Python code.
It cannot prove the function implements only its declared capability. Controlled executors
replace the callback and narrow that behavior. `sandboxed=True` means an explicit executor
is required; this name is API compatibility with the product design, not OS confinement.

Filesystem checks assume no hostile concurrent filesystem mutations. Resolved paths and
link rejection reduce accidents but do not remove TOCTOU or hardlink attacks. Use a dedicated
unprivileged account/container and read-only mounts for stronger isolation. Snapshot limits
also assume a stable workspace; snapshots are not a hostile-filesystem resource sandbox.

Shell command strings are exact keys to administrator-supplied argv lists. Shell parsing is
disabled and executable paths must be absolute. Working directory does not restrict file
access. Git hooks, test files, Python imports, build scripts and executable binaries are
code and must be trusted or isolated. Output is bounded, but descendants can escape process
cleanup. No subprocess-count or memory limit is claimed.

The network executor resolves the host once, requires every address to be public and
connects only to those addresses, so DNS rebinding cannot redirect it. Redirects and
environment proxies are disabled. Only GET is implemented; this is not a generic secure
HTTP client. `EgressProxy` applies the same pinning to tunneled connections, but only
network isolation can force tools to use it.

`ContainerExecutor` adds OS-level isolation for untrusted commands: no network, read-only
root, no capabilities, no new privileges, an unprivileged user and resource limits. It
inherits the container engine's trust and kernel-sharing model.

## Verification and audit interpretation

An approval authorizes the normalized action snapshot. Providers receive a deep copy, so
editing their request cannot alter execution. The verifier checks persistent file content
inside one root only. Failure means effects may already have occurred. There is no rollback.
Concurrent legitimate writers can cause verification failures; use an isolated workspace.

The audit boundary begins at Guard dispatch; requests rejected by a framework before
dispatch are not seen. Audit logs omit full results and raw exception text. Sensitive-data
patterns are heuristic, so logs and exception causes still require controlled access.
Signing keys, retention controls and off-host copies (exporters) belong to the deployment.
Appends check only the checkpoint and the last event; full verification catches older edits.
An empty or consistently rewritten unsigned chain is not proof of history.

## Approvals and the dashboard

Approver tokens are bearer credentials: store them like passwords and remove approvers who
leave. The dashboard requires an approver for every page, uses HttpOnly SameSite=Strict
session cookies, a CSRF header for writes and a strict Content-Security-Policy, and binds to
localhost by default. Expose it only behind HTTPS with `--secure-cookies`. Grants trade
interruptions for exposure: prefer `once` and short durations for high-risk tools.

## Non-goals

AgentGuard cannot secure a compromised host, malicious trusted application/plugin, or actions
outside the interception boundary. It cannot guarantee LLM intent classification, exhaustive
secret/PII detection, safe arbitrary-code execution, transactional rollback or forensic log
authenticity. This MVP is not a replacement for OS sandboxing or an independent security audit.

