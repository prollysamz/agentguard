# Public API

This page is the list of AgentGuard's designated public API: the names under
[`agentguard`](#agentguard) and in [Other public modules](#other-public-modules).
[Provisional modules](#provisional-modules) are usable but may change in any minor release.
Everything else is internal and may change without notice. Breaking changes are listed in
the [changelog](changelog.md); see [Stability](stability.md) for what is proposed for 1.0.

## `agentguard`

| Name | Kind | Purpose |
| --- | --- | --- |
| `Guard(policy, audit="agentguard.jsonl", *, mode, agent_id, context, approval, approval_timeout, judge, rate_limiter)` | class | The interception point. `audit` is a path or an `AuditLogger`. See below. |
| `GuardDenied` | exception | A call was denied; `.decision` holds the details |
| `ApprovalPending` | exception | A `GuardDenied` for a call queued for a human; `.request_id` |
| `GuardError` | exception | Infrastructure or execution failure; base of `GuardDenied` |
| `Decision` | dataclass | `effect`, `policy_result`, `risk_score`, `reasons`, `strong_approval` |
| `Effect` | enum | `ALLOW`, `ASK`, `DENY` |
| `Action` | model | The normalized call given to approvers, judges, executors and verifiers |
| `Approval`, `ApprovalProvider` | dataclass, protocol | Approval answers and the provider interface |
| `load_policy(source)` | function | Load and validate a policy from a path, dict or `Policy` |
| `explain(policy, capability, arguments, *, working_directory, environment)` | function | The data behind `agentguard explain` |
| `__version__` | str | Installed version |

### `Guard`

| Member | Purpose |
| --- | --- |
| `tool(*, capability, name, sandboxed, executor, verifier, path_arg, url_arg, command_arg, content_arg, recipient_args)` | Decorator that registers a tool |
| `call(name, arguments)` / `await acall(name, arguments)` | Dispatch by name |
| `new_session(agent_id=None)` | A `Session` with `call`, `acall`, `with` binding, `state`, `summary` |
| `default_session` | The session used when none is bound |
| `tools` | Registered tool names |
| `capabilities` | Built-in plus policy-declared capabilities |
| `summary` | Count of evaluated decisions by effect |
| `session_id`, `session` | Session identity and risk state |

Constructor options: `mode` is `"enforce"` or `"dry-run"`; `context` is
`{"working_directory", "environment", "user"}`; `approval_timeout` is in seconds.

## Other public modules

| Module | Names |
| --- | --- |
| `agentguard.approval` | `Approval`, `ApprovalProvider`, `ApprovalStore`, `QueueApproval`, `CLIApproval`, `SlackNotifier`, `WebhookNotifier` |
| `agentguard.approval.webhook` | `verify_signature` |
| `agentguard.audit.logger` | `AuditLogger` |
| `agentguard.audit.export` | `LoggingExporter`, `HttpExporter` |
| `agentguard.audit.reader` | `read_log` |
| `agentguard.audit.report` | `build_report`, `format_report` |
| `agentguard.core.ratelimit` | `LocalRateLimiter`, `RedisRateLimiter` |
| `agentguard.execution` | `ContainerExecutor`, `FilesystemExecutor`, `ShellExecutor`, `NetworkExecutor`, `WorkspaceVerifier` |
| `agentguard.execution.egress` | `EgressProxy` |
| `agentguard.risk.secrets` | `detect_secrets`, `detect_pii`, `detect_sensitive`, `redact` |
| `agentguard.adapters.langchain` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.openai_agents` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.adk` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.mcp` | `register_tool` |
| `agentguard.adapters.python` | `GuardMiddleware` |
| `agentguard.risk.gemma_judge` | `GemmaJudge`, `OllamaClient` |

## Provisional modules

These work and are documented, but their names, signatures and results may change in any
minor release, with a changelog note. Do not build long-lived integrations on them.

| Module | Names | Why provisional |
| --- | --- | --- |
| `agentguard.bench.judge` | `load_cases`, `run_benchmark`, `summarize` | Benchmark helpers; the case format and metrics are still evolving |
| `agentguard.risk.commands` | `analyze`, `assess` | Command-analysis internals; use `explain` or a `Guard` for decisions |
| `agentguard.dashboard.app` | `create_app` | Dashboard internals; run it with `agentguard dashboard` |

The package ships `py.typed`.
