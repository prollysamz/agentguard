# Public API

These names are the supported API. Everything else is internal and may change between
0.x releases. Breaking changes are listed in the [changelog](changelog.md).

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
| `agentguard.dashboard.app` | `create_app` |
| `agentguard.execution` | `ContainerExecutor`, `FilesystemExecutor`, `ShellExecutor`, `NetworkExecutor`, `WorkspaceVerifier` |
| `agentguard.execution.egress` | `EgressProxy` |
| `agentguard.risk.commands` | `analyze`, `assess` |
| `agentguard.risk.secrets` | `detect_secrets`, `detect_pii`, `detect_sensitive`, `redact` |
| `agentguard.bench.judge` | `load_cases`, `run_benchmark`, `summarize` |
| `agentguard.adapters.langchain` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.openai_agents` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.adk` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.mcp` | `register_tool` |
| `agentguard.adapters.python` | `GuardMiddleware` |
| `agentguard.risk.gemma_judge` | `GemmaJudge`, `OllamaClient` |

The package ships `py.typed`.
