# Public API

These names are the supported API. Everything else is internal and may change between
0.x releases. Breaking changes are listed in the [changelog](changelog.md).

## `agentguard`

| Name | Kind | Purpose |
| --- | --- | --- |
| `Guard(policy, audit="agentguard.jsonl", *, mode, agent_id, context, approval, approval_timeout, judge)` | class | The interception point. See below. |
| `GuardDenied` | exception | A call was denied; `.decision` holds the details |
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
| `tools` | Registered tool names |
| `capabilities` | Built-in plus policy-declared capabilities |
| `summary` | Count of evaluated decisions by effect |
| `session_id`, `session` | Session identity and risk state |

Constructor options: `mode` is `"enforce"` or `"dry-run"`; `context` is
`{"working_directory", "environment", "user"}`; `approval_timeout` is in seconds.

## Other public modules

| Module | Names |
| --- | --- |
| `agentguard.approval` | `Approval`, `ApprovalProvider`, `CLIApproval` |
| `agentguard.execution` | `FilesystemExecutor`, `ShellExecutor`, `NetworkExecutor`, `WorkspaceVerifier` |
| `agentguard.adapters.langchain` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.openai_agents` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.adk` | `guarded_tool`, `from_guarded` |
| `agentguard.adapters.mcp` | `register_tool` |
| `agentguard.adapters.python` | `GuardMiddleware` |
| `agentguard.risk.gemma_judge` | `GemmaJudge`, `OllamaClient` |

The package ships `py.typed`.
