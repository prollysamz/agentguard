# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change the API.

## [Unreleased]

## [0.2.0] - 2026-10-08

First release on PyPI, as `agentguard-oss` (`import agentguard`).

### Added
- Argument roles: `guard.tool(path_arg=, url_arg=, command_arg=, content_arg=,
  recipient_args=)` for tools whose parameters are not named `path`, `url`, `cmd`,
  `content` or `to`. Misconfigured tools fail at registration.
- Custom capabilities declared in the policy (`capabilities: {db.query: {risk: 30}}`),
  with baseline risk, an outbound flag for session-taint checks, and a description.
- `agentguard check-policy` validates a policy and prints a summary or located errors.
- `agentguard explain` shows the matching rules, risk factors and decision for one call.
- Framework adapters: LangChain/LangGraph, OpenAI Agents SDK and Google ADK
  (`agentguard.adapters.*.guarded_tool`). Denials are returned to the model with reasons.
- Gemma is the default live demo agent when Ollama has a Gemma model; `--scripted` runs
  offline. The judge takes trusted `guidance` and a `capabilities` scope.
- `ShellExecutor(check=False)` returns nonzero exits as results.
- `Guard.tools`, `Guard.capabilities`, `agentguard.__version__`, `py.typed`.

### Changed
- Distribution renamed from `agentguard-sdk` (taken on PyPI) to `agentguard-oss`.
- Tools receive the absolute requested path; policy and credential checks use both the
  requested path and its resolved target.
- A judge `deny` flag escalates to human approval; a judge score at or above the deny
  threshold still denies.
- Ollama requests disable thinking, use an 8192-token context and longer timeouts.

### Fixed
- Links inside the workspace bypassed `FilesystemExecutor` link rejection, and Windows
  junctions were missed on Python 3.11 by the executor and the verifier.
- The email/message recipient limit ignored `cc`, `bcc` and `recipients`.
- Nested guarded calls from an async tool deadlocked.
- New files were created with lowercase names on Windows.
- `format` flags (`ruff format`, `--format=`) were hard-denied as disk formatting.
- Policy domains accepted `?` and `[`, which acted as wildcards.
- `git push` and `repository.write` were not treated as outbound for session taint.
- The audit record overwrote the action's proposal timestamp.

## [0.1.0] - 2026-10-08

Initial source release: policy as code, deterministic risk scoring, CLI approval,
controlled executors, workspace verification, hash-chained audit log, MCP adapter,
and the prompt-injection demo with an optional local Gemma agent and judge.

[Unreleased]: https://github.com/prollysamz/agentguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/prollysamz/agentguard/compare/8a0f847...v0.2.0
[0.1.0]: https://github.com/prollysamz/agentguard/commit/8a0f847
