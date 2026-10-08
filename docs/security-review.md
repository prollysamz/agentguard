# Security review guide

!!! warning "Not yet independently reviewed"
    AgentGuard has had automated analysis, property-based testing and reviews by its
    authors and AI assistants, but **no independent security review**. This page scopes one.
    AgentGuard will not be called 1.0 until it has had one.

## Scope

| Area | Code | Entry points |
| --- | --- | --- |
| Interception pipeline | `agentguard/core/guard.py` | `Guard.call/acall`, `@guard.tool`, sessions, nested calls |
| Policy | `agentguard/policy/` | YAML/JSON/dict policies, path and domain matching |
| Risk and detection | `agentguard/risk/` | Command analysis, credential paths, gitleaks rules on RE2, PII |
| Execution | `agentguard/execution/` | Filesystem, shell, container and network executors; DNS pinning; egress proxy |
| Approvals | `agentguard/approval/` | SQLite store, queued approvals and grants, Slack and webhook channels |
| Dashboard | `agentguard/dashboard/` | HTTP API, token login, cookies, CSRF, CSP, `/slack/actions` |
| Audit | `agentguard/audit/` | Hash chain, checkpoint, rotation, HMAC signing, exporters |
| Adapters | `agentguard/adapters/` | LangChain, OpenAI Agents SDK, Google ADK, MCP |
| Release | `.github/workflows/release.yml`, `scripts/` | PyPI trusted publishing, vendored ruleset updates |

The trust model, assets and non-goals are in the [threat model](security.md). In short:
model output and everything it reads are untrusted; application code, policy, executors,
approval providers and the host are trusted. AgentGuard is an interception layer, not a
sandbox, except where `ContainerExecutor` provides OS-level isolation.

## Where to look first

1. **Normalization differentials.** Can any input make policy or risk evaluate a different
   target from the one that executes? Paths (`..`, links, junctions, case, `~`, Windows
   drive and UNC forms), URLs (parser differences between `urlsplit` and httpx, IDNA,
   userinfo, ports), and commands. All three ChatGPT audit findings were here.
2. **Approvals and the dashboard.** Token generation and storage, session cookies, CSRF
   (custom-header check plus `SameSite=Strict`), grant scoping (agent, environment, tool,
   capability, expiry), race conditions between `submit`, `resolve` and `use_grant`, and the
   Slack signature check.
3. **Command analysis.** Known evasions are listed below. Exact-command executors and
   containers are the real control; the analyzer is a speed bump for plain tools.
4. **Isolation.** `ContainerExecutor` flags and defaults, behavior when the engine is
   misconfigured, `EgressProxy` CONNECT parsing and resource limits, and whether DNS
   pinning holds across redirects, retries and connection reuse.
5. **Detection.** Secret and PII evasion; regular-expression complexity in AgentGuard's own
   patterns (gitleaks rules run on RE2; the rest run on Python's backtracking `re`).
6. **Audit integrity.** Whether the documented guarantees (checkpoint, segments,
   signatures) hold, and what an attacker with write access to the log directory can do.
7. **Supply chain.** Pinned dependency ranges, the vendored gitleaks rules and their update
   script, GitHub Actions permissions, and the trusted-publishing release workflow.

## Known weaknesses

These are documented, not fixed. A reviewer should confirm the documentation is accurate
and look for worse variants.

- **Shell string analysis is incomplete.** Obfuscation (run-time-built program names,
  `eval`, generated code piped into a shell) is flagged for approval rather than decoded.
  Arbitrary code inside an interpreter (`python -c`) is only recognized by keywords.
- **Strong approval over the API** re-enters the same bearer token, which proves nothing
  for an automated caller. Strong approvals should be given by a person in the dashboard.
- **Approver tokens are bearer credentials.** Anyone holding one can approve until the
  approver is removed. The approval store should be readable only by its service account.
- **Grants widen what runs without asking.** A tool grant covers any arguments.
- **Unsigned audit logs** can be rewritten consistently by anyone with write access.
- **The egress proxy cannot see inside TLS.** Domain fronting on shared CDNs is possible.
- **Plain Python tools** receive the requested path and can follow links that change after
  policy evaluation (TOCTOU). Use `FilesystemExecutor` or a container for untrusted paths.
- **Benchmarks** were written by the same authors as the rules; see
  [Benchmarks](benchmarks.md).

## Automated checks in place

| Check | Where |
| --- | --- |
| Unit, integration and property-based tests on Linux, Windows, macOS × Python 3.11–3.14 | CI on every push |
| Property-based tests at 3,000 examples per property | Nightly CI |
| Docker isolation tests against a real engine | CI (Linux) |
| CodeQL (Python, JavaScript, Actions; security-extended queries) | Security workflow |
| bandit | Security workflow |
| pip-audit on all runtime dependencies | Security workflow, weekly |
| Dependabot for Python and Actions | Weekly |

## Issues found and fixed so far

Found by the authors, an AI-assisted audit, property-based tests and new CI platforms.
None of these was found by an independent reviewer.

| Issue | Found by | Fixed in |
| --- | --- | --- |
| Links inside the workspace bypassed `FilesystemExecutor`; Windows junctions missed on Python 3.11 | AI audit | 0.2 |
| Recipient limits ignored `cc` and `bcc` | AI audit | 0.2 |
| Nested async guarded calls deadlocked | AI audit | 0.2 |
| New files lowercased on Windows; `format` flags hard-denied; `?` and `[` acted as domain wildcards | Author review | 0.2 |
| `rm -r -f`, `chmod 0777`, `curl … \| python3` evaded detection; `echo rm -rf` falsely blocked | Property tests | 0.4 |
| URLs with DEL or C1 control characters accepted, then failed inside httpx | Property tests | 0.4 |
| `curl -d @.env` not treated as reading a credential file | Dashboard seeding | 0.3 |
| `killpg` raised on macOS during timeout cleanup | macOS CI | 0.4 |
| Writable container workspaces were unwritable (uid mismatch) | Docker CI | 0.4 |
| Persistence paths missed once normalized to `C:\…` on Windows | Benchmark | 0.4 |
| A benchmark run with the model offline silently reported no judge results | Benchmark | 0.4 |

## Running it locally

```sh
git clone https://github.com/prollysamz/agentguard.git && cd agentguard
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev,all,docs]"
python -m pytest -q
HYPOTHESIS_PROFILE=thorough python -m pytest -q tests/test_properties.py
python -m bandit -q -r agentguard
agentguard judge-bench                              # rules-only benchmark
agentguard demo --scripted
agentguard dashboard                                # after: agentguard approvers add you
```

## Exit criteria for 1.0

- An independent review covering the areas above, with every critical and high finding
  fixed and the report (or a summary) published.
- A holdout benchmark written by someone other than the rule authors, with results
  published for the deterministic rules and at least one judge model.
- No open known weakness without either a fix or a documented, tested mitigation.

## Reporting a vulnerability

Report privately through
[GitHub security advisories](https://github.com/prollysamz/agentguard/security/advisories/new).
