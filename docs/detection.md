# Detection

AgentGuard looks for credentials, personal data and dangerous commands in every call's
arguments, and for credentials in every result. What it finds drives policy conditions
(`sensitive_data`), risk scores, session taint and redaction in audit logs and
notifications.

## Credentials

Three sources, combined:

| Source | Covers |
| --- | --- |
| [gitleaks](https://github.com/gitleaks/gitleaks) ruleset, vendored (MIT) | 221 rules for provider tokens and keys: cloud, source hosting, payments, chat, AI APIs and a generic high-entropy key rule |
| AgentGuard patterns | Private key blocks, JWTs, database connection strings, `password=...` pairs, short test-style GitHub and `sk-` tokens |
| Field names | Values under keys like `password`, `token`, `api_key`, `authorization` |

The gitleaks rules run on [RE2](https://github.com/google/re2) (the `google-re2` package),
the engine they were written for. Matching is linear time, so scanning attacker-controlled
text such as a fetched web page cannot stall the agent (110 KB scans in about 20 ms).
Keyword prefilters, entropy thresholds, allowlists and stopwords apply as they do in
gitleaks; for example, AWS's documented example key is not flagged. Refresh the rules with:

```sh
python scripts/update_secret_rules.py      # latest gitleaks config, or --ref <commit>
python -m pytest -q                        # then review the diff
```

Categories reported: `api_key`, `ssh_key`, `jwt`, `password`, `database_url`.

## Personal data

| Category | Detection | Redacted in logs |
| --- | --- | --- |
| `credit_card` | 13–19 digits, known issuer prefix, Luhn checksum | Yes |
| `ssn` | US format with issuance rules (no `000`, `666`, `9xx` areas) | Yes |
| `iban` | Country code and ISO 7064 mod 97 checksum | Yes |
| `email` | Address syntax | No: often the action's subject |
| `phone` | International `+CC` and North American formats | No |

Checksums keep false positives low: `4111 1111 1111 1112` and `GB00 WEST ...` are not
reported. Outbound payloads with card numbers, SSNs or IBANs add 30 risk; other personal
data adds 10. Policies can name any category:

```yaml
- capability: email.send
  sensitive_data: [credit_card, ssn, iban]
  effect: deny
```

## Commands

Shell commands are tokenized like a POSIX shell, split at `; & | && ||`, newlines, `$( )`
and backticks, and unwrapped from `bash -c`, `cmd /c`, `powershell -Command`, `eval`,
`env`, `nohup`, `sudo`, `busybox` and similar. Each simple command is judged by its
program and flags.

| Result | Examples |
| --- | --- |
| **Always denied** | Recursive forced deletion (`rm -r -f`, `Remove-Item -Recurse -Force`, `find -delete`), disk tools, world-writable or setuid permissions, disabling firewalls or security services, download-and-execute, decoded payloads piped into a shell, encoded PowerShell, credential files |
| **Asks a human** (risk 70) | `terraform destroy`, `kubectl delete`, cloud CLI deletes, destructive SQL, `git reset --hard`, `nc`/`socat` in pipelines, command substitution in DNS lookups, inline interpreter code with network access or file deletion, secret-looking environment variables, environment dumps piped onward, run-time-built program names, generated code piped into an interpreter |
| **Writes that ask** | Shell profiles, git hooks, CI workflows, systemd units, cron, launch agents, `/etc`, `/var/log` |

Shell is too expressive for string analysis to be complete. Obfuscation is treated as a
reason to ask rather than decoded. For untrusted workloads, use exact-command executors
(`ShellExecutor`, `ContainerExecutor`), which run only argv lists you wrote.
`agentguard explain policy.yaml shell.execute --arg cmd="..."` shows how any command is
judged. See [Benchmarks](benchmarks.md) for measured recall and false-positive rates.

Changes to Git's `core.hooksPath` also raise risk to 70: redirecting hooks can run
code on later Git operations or disable existing checks. This covers legacy assignments,
`--add`, `--replace-all`, `--unset`, `--unset-all`, and modern `config set`/`config unset`,
across config scopes and explicit files. Queries (`config get`, `--get`, or a key without
a value) and unrelated settings such as `user.name` do not raise this concern.
Ask-level concerns propagate through shell, cmd, PowerShell and eval wrappers, within
the analyzer's nesting limit. This check does not cover every way of configuring hooks,
such as Git aliases, direct config-file edits or command-scoped `git -c` overrides.
