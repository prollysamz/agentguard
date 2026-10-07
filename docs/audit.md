# Audit log

Every call is recorded in a JSON Lines file (`audit=` on the Guard, default
`agentguard.jsonl`). Each event stores the SHA-256 hash of the previous event, so editing
or deleting a line in the middle breaks the chain.

## Events

| Stage | Meaning |
| --- | --- |
| `rejected` | Malformed call, unknown tool or halted session; never evaluated |
| `proposed` | Evaluated: `policy_result`, `risk_score`, `evaluated_decision`, `reasons` |
| `denied` | Not executed, with the reason |
| `authorized` | Allowed or approved (`approved_by`), about to run |
| `executing` | Execution started |
| `executed` | Execution returned |
| `observed` | Verification result, result type, whether output contained a secret |
| `failed` | Execution or verification failed (exception type only); session halted |

Events for one call share an `action_id`. `timestamp` is when the event was written;
`action_timestamp` is when the call was proposed. An `executing` event with no later event
can mean a crash mid-call.

Arguments are redacted (secret-looking keys and values). Full results and raw exception
messages are never logged.

## Reading logs

```sh
agentguard verify-log --audit agentguard.jsonl
agentguard logs --audit agentguard.jsonl --decision deny
agentguard logs --audit agentguard.jsonl --risk high
agentguard inspect evt_... --audit agentguard.jsonl
```

Readers verify the whole chain before showing anything.

## Guarantees and limits

- Appends take a cross-process file lock, verify the chain, then write, flush and `fsync`.
- If the audit write fails before execution, the call does not run.
- Hash chaining cannot detect a fully rewritten chain or a truncated tail. Store the latest
  hash and event count somewhere else, or ship events to append-only storage, if you need
  that.
- Each append re-reads the file: fine for development and small deployments, slow for very
  large logs.
- Secret redaction is pattern-based. Protect log files and their retention.
