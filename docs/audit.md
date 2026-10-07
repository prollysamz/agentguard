# Audit log

Every call is recorded in a JSON Lines file (`audit=` on the Guard, default
`agentguard.jsonl`). Each event stores the SHA-256 hash of the previous event, so editing
or deleting a line breaks the chain.

## Events

| Stage | Meaning |
| --- | --- |
| `rejected` | Malformed call, unknown tool or halted session; never evaluated |
| `proposed` | Evaluated: `policy_result`, `risk_score`, `evaluated_decision`, `reasons` |
| `denied` | Not executed, with the reason. Queued approvals add `approval_request_id` and `approval_status: pending` |
| `authorized` | Allowed or approved (`approved_by`, including the grant ID), about to run |
| `executing` | Execution started |
| `executed` | Execution returned |
| `observed` | Verification result, result type, whether output contained a secret |
| `failed` | Execution or verification failed (exception type only); session halted |

Events for one call share an `action_id`. `timestamp` is when the event was written;
`action_timestamp` is when the call was proposed. An `executing` event with no later event
can mean a crash mid-call. Arguments are redacted. Full results and raw exception messages
are never logged.

## Reading logs

```sh
agentguard verify-log --audit agentguard.jsonl
agentguard logs --audit agentguard.jsonl --decision deny
agentguard inspect evt_... --audit agentguard.jsonl
agentguard report --audit agentguard.jsonl --dry-run-only
```

Readers verify every segment and the checkpoint before showing anything. The
[dashboard](dashboard.md) shows the same data in a browser.

## Configuring the logger

```python
import os

from agentguard.audit.export import HttpExporter, LoggingExporter
from agentguard.audit.logger import AuditLogger

audit = AuditLogger(
    "/var/log/agentguard/audit.jsonl",
    max_bytes=50_000_000,                          # rotate at 50 MB
    signing_key=os.environ["AGENTGUARD_AUDIT_KEY"],
    exporters=[LoggingExporter()],
)
guard = Guard("policy.yaml", audit=audit)
```

### Checkpoint

Appends keep a small checkpoint file next to the log (`audit.jsonl.head`) with the event
count, last hash, file size and the offset of the last event. Each append checks that the
file size matches and the last event verifies, instead of re-reading the whole log, so
append cost stays flat as the log grows (about 7 ms, mostly two `fsync` calls). An append
from outside AgentGuard, a truncated tail, or an edited last event stops the next call.
Edits deeper in the file are caught by full verification (`verify-log`, the dashboard,
`read_log`). Logs without a checkpoint are verified once and migrated on the next append.

### Rotation

With `max_bytes`, the active file is renamed to `audit.000001.jsonl`, `audit.000002.jsonl`,
... before it would exceed the limit. The hash chain continues across segments, and
readers verify them all in order. Archive old segments together with the active log.

### Signing

With `signing_key`, each event gets `signature: hmac-sha256:<hex>` over its hash. Hash
chaining alone cannot detect someone who rewrites the whole chain and recomputes every
hash; without the key, they cannot recompute the signatures. Verify with the key:

```sh
agentguard verify-log --audit audit.jsonl --key-env AGENTGUARD_AUDIT_KEY
agentguard dashboard --audit audit.jsonl --audit-key-env AGENTGUARD_AUDIT_KEY
```

Keep the key away from the machine's other users and from agents. Anyone with the key can
sign events.

### Export to OpenTelemetry and SIEMs

Exporters receive each event after it is durably written. Failures are logged and never
block the agent; the local log stays the record of truth.

`LoggingExporter` emits a Python log record per event with flat attributes
(`agentguard.tool`, `agentguard.risk_score`, `agentguard.final_decision`, ...) and the
full event as JSON in `agentguard.event`. Attach any handler. For OpenTelemetry:

```python
import logging

from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

provider = LoggerProvider()
provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
logging.getLogger("agentguard.audit").addHandler(LoggingHandler(logger_provider=provider))
logging.getLogger("agentguard.audit").setLevel(logging.INFO)
```

For syslog-based SIEMs, attach `logging.handlers.SysLogHandler` instead.

`HttpExporter(url, headers=..., transform=..., secret=...)` POSTs each event as JSON from a
background thread with a bounded queue (dropped events are counted in `dropped`). For
Splunk HEC:

```python
HttpExporter(
    "https://splunk.example:8088/services/collector/event",
    headers={"Authorization": f"Splunk {hec_token}"},
    transform=lambda event: {"event": event, "sourcetype": "agentguard"},
)
```

## Limits

- Hash chains and signatures prove the log is internally consistent and was written by a
  key holder. They do not prevent deletion of the whole log; ship events off the machine
  (exporters) if that matters.
- Secret redaction is pattern-based. Protect log files and their retention.
