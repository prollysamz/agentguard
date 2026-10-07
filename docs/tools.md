# Registering tools

```python
@guard.tool(capability="filesystem.read")
def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    ...
```

`guard.tool` returns a wrapper with the same name, docstring and signature, so agent
frameworks build the same schema they would for the raw function. Give the agent the
wrapper only. Calling it runs the full [pipeline](concepts.md#the-pipeline).

## Requirements

- Every parameter needs a type annotation. Values are validated strictly: the string
  `"3"` is not an `int`.
- No `*args`, `**kwargs` or positional-only parameters.
- Arguments must be JSON-compatible and fit `limits.max_argument_bytes`.
- Tool names are unique per Guard (`name=` overrides the function name).
- The capability must be built in or [declared in the policy](policy.md#custom-capabilities).

Misconfigured tools raise `ValueError` at registration, not on the first call.

## Argument roles

Checks look for specific arguments: `path` for files, `url` for network, `cmd` or
`command` for shell and repository tools, `content` for file writes, and `to`, `cc`, `bcc`,
`recipient`, `recipients` for recipient limits. If your parameters are named differently,
say which one plays each role:

```python
@guard.tool(capability="filesystem.write", path_arg="filename", content_arg="text")
def save_note(filename: str, text: str) -> dict: ...

@guard.tool(capability="network.request", url_arg="endpoint")
def fetch(endpoint: str, timeout: int = 10) -> str: ...

@guard.tool(capability="shell.execute", command_arg="script")
def run(script: str) -> str: ...

@guard.tool(capability="email.send", recipient_args=["emails", "watchers"])
def notify(emails: list[str], watchers: list[str], body: str) -> str: ...
```

Policy, risk, executors and the audit log see the canonical names (`path`, `url`, ...).
Your function is still called with its own parameter names.

## Async tools

```python
@guard.tool(capability="network.request")
async def fetch(url: str) -> str: ...

text = await fetch("https://docs.python.org/3/")
```

Async calls run the pipeline in a worker thread; calls on one Guard are serialized.
`await guard.acall(name, arguments)` is the async form of `guard.call`. Cancelling the
caller does not cancel a tool that is already executing.

## Executors and verifiers

An executor replaces your function with a narrower implementation. A verifier checks what
changed afterwards. See [Controlled execution](execution.md).

```python
from agentguard.execution import FilesystemExecutor, WorkspaceVerifier

@guard.tool(
    capability="filesystem.write",
    executor=FilesystemExecutor("./workspace"),
    verifier=WorkspaceVerifier("./workspace"),
)
def write_file(path: str, content: str) -> dict:
    raise AssertionError("The executor runs instead")
```

`sandboxed=True` requires an executor; it does not mean OS isolation.

## Calling by name

Agent loops that receive a tool name and a JSON object can dispatch directly:

```python
result = guard.call("read_file", {"path": "workspace/notes.txt"})
```

Unknown names, wrong types, extra or missing arguments are denied and audited.
`guard.tools` lists registered names, for building a model's tool list.

## Handling denials

A denied call raises `GuardDenied`. `exc.decision` holds the effect, risk score and
reasons. Other failures raise `GuardError`; after an execution or verification failure the
session is halted. Framework adapters return denials to the model as results by default,
so the agent can adapt instead of crashing.
