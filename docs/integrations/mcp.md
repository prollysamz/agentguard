# MCP

```sh
pip install "agentguard-oss[mcp]"
```

Expose guarded tools from an [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
1.x `FastMCP` server:

```python
--8<-- "examples/mcp_server.py"
```

`register_tool(server, guard, function, capability=..., **options)` decorates the function
and adds only the guarded version to the server. Run the example from the repository root
with `python examples/mcp_server.py`.

MCP validates arguments against the tool schema first; AgentGuard validates again.
Requests MCP rejects before dispatch never reach AgentGuard and are not in its audit log.
Denials come back to the client as tool errors with AgentGuard's reasons. Keep the audit
log on disk, not stdout, when using the stdio transport.
