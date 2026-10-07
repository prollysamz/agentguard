def register_tool(server, guard, function, *, capability, **options):
    """Register a guarded callable on an MCP Python SDK 1.x FastMCP server."""
    guarded = guard.tool(capability=capability, **options)(function)
    server.add_tool(guarded)
    return guarded
