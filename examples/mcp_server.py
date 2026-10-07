"""Run from the repository root after installing .[mcp]. Audit goes to disk, not stdout."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from agentguard import Guard
from agentguard.adapters.mcp import register_tool
from agentguard.execution import FilesystemExecutor

root = Path("workspace").resolve()
root.mkdir(exist_ok=True)
guard = Guard("examples/policy.yaml")
server = FastMCP("AgentGuard")


def read_file(path: str) -> str:
    """Read a workspace file through AgentGuard."""
    raise AssertionError("The controlled executor handles the read")


register_tool(
    server, guard, read_file, capability="filesystem.read", executor=FilesystemExecutor(root)
)

if __name__ == "__main__":
    server.run(transport="stdio")
