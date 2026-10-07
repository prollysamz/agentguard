class GuardMiddleware:
    """Dispatch only registered tool names; caller-supplied capability/context is ignored."""

    def __init__(self, guard):
        self.guard = guard

    def invoke(self, tool: str, arguments: dict):
        return self.guard.call(tool, arguments)

    async def ainvoke(self, tool: str, arguments: dict):
        return await self.guard.acall(tool, arguments)
