"""Sync bridge from the agent loop to the Blast Radius MCP server (stdio). Runs an asyncio loop in a background thread."""
from __future__ import annotations
import asyncio, json, os, pathlib, sys, threading
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

ROOT = pathlib.Path(__file__).resolve().parent.parent


class McpBridge:
    def __init__(self, graph: str, repo: str | None):
        self.graph, self.repo = graph, repo
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True); self._thread.start()
        self._session = None; self._ctx = []
        self.tools: list[dict] = []
        self._run(self._connect())

    def _run(self, coro, timeout=180):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    async def _connect(self):
        env = {**os.environ, "BLAST_GRAPH": self.graph, "BLAST_REPO": self.repo or "", "PYTHONPATH": str(ROOT)}
        params = StdioServerParameters(command=sys.executable, args=["-m", "agent.mcp_server"], env=env, cwd=str(ROOT))
        ctx = stdio_client(params); read, write = await ctx.__aenter__(); self._ctx.append(ctx)
        sess = ClientSession(read, write); await sess.__aenter__(); self._ctx.append(sess)
        await sess.initialize(); self._session = sess
        listed = await sess.list_tools()
        self.tools = [{"name": t.name, "description": t.description or "", "input_schema": _clean(t.input_schema)} for t in listed.tools]

    def call(self, name: str, args: dict) -> str:
        async def _c():
            r = await self._session.call_tool(name, args)
            parts = [c.text for c in r.content if getattr(c, "type", "") == "text"]
            return "\n".join(parts) if parts else json.dumps({"error": "empty MCP result"})
        return self._run(_c(), timeout=600)

    def close(self):
        async def _close():
            for c in reversed(self._ctx):
                try:
                    await c.__aexit__(None, None, None)
                except Exception:
                    pass
        try:
            self._run(_close(), timeout=10)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)


def _clean(schema: dict) -> dict:
    """MCP schemas come from Python signatures; keep them as plain JSON Schema for the Anthropic API."""
    s = dict(schema or {}); s.setdefault("type", "object"); s.pop("title", None)
    for p in s.get("properties", {}).values():
        p.pop("title", None)
    return s
