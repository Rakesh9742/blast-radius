"""Blast Radius MCP server: every graph tool, algorithm tool and action is exposed over the Model Context Protocol (stdio).

The agent selects tools through MCP; the same server plugs into Claude Desktop / Claude Code:
  {"mcpServers": {"blast-radius": {"command": ".venv/bin/python", "args": ["-m", "agent.mcp_server"],
                   "cwd": "<repo>", "env": {"BLAST_GRAPH": "mealie", "BLAST_REPO": "<repo>/data/repos/mealie"}}}}
Each tool returns a JSON envelope: {"result": <tool output>, "trace": [cypher steps run for this call], "graph": {nodes, edges}}.
"""
from __future__ import annotations
import json, os, sys
from mcp.server.mcpserver import MCPServer
from agent.tools import GraphTools, Trace, TOOL_DEFS

server = MCPServer("blast-radius", instructions="Security-triage tools over a FalkorDB code graph: vulnerabilities, reachability, ownership, graph algorithms, and fix actions.")
_tools: GraphTools | None = None


def _gt() -> GraphTools:
    global _tools
    if _tools is None:
        _tools = GraphTools(os.getenv("BLAST_GRAPH", "mealie"), Trace(), os.getenv("BLAST_REPO") or None)
    return _tools


def _call(name: str, kwargs: dict) -> str:
    gt = _gt()
    before = len(gt.trace.steps); gt.trace.graph = {"nodes": {}, "edges": {}}
    try:
        result = getattr(gt, name)(**{k: v for k, v in kwargs.items() if v is not None or k in ("package", "endpoint")})
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}
    return json.dumps({"result": result, "trace": gt.trace.steps[before:], "graph": gt.trace.graph_dict()}, default=str)


_PY = {"string": "str", "integer": "int", "number": "float", "boolean": "bool", "array": "list[str]"}


def _pytype(prop: dict) -> str:
    t = prop.get("type")
    if isinstance(t, list):
        base = next((x for x in t if x != "null"), "string")
        return f"{_PY.get(base, 'str')} | None"
    return _PY.get(t, "str")


# Build one typed function per tool definition so the MCP schema is derived from real signatures.
for _d in TOOL_DEFS:
    _props = _d["input_schema"]["properties"]
    _opt = lambda v: "null" in (v.get("type") if isinstance(v.get("type"), list) else [])
    _ordered = sorted(_props.items(), key=lambda kv: _opt(kv[1]))          # required first, optional (nullable) last
    _params = ", ".join(f"{k}: {_pytype(v)}" + (" = None" if _opt(v) else "") for k, v in _ordered)
    if not _props:
        _params = ""
    _args = ", ".join(f"{k}={k}" for k in _props)
    _src = f'def {_d["name"]}({_params}) -> str:\n    """{_d["description"]}"""\n    return _call("{_d["name"]}", dict({_args}))\n'
    _ns: dict = {"_call": _call}
    exec(_src, _ns)
    server.tool(name=_d["name"], description=_d["description"])(_ns[_d["name"]])


if __name__ == "__main__":
    server.run(transport="stdio")
