"""Render a readable tool-call log (MCP request/response per step) from a saved run: python scripts/export_tool_log.py <run-id> > docs/example-tool-calls.md"""
import json, sys, pathlib, datetime
run = json.load(open(pathlib.Path(__file__).resolve().parent.parent / "data" / "reports" / f"run-{sys.argv[1]}.json"))
res = run["result"]; calls = [e for e in run["events"] if e["type"] == "tool_result"]
print(f"# Example run: every tool call the agent made\n")
print(f"**Repo:** {run['graph_name']} · **Question:** {run['prompt']}\n")
print(f"**Transport:** {res.get('tools_via', 'direct')} ({res.get('tool_count', '?')} tools discovered from the MCP server) · **Model:** {res['model']} · **{len(calls)} tool calls, {len([s for s in res['trace'] if s['type']=='cypher'])} graph queries, {run['seconds']} s, {res['usage']['input']:,} tokens in / {res['usage']['output']:,} out**\n")
for i, c in enumerate(calls, 1):
    print(f"## {i}. {c.get('title') or c['name']}  \n*phase: {c.get('phase','')} · {c['ms']} ms*\n")
    print("```json\n→ mcp.call_tool(\"%s\", %s)\n```" % (c["name"], json.dumps(c.get("input", {}), ensure_ascii=False)))
    for s in c.get("steps", []):
        if s.get("query"):
            print(f"\n*Cypher run by the tool* ({s['label']}, {s['rows']} rows, {s['ms']} ms):\n```cypher\n{s['query']}\n```")
        elif s["type"] in ("action", "external"):
            print(f"\n*{s['type']}:* {s['label']}")
    prev = (c.get("preview") or "")
    print("\n```json\n← " + (prev[:700] + (" …" if len(prev) > 700 else "")) + "\n```\n")
    if c.get("summary"):
        print(f"**Result:** {c['summary']}\n")
print("## Final answer\n")
print(res["answer"])
