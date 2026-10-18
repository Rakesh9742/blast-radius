"""Claude tool-use loop for Blast Radius. Manual loop so every step is traced for the UI."""
from __future__ import annotations
import json, os, time
from typing import Callable
import anthropic
from agent.tools import GraphTools, Trace, TOOL_DEFS, dispatch
from agent.mcp_bridge import McpBridge

TOOL_TRANSPORT = os.getenv("BLAST_TOOLS", "mcp")   # 'mcp' (default): tools selected and called through the Blast Radius MCP server; 'direct': in-process

MODEL = os.getenv("BLAST_MODEL", "claude-opus-5-5")
EFFORT = os.getenv("BLAST_EFFORT", "medium")

SYSTEM = """You are Blast Radius, a security triage agent. You reason over a code knowledge graph stored in FalkorDB that links
vulnerabilities -> packages -> functions that use them -> call chains -> HTTP endpoints, plus git ownership.

Your job when given a vulnerability, CVE, or package: determine whether it is actually reachable in THIS codebase, by which endpoints,
who owns the code, and what the fix is. Then act: plan and verify the fix, apply it on a branch, open a PR (or write a report), and record the decision.

Method (follow in order, skip steps that are clearly unnecessary):
1. Identify: find_vulnerability / list_vulnerabilities to pin the package, installed version, severity and fixed version. Call past_decisions too: if this was already triaged, say so and build on it.
   Call live_app_status once: if a live deployment is connected, endpoints carry live/auth_required flags; rank live + unauthenticated endpoints first and say which findings are confirmed deployed vs static-only.
2. Direct reachability: reachability(package). If no first-party function uses it, run transitive_exposure(package) and reason about the framework layer.
   If asked about data impact, or when the sink functions touch persistence, call data_exposure(package=...) to name the tables at risk.
   probe_endpoints only when the user explicitly says they own/are authorized to test the deployment; never otherwise.
   Then use the graph algorithms: shortest_attack_paths(package) for the exact attack path to quote, and choke_points(package) to find the one function where a guard protects the most endpoints (mention it in the fix section). impact_radius(function) when asked what a function change or compromise would affect.
2b. Portfolio: if other repositories have been analysed, call cross_repo_impact(package) once and add a short 'Other repositories' line to the answer (which repos carry the same package, how many endpoints reach it there, what was decided before). Skip it when it returns no other repos.
3. Narrow by vulnerability semantics: read the vulnerability details (e.g. image decoding -> only endpoints that accept images; multipart -> upload/form endpoints; JWT -> auth paths). Use get_function on the sink to confirm the vulnerable API is actually called.
4. Ownership: who_owns on the key sink function or file.
5. Fix: plan_fix -> verify_fix -> apply_dependency_fix. Then open_pull_request with a markdown body (impact, endpoints, path, owners, fix). Then record_triage_decision.
   If the user only asks a question (no request to fix), stop after step 4 and offer the fix.

When the verdict is NOT REACHABLE or NEEDS REVIEW, do not just stop:
- Say precisely what evidence would change the verdict (e.g. "a call from any handler into decode_unsafe", "runtime traces showing X").
- Name the owner who should confirm, using who_owns on the closest sink or file.
- Still record_triage_decision for every advisory you assessed (NOT_REACHABLE or NEEDS_REVIEW with the reason), so the graph remembers.
- If a safe upgrade exists, offer it as low-priority hygiene (plan_fix / verify_fix) and say it is optional; apply it only if the user asked you to fix.

Rules:
- Only state endpoints, functions, owners and versions that appeared in tool results. Never invent paths. Quote confidence (high/medium) from reachability.
- Prefer several focused tool calls over one giant one. You may call independent tools in parallel.
- Final answer format (markdown):
  **Verdict:** EXPLOITABLE / NOT REACHABLE / NEEDS REVIEW - one line why.
  Start every line or table row that needs a human's attention with 🔴 (publicly callable endpoints, unknown auth status on paths that serve files, certificates, exports or payments, exploitable paths, deployed routes missing from code). Put them in a short **Needs attention** list right after the verdict. Never prefix routine items.
  **Affected endpoints:** table (endpoint, hops, confidence).
  **Attack path:** the shortest path as `endpoint -> handler -> ... -> sink -> package`.
  **Owners:** names with share and last touched.
  **Fix:** version, verification result, branch / PR / report.
  Tables: at most 4 columns, endpoint first, short cells (no sentences inside cells; put explanations in bullets below the table).
  Keep it tight; the UI shows the graph and the queries next to your answer.
Repository under analysis: {repo}. GitHub PRs {gh}."""


PHASE = {"data_exposure": "reach", "probe_endpoints": "reach", "live_app_status": "identify", "shortest_attack_paths": "reach", "choke_points": "reach", "impact_radius": "reach", "list_vulnerabilities": "identify", "find_vulnerability": "identify", "past_decisions": "identify",
         "reachability": "reach", "transitive_exposure": "reach", "cross_repo_impact": "reach", "get_function": "reach", "search_code": "reach", "run_cypher": "reach",
         "who_owns": "owners", "plan_fix": "fix", "verify_fix": "fix", "apply_dependency_fix": "act", "open_pull_request": "act",
         "record_triage_decision": "record"}
TITLE = {"data_exposure": "Data at risk", "probe_endpoints": "Probe live endpoints", "live_app_status": "Check the live deployment", "shortest_attack_paths": "Shortest attack paths to", "choke_points": "Find choke points for", "impact_radius": "Blast radius of", "list_vulnerabilities": "Scan vulnerable packages", "find_vulnerability": "Look up advisory", "past_decisions": "Check earlier decisions",
         "reachability": "Trace endpoints that reach", "transitive_exposure": "Walk dependency chain for", "cross_repo_impact": "Check other analysed repos for", "get_function": "Read function",
         "search_code": "Search code for", "run_cypher": "Ad-hoc graph query", "who_owns": "Find owners of", "plan_fix": "Plan fix for",
         "verify_fix": "Verify fix with OSV", "apply_dependency_fix": "Bump dependency on a branch", "open_pull_request": "Open pull request",
         "record_triage_decision": "Record triage decision"}


def describe(name: str, args: dict, out: str) -> dict:
    """Human-readable title + one-line result for the UI, derived from tool input/output."""
    subject = args.get("package") or args.get("query") or args.get("target") or args.get("qualname") or args.get("title") or ""
    if name == "impact_radius":
        subject = (args.get("function") or "").split(".")[-1]
    if name == "get_function" or name == "who_owns":
        subject = subject.split(".")[-1] if "/" not in subject else subject.split("/")[-1]
    if name == "record_triage_decision":
        subject = args.get("status", "")
    if name == "run_cypher":
        subject = ""
    title = f"{TITLE.get(name, name)} {subject}".strip()
    try:
        o = json.loads(out)
    except Exception:
        return {"title": title, "summary": "", "phase": PHASE.get(name, "reach")}
    if isinstance(o, dict) and o.get("error"):
        return {"title": title, "summary": f"error: {str(o['error'])[:90]}", "phase": PHASE.get(name, "reach"), "error": True}
    s = ""
    try:
        if name == "list_vulnerabilities":
            s = f"{o['count']} advisories on {o['package']}" if "package" in o else f"{len(o['vulnerable_packages'])} vulnerable packages, {sum(1 for p in o['vulnerable_packages'] if p['used_by_functions'])} used by first-party code"
        elif name == "find_vulnerability":
            m = o["matches"]; s = f"{len(m)} match(es)" + (f": {m[0]['id']} ({m[0]['severity']}) in {m[0]['package']} {m[0]['installed']}" if m else "")
        elif name == "reachability":
            s = f"{o['reachable_endpoints']} of {o['total_endpoints']} endpoints reach {len(o['sink_functions'])} function(s) using {o['package']}"
        elif name == "cross_repo_impact":
            aff = [r for r in o["repos"] if r.get("advisories")]
            s = (f"{len(aff)} of {o['other_repos_analysed']} other analysed repos carry vulnerable {o['package']}: " + ", ".join(f"{r['graph']} ({r['version']}, {r['endpoints_reaching']} endpoints reach it)" for r in aff[:4])) if aff else f"none of the {o['other_repos_analysed']} other analysed repos carries vulnerable {o['package']}"
        elif name == "transitive_exposure":
            s = f"depended on by {', '.join(p['parent'] for p in o['depended_on_by'][:4]) or 'nothing'}; {o.get('files_importing_directly', 0)} files import it directly"
        elif name == "who_owns":
            ow = o["owners"]; s = f"{ow[0]['name']} ({int(ow[0]['avg_share']*100)}% share, last touched {ow[0]['last_touched']})" + (f" +{len(ow)-1} more" if len(ow) > 1 else "") if ow else "no ownership data"
        elif name == "get_function":
            s = f"{o['file']}:{o['line']} · {len(o['callers'])} callers · uses {', '.join(o['packages_used'][:3]) or 'no external packages'}"
        elif name == "search_code":
            s = f"{len(o['results'])} functions"
        elif name == "run_cypher":
            q = " ".join(str(args.get("query", "")).split()); s = f"{len(o['rows'])} rows · {q[:110]}{'…' if len(q) > 110 else ''}"
        elif name == "past_decisions":
            s = f"{len(o['decisions'])} earlier decisions" if o["decisions"] else "nothing triaged before"
        elif name == "plan_fix":
            s = f"{o['installed']} → {o['minimum_safe_version']} (latest on {o.get('registry', 'the registry')} {o.get('latest_release')}), resolves {o['vulnerabilities_resolved']} advisories"
        elif name == "verify_fix":
            s = f"{o['package']} {o['version']}: " + ("clean, no known vulnerabilities" if o["clean"] else f"{len(o['known_vulnerabilities'])} known vulnerabilities remain")
        elif name == "apply_dependency_fix":
            s = f"branch {o['branch']} @ {o['commit']}"
            return {"title": title, "summary": s, "phase": "act", "diff": o.get("diff", "")}
        elif name == "open_pull_request":
            s = o.get("pull_request") or f"report written: {o.get('report_path', '').split('/')[-1]}"
        elif name == "record_triage_decision":
            s = f"{len(o['recorded'])} advisories marked {o['status']}"
        elif name == "data_exposure":
            s = (f"{len(o['tables_on_attack_paths'])} tables on attack paths" if "tables_on_attack_paths" in o else f"{len(o.get('tables', o.get('results', [])))} tables")
        elif name == "probe_endpoints":
            vs = [r["verdict"] for r in o["results"]]; s = ", ".join(f"{vs.count(v)} {v}" for v in sorted(set(vs)))
        elif name == "live_app_status":
            if not o.get("connected"):
                s = "no live app connected"
            elif o.get("frontend_confirmed_calls") and not o.get("only_in_code") and o.get("live") == o.get("frontend_confirmed_calls", 0) + o.get("frontend_route_strings_unconfirmed", 0):
                s = f"{o['frontend_confirmed_calls']} API calls confirmed from the frontend · {o['frontend_route_strings_unconfirmed']} unconfirmed route strings · {o['live_unauthenticated']} callable without login · {len(o.get('api_areas_from_frontend', []))} API areas"
            else:
                s = f"{o['live']} live endpoints · {o['live_unauthenticated']} callable without login · {o['only_live']} only in the deployment · {o['only_in_code']} only in code"
        elif name == "shortest_attack_paths":
            s = f"{len(o['paths'])} shortest paths via algo.SPpaths" + (f", best {o['paths'][0]['hops']} hops to {o['paths'][0]['endpoint']}" if o['paths'] else "")
        elif name == "choke_points":
            c = o["choke_points"]; s = f"{c[0]['function'].split('.')[-1]}() sits on paths to {c[0]['endpoints_through_it']} endpoints (betweenness + pagerank)" if c else "no paths"
        elif name == "impact_radius":
            s = f"{o['downstream_functions']} functions downstream · {o.get('callers', 0)} callers · {o.get('endpoints', 0)} endpoints upstream"
    except Exception:
        s = ""
    return {"title": title, "summary": s, "phase": PHASE.get(name, "reach")}


class Agent:
    def __init__(self, graph_name: str, repo_path: str | None = None, on_event: Callable[[dict], None] | None = None):
        self.client = anthropic.Anthropic()
        self.graph_name, self.repo_path = graph_name, repo_path
        self.on_event = on_event or (lambda e: None)
        self.messages: list[dict] = []
        gh = "are configured (push + open PR)" if os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPO") else "are NOT configured: open_pull_request writes a local report instead"
        self.system = SYSTEM.format(repo=graph_name, gh=gh)
        self.bridge = None
        if TOOL_TRANSPORT == "mcp":
            self.bridge = McpBridge(graph_name, repo_path)
            self.tool_defs = self.bridge.tools            # tool list discovered from the MCP server
        else:
            self.tool_defs = TOOL_DEFS

    def close(self):
        if self.bridge:
            try:
                self.bridge.close()
            except Exception:
                pass
            self.bridge = None

    def _emit(self, **e):
        e.setdefault("t", time.time()); self.on_event(e)

    def run(self, user_text: str, max_turns: int = 16) -> dict:
        trace = Trace()
        tools = GraphTools(self.graph_name, trace, self.repo_path)
        self.messages.append({"role": "user", "content": user_text})
        final_text, usage = "", {"input": 0, "output": 0}
        for turn in range(max_turns):
            resp = self.client.beta.messages.create(
                model=MODEL, max_tokens=16000,
                system=[{"type": "text", "text": self.system, "cache_control": {"type": "ephemeral"}}],
                tools=self.tool_defs, messages=self.messages,
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": EFFORT},
                betas=["server-side-fallback-2026-07-01"], fallbacks="default",
            )
            usage["input"] += resp.usage.input_tokens; usage["output"] += resp.usage.output_tokens
            self.messages.append({"role": "assistant", "content": resp.content})
            for b in resp.content:
                if b.type == "thinking" and getattr(b, "thinking", ""):
                    self._emit(type="thinking", text=b.thinking)
                elif b.type == "text" and b.text.strip():
                    self._emit(type="text", text=b.text)
            if resp.stop_reason == "refusal":
                final_text = "The model declined this request." + (f" ({resp.stop_details.category})" if getattr(resp, "stop_details", None) else "")
                break
            if resp.stop_reason == "pause_turn":
                continue
            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if resp.stop_reason != "tool_use" or not tool_uses:
                final_text = "\n".join(b.text for b in resp.content if b.type == "text")
                if resp.stop_reason == "max_tokens":
                    final_text += "\n\n_(response truncated: max_tokens reached)_"
                break
            results = []
            for tu in tool_uses:
                args = tu.input if isinstance(tu.input, dict) else json.loads(tu.input)
                self._emit(type="tool_call", name=tu.name, input=args, via=TOOL_TRANSPORT, **describe(tu.name, args, ""))
                before = len(trace.steps)
                t0 = time.time()
                if self.bridge:
                    try:
                        env = json.loads(self.bridge.call(tu.name, args))
                    except Exception as e:
                        env = {"result": {"error": f"MCP call failed: {e}"}, "trace": [], "graph": None}
                    out = json.dumps(env.get("result"), default=str)
                    trace.steps.extend(env.get("trace") or []); trace.add_graph(env.get("graph"))
                else:
                    out = dispatch(tools, tu.name, args)
                self._emit(type="tool_result", name=tu.name, ms=round((time.time() - t0) * 1000), preview=out[:1500], result_chars=len(out), via=TOOL_TRANSPORT, input=args,
                           steps=trace.steps[before:], graph=trace.graph_dict(), **describe(tu.name, args, out))
                results.append({"type": "tool_result", "tool_use_id": tu.id, "content": out[:60000], "is_error": out.startswith('{"error"')})
            self.messages.append({"role": "user", "content": results})
        self._emit(type="final", text=final_text, usage=usage)
        return {"answer": final_text, "trace": trace.steps, "graph": trace.graph_dict(), "usage": usage, "model": MODEL, "tools_via": TOOL_TRANSPORT, "tool_count": len(self.tool_defs)}
