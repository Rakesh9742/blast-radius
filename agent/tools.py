"""Agent tools. Every graph tool is a parameterised Cypher query against FalkorDB and returns
(result_dict, graph_fragment) so the UI can highlight exactly what the agent looked at."""
from __future__ import annotations
import json, os, re, subprocess, time, pathlib, datetime
import httpx
from packaging.version import Version, InvalidVersion
from core.db import get_graph, rows

REPORTS = pathlib.Path(__file__).resolve().parent.parent / "data" / "reports"
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


class Trace:
    """Collects every Cypher query the agent ran, for the explain panel."""
    def __init__(self):
        self.steps: list[dict] = []
        self.graph = {"nodes": {}, "edges": {}}

    def add_graph(self, frag: dict | None):
        if not frag:
            return
        for n in frag.get("nodes", []):
            self.graph["nodes"].setdefault(n["id"], n)
        for e in frag.get("edges", []):
            k = f"{e['source']}|{e['type']}|{e['target']}"
            self.graph["edges"].setdefault(k, e)

    def graph_dict(self):
        return {"nodes": list(self.graph["nodes"].values()), "edges": list(self.graph["edges"].values())}


class GraphTools:
    def __init__(self, graph_name: str, trace: Trace | None = None, repo_path: str | None = None):
        self.g = get_graph(graph_name)
        self.graph_name = graph_name
        self.trace = trace or Trace()
        self.repo_path = repo_path

    # ---------- helpers ----------
    def q(self, cypher: str, params: dict | None = None, label: str = "", read_only: bool = True) -> list[dict]:
        t = time.time()
        res = (self.g.ro_query if read_only else self.g.query)(cypher, params or {})
        out = rows(res)
        self.trace.steps.append({"type": "cypher", "label": label, "query": re.sub(r"\s+", " ", cypher).strip(),
                                 "params": params or {}, "rows": len(out), "ms": round((time.time() - t) * 1000, 1)})
        return out

    @staticmethod
    def node(id_, label, name, **props):
        return {"id": id_, "label": label, "name": name, **props}

    @staticmethod
    def edge(s, t, type_, **props):
        return {"source": s, "target": t, "type": type_, **props}

    # ---------- read tools ----------
    def list_vulnerabilities(self, package: str | None = None, min_severity: str = "LOW") -> dict:
        thr = SEV_ORDER.get(min_severity.upper(), 1)
        if package:
            data = self.q("MATCH (v:Vulnerability)-[a:AFFECTS]->(p:Package {name: $pkg}) "
                          "RETURN v.id AS id, v.cve AS cve, v.severity AS severity, v.summary AS summary, a.fixed_version AS fixed_version, "
                          "p.version AS installed, v.published AS published ORDER BY v.published DESC",
                          {"pkg": package.lower()}, "vulnerabilities for package")
            data = [d for d in data if SEV_ORDER.get(d["severity"], 0) >= thr]
            frag = {"nodes": [self.node(f"pkg:{package}", "Package", package, version=(data[0]["installed"] if data else ""))] + [self.node(d["id"], "Vulnerability", d["id"], severity=d["severity"], summary=(d.get("summary") or "")[:140], fixed=d.get("fixed_version") or "") for d in data],
                    "edges": [self.edge(d["id"], f"pkg:{package}", "AFFECTS") for d in data]}
            self.trace.add_graph(frag)
            return {"package": package, "count": len(data), "vulnerabilities": data[:40]}
        data = self.q("MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package) "
                      "OPTIONAL MATCH (p)<-[:USES]-(fn:Function) "
                      "WITH p, collect(DISTINCT v) AS vs, count(DISTINCT fn) AS used_by_functions "
                      "RETURN p.name AS package, p.version AS version, p.direct AS direct_dependency, size(vs) AS vulns, "
                      "size([x IN vs WHERE x.severity IN ['CRITICAL','HIGH']]) AS high_or_critical, used_by_functions "
                      "ORDER BY high_or_critical DESC, vulns DESC", {}, "vulnerable packages overview")
        return {"vulnerable_packages": data, "note": "used_by_functions=0 means no first-party code imports it directly; check transitive_exposure."}

    def find_vulnerability(self, query: str) -> dict:
        data = self.q("MATCH (v:Vulnerability)-[a:AFFECTS]->(p:Package) WHERE v.id = $q OR v.cve = $q OR $q IN v.aliases "
                      "RETURN v.id AS id, v.cve AS cve, v.aliases AS aliases, v.severity AS severity, v.cvss AS cvss, v.summary AS summary, "
                      "v.details AS details, v.published AS published, v.references AS references, p.name AS package, p.version AS installed, a.fixed_version AS fixed_version",
                      {"q": query.strip()}, "vulnerability lookup by id")
        if not data:
            ft = "|".join(re.findall(r"[A-Za-z0-9_]+", query)) or query
            data = self.q("CALL db.idx.fulltext.queryNodes('Vulnerability', $q) YIELD node, score "
                          "MATCH (node)-[a:AFFECTS]->(p:Package) RETURN node.id AS id, node.cve AS cve, node.severity AS severity, node.summary AS summary, "
                          "p.name AS package, p.version AS installed, a.fixed_version AS fixed_version, score ORDER BY score DESC LIMIT 10",
                          {"q": ft}, "vulnerability full-text search")
        for d in data:
            self.trace.add_graph({"nodes": [self.node(d["id"], "Vulnerability", d["id"], severity=d["severity"], summary=(d.get("summary") or "")[:140], fixed=d.get("fixed_version") or ""), self.node(f"pkg:{d['package']}", "Package", d["package"], version=d.get("installed", ""))],
                                  "edges": [self.edge(d["id"], f"pkg:{d['package']}", "AFFECTS")]})
        return {"matches": data}

    def reachability(self, package: str, max_hops: int = 4) -> dict:
        package = package.lower(); max_hops = max(0, min(int(max_hops), 6))
        data = self.q(f"MATCH (p:Package {{name: $pkg}})<-[:USES]-(sink:Function) "
                      f"MATCH path = (h:Function)-[:CALLS*0..{max_hops}]->(sink) "
                      f"MATCH (h)-[:EXPOSES]->(e:Entrypoint) "
                      f"RETURN e.id AS endpoint, sink.qualname AS sink, [n IN nodes(path) | n.qualname] AS functions, "
                      f"[r IN relationships(path) | r.how] AS resolution, length(path) AS hops, e.live AS live, e.auth_required AS auth_required ORDER BY hops LIMIT 400",
                      {"pkg": package}, f"reachability: endpoints -> functions using {package}")
        sinks = self.q("MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function) RETURN sink.qualname AS qualname, sink.file AS file, sink.lineno AS line",
                       {"pkg": package}, "sink functions (direct users of package)")
        best: dict[str, dict] = {}
        for d in data:
            conf = "high" if all(h != "name-match" for h in d["resolution"]) else "medium"
            cur = best.get(d["endpoint"])
            if not cur or (d["hops"], conf == "medium") < (cur["hops"], cur["confidence"] == "medium"):
                best[d["endpoint"]] = {"endpoint": d["endpoint"], "hops": d["hops"], "confidence": conf, "path": d["functions"], "sink": d["sink"],
                                       "live": d.get("live"), "auth_required": d.get("auth_required")}
        nodes = [self.node(f"pkg:{package}", "Package", package)] + [self.node(s["qualname"], "Function", s["qualname"].split(".")[-1], file=s["file"]) for s in sinks]
        edges = [self.edge(s["qualname"], f"pkg:{package}", "USES") for s in sinks]
        for b in best.values():
            fns = b["path"]
            nodes.append(self.node(b["endpoint"], "Entrypoint", b["endpoint"]))
            edges.append(self.edge(fns[0], b["endpoint"], "EXPOSES"))
            for i, f in enumerate(fns):
                nodes.append(self.node(f, "Function", f.split(".")[-1]))
                if i + 1 < len(fns):
                    edges.append(self.edge(f, fns[i + 1], "CALLS", confidence=b["confidence"]))
        self.trace.add_graph({"nodes": nodes, "edges": edges})
        ranked = sorted(best.values(), key=lambda b: (not b.get("live"), b.get("auth_required") is not False, b["confidence"] != "high", b["hops"], b["endpoint"]))
        by_sink: dict[str, int] = {}
        for b in ranked:
            by_sink[b["sink"]] = by_sink.get(b["sink"], 0) + 1
        total_endpoints = self.q("MATCH (e:Entrypoint) RETURN count(e) AS n", {}, "total endpoints")[0]["n"]
        return {"package": package, "sink_functions": sinks, "reachable_endpoints": len(ranked), "total_endpoints": total_endpoints,
                "endpoints_by_sink": by_sink, "endpoints": ranked[:40],
                "truncated_note": f"showing 40 of {len(ranked)} endpoints; use run_cypher to list more" if len(ranked) > 40 else "",
                "confidence_note": "high = every call edge resolved statically; medium = at least one edge matched by method name only (possible false positive).",
                "live_note": "live=true means the endpoint was confirmed on the connected deployment (OpenAPI); auth_required=false means it is callable without login; auth_required=null means unknown (never assume public). On surface-only graphs, confirmed=true marks HTTP calls proven in the frontend code and confirmed=false marks route-like strings that may be client-side pages. Prioritise live + unauthenticated. live=null means no live app has been connected or the route is not deployed."}

    def transitive_exposure(self, package: str) -> dict:
        package = package.lower()
        parents = self.q("MATCH (p:Package {name: $pkg})<-[:DEPENDS_ON*1..3]-(parent:Package) "
                         "OPTIONAL MATCH (parent)<-[:USES]-(fn:Function) OPTIONAL MATCH (fn)-[:EXPOSES]->(e:Entrypoint) "
                         "RETURN DISTINCT parent.name AS parent, parent.version AS version, parent.direct AS direct_dependency, "
                         "count(DISTINCT fn) AS functions_using_parent, count(DISTINCT e) AS endpoints_directly_in_handlers ORDER BY functions_using_parent DESC",
                         {"pkg": package}, f"packages that depend on {package}")
        direct = self.q("MATCH (p:Package {name: $pkg}) OPTIONAL MATCH (p)<-[:IMPORTS]-(f:File) RETURN p.direct AS direct_dependency, p.description AS description, count(f) AS files_importing_directly",
                        {"pkg": package}, "direct import check")
        frag = {"nodes": [self.node(f"pkg:{package}", "Package", package)] + [self.node(f"pkg:{p['parent']}", "Package", p["parent"]) for p in parents],
                "edges": [self.edge(f"pkg:{p['parent']}", f"pkg:{package}", "DEPENDS_ON") for p in parents]}
        self.trace.add_graph(frag)
        return {"package": package, **(direct[0] if direct else {}), "depended_on_by": parents,
                "hint": "If a parent is a web framework (fastapi/starlette/uvicorn), every HTTP endpoint is in scope at the framework layer; narrow by the vulnerability details (e.g. multipart parsing only affects endpoints accepting uploads/forms)."}

    def who_owns(self, target: str) -> dict:
        owners = self.q("MATCH (a:Author)-[o:OWNS]->(fn:Function) WHERE fn.qualname = $t OR fn.file = $t "
                        "RETURN a.name AS name, a.email AS author_id, sum(o.lines) AS lines, round(avg(o.share) * 100) / 100 AS avg_share, max(o.last_touched) AS last_touched "
                        "ORDER BY lines DESC LIMIT 6", {"t": target}, "code ownership via git blame")
        file_ = target if "/" in target else None
        if not file_:
            r = self.q("MATCH (fn:Function {qualname: $t}) RETURN fn.file AS file", {"t": target}, "resolve function file")
            file_ = r[0]["file"] if r else None
        commits = []
        if file_:
            commits = self.q("MATCH (a:Author)-[:AUTHORED]->(c:Commit)-[:MODIFIED]->(f:File {path: $f}) "
                             "RETURN c.short AS sha, c.date AS date, a.name AS author, c.subject AS subject ORDER BY c.date DESC LIMIT 8",
                             {"f": file_}, "recent commits touching file")
        nodes = [self.node(a["author_id"], "Author", a["name"]) for a in owners]
        edges = [self.edge(a["author_id"], target, "OWNS", lines=a["lines"]) for a in owners]
        if "/" in target:
            nodes.append(self.node(target, "File", target.split("/")[-1]))
            # connect the file to the functions in it that use external packages, so ownership joins the attack path in the UI
            fns = self.q("MATCH (f:File {path: $p})-[:CONTAINS]->(fn:Function)-[:USES]->(:Package) RETURN DISTINCT fn.qualname AS q LIMIT 12", {"p": target}, "functions in file")
            for r in fns:
                nodes.append(self.node(r["q"], "Function", r["q"].split(".")[-1]))
                edges.append(self.edge(target, r["q"], "CONTAINS"))
        else:
            nodes.append(self.node(target, "Function", target.split(".")[-1]))
            if file_:
                nodes.append(self.node(file_, "File", file_.split("/")[-1])); edges.append(self.edge(file_, target, "CONTAINS"))
        self.trace.add_graph({"nodes": nodes, "edges": edges})
        return {"target": target, "file": file_, "owners": owners, "recent_commits": commits}

    def get_function(self, qualname: str) -> dict:
        info = self.q("MATCH (fn:Function {qualname: $q}) OPTIONAL MATCH (fn)-[:USES]->(p:Package) OPTIONAL MATCH (fn)-[:EXPOSES]->(e:Entrypoint) "
                      "RETURN fn.qualname AS qualname, fn.file AS file, fn.lineno AS line, fn.end_lineno AS end_line, fn.doc AS doc, fn.source AS source, "
                      "collect(DISTINCT p.name) AS packages_used, collect(DISTINCT e.id) AS exposes", {"q": qualname}, "function detail")
        callers = self.q("MATCH (c:Function)-[r:CALLS]->(fn:Function {qualname: $q}) RETURN c.qualname AS qualname, r.how AS resolution LIMIT 25", {"q": qualname}, "callers")
        callees = self.q("MATCH (fn:Function {qualname: $q})-[r:CALLS]->(c:Function) RETURN c.qualname AS qualname, r.how AS resolution LIMIT 25", {"q": qualname}, "callees")
        if info:
            self.trace.add_graph({"nodes": [self.node(qualname, "Function", qualname.split(".")[-1])] + [self.node(c["qualname"], "Function", c["qualname"].split(".")[-1]) for c in callers + callees],
                                  "edges": [self.edge(c["qualname"], qualname, "CALLS") for c in callers] + [self.edge(qualname, c["qualname"], "CALLS") for c in callees]})
        return {**(info[0] if info else {"error": f"no function {qualname}"}), "callers": callers, "callees": callees}

    def search_code(self, query: str, limit: int = 10) -> dict:
        ft = "|".join(w for w in re.findall(r"[A-Za-z0-9_]+", query)) or query
        data = self.q("CALL db.idx.fulltext.queryNodes('Function', $q) YIELD node, score RETURN node.qualname AS qualname, node.file AS file, node.lineno AS line, "
                      "left(node.doc, 160) AS doc, score ORDER BY score DESC LIMIT $lim", {"q": ft, "lim": int(limit)}, "full-text code search")
        return {"query": query, "results": data}

    def run_cypher(self, query: str) -> dict:
        if re.search(r"\b(CREATE|MERGE|DELETE|SET|REMOVE|DROP)\b", query, re.I):
            return {"error": "read-only tool: write clauses are not allowed"}
        try:
            data = self.q(query + ("" if re.search(r"\bLIMIT\b", query, re.I) else " LIMIT 50"), {}, "ad-hoc read-only Cypher")
        except Exception as e:
            return {"error": str(e)}
        return {"rows": data}

    def live_app_status(self) -> dict:
        """What the connected live deployment exposes vs what the analysed code declares (drift), plus unauthenticated live endpoints."""
        repo = self.q("MATCH (r:Repo) RETURN r.live_url AS url, r.live_version AS version, r.live_openapi AS openapi, r.live_checked AS checked LIMIT 1", {}, "live app metadata")
        if not repo or not repo[0]["url"]:
            return {"connected": False, "note": "no live deployment connected; findings are from static analysis of the code only"}
        counts = self.q("MATCH (e:Entrypoint) RETURN count(CASE WHEN e.live THEN 1 END) AS live, count(CASE WHEN e.source = 'openapi-only' THEN 1 END) AS only_live, "
                        "count(CASE WHEN e.live IS NULL AND e.router <> 'live' THEN 1 END) AS only_in_code, count(CASE WHEN e.live AND e.auth_required = false THEN 1 END) AS live_unauthenticated, count(CASE WHEN e.confirmed THEN 1 END) AS frontend_confirmed_calls, count(CASE WHEN e.confirmed = false THEN 1 END) AS frontend_route_strings_unconfirmed", {}, "live vs code counts")[0]
        unauth = self.q("MATCH (e:Entrypoint) WHERE e.live AND e.auth_required = false OPTIONAL MATCH (h:Function)-[:EXPOSES]->(e) "
                        "RETURN e.id AS endpoint, e.summary AS summary, collect(h.qualname)[0] AS handler ORDER BY e.id LIMIT 40", {}, "live unauthenticated endpoints")
        only_live = self.q("MATCH (e:Entrypoint {source: 'openapi-only'}) RETURN e.id AS endpoint, e.summary AS summary ORDER BY e.id LIMIT 40", {}, "endpoints only in the live app")
        only_code = self.q("MATCH (e:Entrypoint) WHERE e.live IS NULL AND e.router <> 'live' RETURN e.id AS endpoint ORDER BY e.id LIMIT 40", {}, "endpoints only in code")
        areas = self.q("MATCH (e:Entrypoint) WHERE e.confirmed WITH split(e.path, '/')[1] AS area, count(*) AS calls, "
                       "count(CASE WHEN e.auth_required = false THEN 1 END) AS public, count(CASE WHEN e.auth_required IS NULL THEN 1 END) AS auth_unknown, "
                       "collect({id: e.method + ' ' + e.path, auth: e.auth_required})[0..6] AS examples RETURN '/' + area AS area, calls, public, auth_unknown, examples ORDER BY calls DESC LIMIT 30",
                       {}, "confirmed frontend API calls grouped by area")
        sensitive = self.q("MATCH (e:Entrypoint) WHERE e.live AND coalesce(e.confirmed, true) AND e.auth_required IS NULL AND e.source <> 'bundle' "
                           "AND (e.path =~ '(?i).*(file|download|export|certificate|cert|report|storage|upload|invoice|pdf|backup|attachment|media|signed-url|view-url).*') "
                           "RETURN e.id AS endpoint, e.summary AS summary ORDER BY e.id LIMIT 25", {}, "unknown-auth calls on file/certificate/export paths")
        gnodes = [self.node(u["endpoint"], "Entrypoint", u["endpoint"], live=True, attn="public") for u in unauth[:12]]; gedges = []
        gnodes += [self.node(x["endpoint"], "Entrypoint", x["endpoint"], live=True, attn="unknown") for x in sensitive[:12]]
        if areas:
            for a in areas[:12]:
                gnodes.append(self.node(f"area:{a['area']}", "Package", f"{a['area']} ({a['calls']})"))
                for ex in a["examples"][:4]:
                    gnodes.append(self.node(ex["id"], "Entrypoint", ex["id"], live=True, attn="public" if ex["auth"] is False else ("unknown" if ex["auth"] is None else "")))
                    gedges.append({"source": f"area:{a['area']}", "target": ex["id"], "type": "EXPOSES"})
        self.trace.add_graph({"nodes": gnodes, "edges": gedges})
        return {"connected": True, **repo[0], **counts, "live_unauthenticated_endpoints": unauth, "only_in_live_app": only_live, "only_in_code": only_code,
                "api_areas_from_frontend": areas, "needs_attention_unknown_auth_sensitive_paths": sensitive,
                "note": "only_in_live_app = deployed routes the analysed revision does not contain (code drift or unanalysed services); only_in_code = routes in the code that the deployment does not expose"}

    def data_exposure(self, table: str | None = None, package: str | None = None) -> dict:
        """Data layer: which tables/models exist, which endpoints reach functions that touch a table, and (optionally) whether the
        code paths from a vulnerable package also touch data (advisory -> package -> function -> table)."""
        if table:
            rows_ = self.q("MATCH (t:Table) WHERE toLower(t.name) = toLower($t) OR toLower(t.model) = toLower($t) "
                           "MATCH (fn:Function)-[:TOUCHES]->(t) OPTIONAL MATCH path=(h:Function)-[:CALLS*0..4]->(fn) WHERE (h)-[:EXPOSES]->() "
                           "OPTIONAL MATCH (h)-[:EXPOSES]->(e:Entrypoint) "
                           "RETURN t.name AS table, t.kind AS kind, count(DISTINCT fn) AS functions_touching, count(DISTINCT e) AS endpoints_reaching, collect(DISTINCT e.id)[0..25] AS endpoints",
                           {"t": table}, f"endpoints reaching table {table}")
            if rows_:
                self.trace.add_graph({"nodes": [self.node(f"table:{rows_[0]['table']}", "Table", rows_[0]["table"])] + [self.node(e, "Entrypoint", e) for e in rows_[0]["endpoints"][:12]], "edges": []})
            return {"table": table, "results": rows_}
        if package:
            rows_ = self.q("MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function), path=(h:Function)-[:CALLS*0..4]->(sink), (h)-[:EXPOSES]->(e:Entrypoint) "
                           "UNWIND nodes(path) AS n MATCH (n)-[:TOUCHES]->(t:Table) "
                           "RETURN t.name AS table, count(DISTINCT e) AS endpoints_on_vulnerable_paths, collect(DISTINCT n.qualname)[0..6] AS functions ORDER BY endpoints_on_vulnerable_paths DESC",
                           {"pkg": package.lower()}, f"tables on attack paths to {package}")
            self.trace.add_graph({"nodes": [self.node(f"table:{r['table']}", "Table", r["table"]) for r in rows_], "edges": [self.edge(f, f"table:{r['table']}", "TOUCHES") for r in rows_ for f in r["functions"][:4]]})
            return {"package": package, "tables_on_attack_paths": rows_, "note": "these tables are read/written by functions on the path from a public endpoint to the vulnerable library: data at risk if the advisory is exploited"}
        rows_ = self.q("MATCH (t:Table) OPTIONAL MATCH (fn:Function)-[:TOUCHES]->(t) RETURN t.name AS table, t.kind AS kind, t.model AS model, count(fn) AS functions_touching ORDER BY functions_touching DESC LIMIT 60", {}, "tables/models")
        return {"tables": rows_}

    def probe_endpoints(self, endpoints: list[str], i_am_authorized: bool) -> dict:
        """SAFE live check against the connected deployment: HEAD/GET for read endpoints, OPTIONS for everything else; no bodies, no credentials,
        one request per endpoint. Classifies: live/needs-login/not-deployed. Refuses unless the caller confirms authorization."""
        if not i_am_authorized:
            return {"error": "refused: probing is only allowed against deployments you own or are authorized to test; call again with i_am_authorized=true"}
        repo = self.q("MATCH (r:Repo) RETURN r.live_url AS url LIMIT 1", {}, "live app url")
        base = (repo[0]["url"] if repo and repo[0]["url"] else "") or ""
        if not base:
            return {"error": "no live app connected"}
        import httpx, time as _t
        out = []
        with httpx.Client(headers={"User-Agent": "BlastRadius/0.1 (benign reachability check)"}, follow_redirects=False, timeout=15) as c:
            for ep in endpoints[:15]:
                method, _, path = ep.partition(" ")
                url = base.rstrip("/") + re.sub(r"\{[^}]*\}", "1", path)
                try:
                    r = c.request("GET" if method.upper() in ("GET", "HEAD") else "OPTIONS", url)
                    code = r.status_code
                    verdict = ("needs-login" if code in (401, 403) else "not-deployed" if code == 404 else "live-unauthenticated" if code < 400 and method.upper() == "GET" else "live" if code in (200, 204, 405, 422, 400) else f"http {code}")
                    out.append({"endpoint": ep, "probe": f"{'GET' if method.upper() in ('GET','HEAD') else 'OPTIONS'} {url}", "status": code, "verdict": verdict,
                                "server": r.headers.get("server", ""), "allow": r.headers.get("allow", "")})
                except Exception as e:
                    out.append({"endpoint": ep, "probe": url, "status": None, "verdict": f"error: {type(e).__name__}"})
                _t.sleep(0.3)
        self.trace.steps.append({"type": "external", "label": f"probed {len(out)} endpoints on {base} (benign HEAD/GET/OPTIONS)", "rows": len(out), "ms": 0})
        return {"base_url": base, "results": out, "note": "benign requests only: no payloads, no auth, one request per endpoint. 401/403 = deployed but protected; 404 = route not deployed; 2xx on GET = reachable without login."}

    # ---------- graph algorithm tools (FalkorDB algo.* procedures) ----------
    def shortest_attack_paths(self, package: str, endpoint: str | None = None, max_paths: int = 5) -> dict:
        """algo.SPpaths: shortest weighted paths from HTTP handlers to the functions that use the package."""
        package = package.lower()
        if endpoint:
            handlers = self.q("MATCH (h:Function)-[:EXPOSES]->(e:Entrypoint) WHERE e.id = $e OR e.path = $e RETURN DISTINCT h.qualname AS h, e.id AS e", {"e": endpoint}, "handler for endpoint")
        else:
            handlers = self.q(f"MATCH (p:Package {{name: $pkg}})<-[:USES]-(sink:Function), path=(h:Function)-[:CALLS*0..5]->(sink), (h)-[:EXPOSES]->(e:Entrypoint) "
                              f"RETURN DISTINCT h.qualname AS h, e.id AS e, min(length(path)) AS hops ORDER BY hops LIMIT {int(max_paths)}", {"pkg": package}, "candidate handlers (reachability)")
        out = []
        for hd in handlers:
            r = self.q("MATCH (h:Function {qualname: $h}), (p:Package {name: $pkg}) "
                       "CALL algo.SPpaths({sourceNode: h, targetNode: p, relTypes: ['CALLS','USES'], maxLen: 8, pathCount: 1}) YIELD path, pathWeight "
                       "RETURN [n IN nodes(path) | coalesce(n.qualname, n.name)] AS nodes, [r IN relationships(path) | coalesce(r.how, type(r))] AS edges, pathWeight AS weight",
                       {"h": hd["h"], "pkg": package}, f"algo.SPpaths {hd['e']} -> {package}")
            for row in r:
                conf = "high" if "name-match" not in row["edges"] else "medium"
                out.append({"endpoint": hd["e"], "hops": row["weight"], "confidence": conf, "path": row["nodes"], "edge_resolution": row["edges"]})
                nodes = [self.node(n, "Function", n.split(".")[-1]) for n in row["nodes"][:-1]] + [self.node(f"pkg:{package}", "Package", package), self.node(hd["e"], "Entrypoint", hd["e"])]
                edges = [self.edge(row["nodes"][0], hd["e"], "EXPOSES")] + [self.edge(a, b if i + 2 < len(row["nodes"]) else f"pkg:{package}", "CALLS" if i + 2 < len(row["nodes"]) else "USES", confidence=conf) for i, (a, b) in enumerate(zip(row["nodes"], row["nodes"][1:]))]
                self.trace.add_graph({"nodes": nodes, "edges": edges})
        return {"package": package, "algorithm": "algo.SPpaths (FalkorDB shortest paths, weight = hops)", "paths": out,
                "note": "each path is the minimum-hop route from a public handler to the vulnerable library; use it as the attack path in the report"}

    def choke_points(self, package: str, top: int = 8) -> dict:
        """Betweenness + PageRank over the CALLS graph, restricted to functions that sit on a path to the package: where one guard cuts off many endpoints."""
        package = package.lower()
        on_path = self.q("MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function), path=(h:Function)-[:CALLS*0..5]->(sink), (h)-[:EXPOSES]->(e:Entrypoint) "
                         "UNWIND nodes(path) AS n WITH n, collect(DISTINCT e.id) AS eps RETURN n.qualname AS fn, size(eps) AS endpoints_through_it", {"pkg": package}, "functions on attack paths")
        if not on_path:
            return {"package": package, "choke_points": [], "note": "no path from any endpoint to this package"}
        eps = {r["fn"]: r["endpoints_through_it"] for r in on_path}
        bt = {r["fn"]: r["score"] for r in self.q("CALL algo.betweenness({nodeLabels: ['Function'], relationshipTypes: ['CALLS']}) YIELD node, score WHERE node.qualname IN $fns RETURN node.qualname AS fn, score",
                                                  {"fns": list(eps)}, "algo.betweenness on CALLS graph")}
        pr = {r["fn"]: r["score"] for r in self.q("CALL algo.pageRank('Function', 'CALLS') YIELD node, score WHERE node.qualname IN $fns RETURN node.qualname AS fn, score",
                                                  {"fns": list(eps)}, "algo.pageRank on CALLS graph")}
        ranked = sorted(eps, key=lambda f: (-eps[f], -bt.get(f, 0), -pr.get(f, 0)))[:int(top)]
        res = [{"function": f, "endpoints_through_it": eps[f], "betweenness": round(bt.get(f, 0), 2), "pagerank": round(pr.get(f, 0), 5)} for f in ranked]
        self.trace.add_graph({"nodes": [self.node(f, "Function", f.split(".")[-1], choke=True) for f in ranked], "edges": []})
        return {"package": package, "algorithms": "algo.betweenness + algo.pageRank (FalkorDB), filtered to functions on attack paths", "choke_points": res,
                "note": "the top entry is where a single input validation or allow-list protects the most endpoints at once"}

    def impact_radius(self, function: str, depth: int = 3) -> dict:
        """algo.BFS outward (what this function can reach) plus incoming callers: the blast radius if this function is compromised or changed."""
        reach = self.q("MATCH (f:Function {qualname: $f}) CALL algo.BFS(f, $d, 'CALLS') YIELD nodes RETURN [n IN nodes | n.qualname] AS reached", {"f": function, "d": int(depth)}, "algo.BFS outward over CALLS")
        callers = self.q("MATCH (c:Function)-[:CALLS*1..3]->(f:Function {qualname: $f}) OPTIONAL MATCH (c)-[:EXPOSES]->(e:Entrypoint) "
                         "RETURN count(DISTINCT c) AS callers, count(DISTINCT e) AS endpoints, collect(DISTINCT e.id)[0..15] AS sample_endpoints", {"f": function}, "incoming callers up to 3 hops")
        pk = self.q("MATCH (f:Function {qualname: $f}) CALL algo.BFS(f, $d, 'CALLS') YIELD nodes UNWIND nodes AS n MATCH (n)-[:USES]->(p:Package) "
                    "OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS]->(p) RETURN p.name AS package, count(DISTINCT v) AS advisories ORDER BY advisories DESC", {"f": function, "d": int(depth)}, "packages reachable downstream")
        reached = reach[0]["reached"] if reach else []
        return {"function": function, "algorithm": "algo.BFS (FalkorDB)", "downstream_functions": len(reached), "downstream_sample": reached[:20],
                "downstream_packages": pk, **(callers[0] if callers else {})}

    # ---------- action tools ----------
    def plan_fix(self, package: str) -> dict:
        package = package.lower()
        data = self.q("MATCH (v:Vulnerability)-[a:AFFECTS]->(p:Package {name: $pkg}) RETURN p.version AS installed, a.fixed_version AS fixed, v.id AS id, v.severity AS severity",
                      {"pkg": package}, "fixed versions for all vulnerabilities of package")
        if not data:
            return {"error": f"no vulnerabilities recorded for {package}"}
        fixes = []
        for d in data:
            try:
                if d["fixed"]:
                    fixes.append(Version(d["fixed"]))
            except InvalidVersion:
                pass
        target = str(max(fixes)) if fixes else None
        unfixed = [d["id"] for d in data if not d["fixed"]]
        latest = self._pypi_latest(package)
        return {"package": package, "installed": data[0]["installed"], "minimum_safe_version": target, "latest_on_pypi": latest,
                "vulnerabilities_resolved": len(data) - len(unfixed), "vulnerabilities_without_fix": unfixed,
                "constraint_suggestion": f'{package} = "^{target}"' if target else None}

    def _pypi_latest(self, package: str) -> str | None:
        try:
            r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=15)
            return r.json()["info"]["version"] if r.status_code == 200 else None
        except Exception:
            return None

    def verify_fix(self, package: str, version: str) -> dict:
        """Ask OSV whether the proposed version still has known vulnerabilities."""
        r = httpx.post("https://api.osv.dev/v1/query", json={"package": {"name": package.lower(), "ecosystem": "PyPI"}, "version": version}, timeout=60)
        vulns = r.json().get("vulns", []) if r.status_code == 200 else []
        self.trace.steps.append({"type": "external", "label": f"OSV check {package}=={version}", "rows": len(vulns), "ms": 0})
        return {"package": package, "version": version, "known_vulnerabilities": [{"id": v["id"], "summary": v.get("summary", "")[:120]} for v in vulns],
                "clean": len(vulns) == 0}

    def apply_dependency_fix(self, package: str, version: str, vulnerability_ids: list[str] | None = None) -> dict:
        """Create a branch in the analysed repo, bump the package constraint wherever it is pinned (pyproject poetry or PEP 621 deps,
        requirements*.txt, requirements/ folder), commit. Returns the diff."""
        if not self.repo_path:
            return {"error": "repo path not configured"}
        repo = pathlib.Path(self.repo_path)
        pkg = package.lower()
        branch = f"blast-radius/bump-{pkg}-{version}"
        git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
        changed: list[str] = []
        skip = {".git", "node_modules", ".venv", "venv"}
        name_re = re.escape(package).replace("\\-", "[-_]")
        # 1) pyproject.toml files: poetry table entries and PEP 621 dependency strings
        for py in sorted(repo.rglob("pyproject.toml"), key=lambda p: len(p.parts)):
            if set(py.parts) & skip:
                continue
            txt = py.read_text(); new = txt
            new = re.sub(rf'(?im)^({name_re}\s*=\s*)"[^"]*"', rf'\g<1>"^{version}"', new)
            new = re.sub(rf'(?im)^({name_re}\s*=\s*\{{[^}}]*?version\s*=\s*)"[^"]*"', rf'\g<1>"^{version}"', new)
            new = re.sub(rf'(?im)"({name_re})(\[[^\]]*\])?\s*(?:[<>=!~^][^"]*)?"', rf'"\g<1>\g<2>>={version}"', new)
            if new != txt:
                py.write_text(new); changed.append(str(py.relative_to(repo)))
        # 1b) package.json (npm): "pkg": "^1.2.3" in dependencies / devDependencies
        for pj in sorted(repo.rglob("package.json"), key=lambda p: len(p.parts)):
            if set(pj.parts) & skip:
                continue
            txt = pj.read_text(errors="ignore")
            new = re.sub(rf'(?m)^(\s*"{re.escape(package)}"\s*:\s*)"[^"]*"', rf'\g<1>"^{version}"', txt)
            if new != txt:
                pj.write_text(new); changed.append(str(pj.relative_to(repo)))
        # 2) pinned requirements files
        for rq in sorted(repo.rglob("*.txt")):
            if set(rq.parts) & skip or not (rq.name.startswith("requirements") or rq.parent.name == "requirements"):
                continue
            txt = rq.read_text(errors="ignore")
            new = re.sub(rf'(?im)^({name_re})(\[[^\]]*\])?\s*==\s*[^\s;#\\]+', rf'\g<1>\g<2>=={version}', txt)
            if new != txt:
                rq.write_text(new); changed.append(str(rq.relative_to(repo)))
        # 1c) npm transitive dependency: pin it through package.json "overrides" and refresh the lockfile
        root_pj, lock = repo / "package.json", repo / "package-lock.json"
        if not changed and root_pj.exists() and lock.exists() and re.search(rf'"node_modules/(?:[^"]+/)?{re.escape(package)}"', lock.read_text(errors="ignore")):
            import json as _json
            data = _json.loads(root_pj.read_text())
            data.setdefault("overrides", {})[package] = f"^{version}"
            root_pj.write_text(_json.dumps(data, indent=2) + "\n")
            r = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=str(repo), capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                git("checkout", "-q", "--", "package.json")
                return {"error": "npm could not refresh package-lock.json for the override", "stderr": r.stderr[-400:]}
            changed += ["package.json", "package-lock.json"]
        if not changed:
            already = any(re.search(rf'(?im)^{name_re}\b.*{re.escape(version)}', (f.read_text(errors="ignore"))) for f in list(repo.rglob("pyproject.toml")) + [q for q in repo.rglob("*.txt") if q.name.startswith("requirements") or q.parent.name == "requirements"] if not (set(f.parts) & skip))
            if already:
                return {"status": "already at version", "package": package, "version": version, "note": "the working tree already pins this version (a previous fix branch may be checked out)"}
            where = "package.json (and no npm lockfile to add an override to)" if root_pj.exists() else "pyproject.toml or any requirements file"
            return {"error": f"{package} is not pinned directly in {where}; it is transitive.",
                    "suggestion": f"bump the parent package that depends on it, or add an explicit pin `{package}>={version}` to force the resolver"}
        git("checkout", "-q", "-B", branch)
        diff = git("diff").stdout
        ids = ", ".join(vulnerability_ids or [])
        msg = f"build(deps): bump {package} to {version}\n\nResolves {ids or 'known vulnerabilities'} reported by OSV.\n\nGenerated by Blast Radius (FalkorDB graph triage)."
        git("add", *changed); git("-c", "user.name=Blast Radius", "-c", "user.email=blast-radius@example.com", "commit", "-q", "-m", msg)
        sha = git("rev-parse", "--short", "HEAD").stdout.strip()
        self.trace.steps.append({"type": "action", "label": f"git branch {branch} @ {sha} ({', '.join(changed)})", "rows": 1, "ms": 0})
        note = "" if "package-lock.json" in changed else (("package-lock.json must be regenerated in CI (`npm install`); this change updates the declared range." if any(f.endswith("package.json") for f in changed))
                else "poetry.lock / uv.lock must be regenerated in CI (`poetry lock` / `uv lock`); this change updates the declared constraint." if any(f.endswith("pyproject.toml") for f in changed) else "pinned requirements updated directly.")
        return {"branch": branch, "commit": sha, "files_changed": changed, "diff": diff, "lockfile_note": note}

    def open_pull_request(self, title: str, body: str) -> dict:
        """Push the current fix branch to GITHUB_REPO (a fork) and open a PR. Falls back to a local report when not configured."""
        token, repo_slug = os.getenv("GITHUB_TOKEN"), os.getenv("GITHUB_REPO")
        if not (token and repo_slug and self.repo_path):
            return self.write_triage_report(title, body)
        try:   # when the analysed repo is the owner's own GitHub repo, open the PR there instead of the configured fork
            own = self.q("MATCH (r:Repo) RETURN r.url AS url LIMIT 1", {}, "repo url")
            m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", (own[0]["url"] or "") if own else "")
            if m and m.group(1).lower() == repo_slug.split("/")[0].lower():
                repo_slug = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
        except Exception:
            pass
        git = lambda *a: subprocess.run(["git", "-C", self.repo_path, *a], capture_output=True, text=True)
        branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        base = os.getenv("GITHUB_BASE_BRANCH", "blast-radius/base")
        url = f"https://x-access-token:{token}@github.com/{repo_slug}.git"
        git("push", "-q", "-f", url, f"{branch}~1:refs/heads/{base}")
        push = git("push", "-q", "-f", url, f"{branch}:refs/heads/{branch}")
        if push.returncode != 0:
            return {"error": "git push failed", "stderr": push.stderr.replace(token, "***")[-500:]}
        r = httpx.post(f"https://api.github.com/repos/{repo_slug}/pulls", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                       json={"title": title, "body": body, "head": branch, "base": base}, timeout=30)
        if r.status_code == 422 and "already exists" in r.text:
            existing = httpx.get(f"https://api.github.com/repos/{repo_slug}/pulls", params={"head": f"{repo_slug.split('/')[0]}:{branch}", "state": "open"},
                                 headers={"Authorization": f"Bearer {token}"}, timeout=30).json()
            return {"pull_request": existing[0]["html_url"] if existing else None, "status": "already open"}
        if r.status_code >= 300:
            return {"error": f"GitHub API {r.status_code}", "detail": r.text[:300]}
        self.trace.steps.append({"type": "action", "label": f"opened PR {r.json()['html_url']}", "rows": 1, "ms": 0})
        return {"pull_request": r.json()["html_url"], "status": "opened"}

    def write_triage_report(self, title: str, body: str) -> dict:
        REPORTS.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60] or "report"
        path = REPORTS / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-{slug}.md"
        path.write_text(f"# {title}\n\n{body}\n")
        self.trace.steps.append({"type": "action", "label": f"wrote {path.name}", "rows": 1, "ms": 0})
        return {"report_path": str(path), "status": "written"}

    def record_triage_decision(self, vulnerability_ids: list[str], status: str, reason: str) -> dict:
        """Persist a decision for one or many advisories on the graph so future sessions and teammates see it."""
        status = status.upper()
        if status not in {"EXPLOITABLE", "NOT_REACHABLE", "MITIGATED", "NEEDS_REVIEW", "FIX_PROPOSED"}:
            return {"error": "status must be one of EXPLOITABLE, NOT_REACHABLE, MITIGATED, NEEDS_REVIEW, FIX_PROPOSED"}
        at = datetime.datetime.now().isoformat(timespec="seconds")
        data = self.q("UNWIND $ids AS id MATCH (v:Vulnerability {id: id}) MERGE (v)-[:TRIAGED]->(d:Decision {vuln: id}) "
                      "SET d.status = $status, d.reason = $reason, d.decided_at = $at, d.by = 'blast-radius-agent' RETURN v.id AS id",
                      {"ids": vulnerability_ids, "status": status, "reason": reason[:500], "at": at}, f"record triage decision ({len(vulnerability_ids)} advisories)", read_only=False)
        done = [d["id"] for d in data]
        self.trace.add_graph({"nodes": [self.node(i, "Vulnerability", i) for i in done] + [self.node(f"decision:{i}", "Decision", status) for i in done],
                              "edges": [self.edge(i, f"decision:{i}", "TRIAGED") for i in done]})
        return {"recorded": done, "not_found": sorted(set(vulnerability_ids) - set(done)), "status": status}

    def past_decisions(self, package: str | None = None) -> dict:
        data = self.q("MATCH (v:Vulnerability)-[:TRIAGED]->(d:Decision) MATCH (v)-[:AFFECTS]->(p:Package) WHERE $pkg = '' OR p.name = $pkg "
                      "RETURN v.id AS id, p.name AS package, d.status AS status, d.reason AS reason, d.decided_at AS decided_at ORDER BY d.decided_at DESC LIMIT 25",
                      {"pkg": (package or "").lower()}, "previous triage decisions")
        return {"decisions": data}


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


TOOL_DEFS = [
    {"name": "list_vulnerabilities", "description": "Overview of vulnerable packages in the repo (with how many first-party functions use each), or all vulnerabilities for one package.",
     "input_schema": _schema({"package": {"type": ["string", "null"], "description": "PyPI package name, or null for the overview"},
                              "min_severity": {"type": "string", "enum": ["LOW", "MODERATE", "HIGH", "CRITICAL"]}}, ["package", "min_severity"])},
    {"name": "find_vulnerability", "description": "Look up a vulnerability by GHSA/CVE/PYSEC id or alias, or full-text search its summary. Returns details, affected package and fixed version.",
     "input_schema": _schema({"query": {"type": "string"}}, ["query"])},
    {"name": "reachability", "description": "Core multi-hop query: find HTTP endpoints from which code using the given package is reachable (Entrypoint <- handler -CALLS*-> function -USES-> Package). Returns ranked endpoints with the call path and a confidence.",
     "input_schema": _schema({"package": {"type": "string"}, "max_hops": {"type": "integer"}}, ["package", "max_hops"])},
    {"name": "transitive_exposure", "description": "For a package not imported directly, find which packages depend on it (DEPENDS_ON chain) and how much first-party code uses those parents.",
     "input_schema": _schema({"package": {"type": "string"}}, ["package"])},
    {"name": "who_owns", "description": "Ownership for a function qualname or file path: git-blame owners (lines, share, last touched) and recent commits.",
     "input_schema": _schema({"target": {"type": "string", "description": "function qualname like mealie.pkgs.img.minify.PillowMinifier.minify, or file path"}}, ["target"])},
    {"name": "get_function", "description": "Source code, docstring, packages used, callers and callees of one function.",
     "input_schema": _schema({"qualname": {"type": "string"}}, ["qualname"])},
    {"name": "search_code", "description": "Full-text search over function names, docstrings and source.",
     "input_schema": _schema({"query": {"type": "string"}, "limit": {"type": "integer"}}, ["query", "limit"])},
    {"name": "run_cypher", "description": "Escape hatch: run a read-only openCypher query against the code graph. Schema: (Repo)-[:CONTAINS]->(File)-[:CONTAINS]->(Function|Class); (Class)-[:HAS_METHOD]->(Function); (Function)-[:CALLS {how}]->(Function); (Function)-[:EXPOSES]->(Entrypoint {id, method, path}); (Function)-[:USES]->(Package); (File)-[:IMPORTS]->(Package); (Package)-[:DEPENDS_ON]->(Package); (Repo)-[:DEPENDS_ON {direct}]->(Package); (Vulnerability {id, cve, severity, summary, fixed_version})-[:AFFECTS {installed_version, fixed_version}]->(Package); (Author)-[:OWNS {lines, share, last_touched}]->(Function); (Author)-[:AUTHORED]->(Commit)-[:MODIFIED]->(File); (Vulnerability)-[:TRIAGED]->(Decision).",
     "input_schema": _schema({"query": {"type": "string"}}, ["query"])},
    {"name": "data_exposure", "description": "DATA LAYER: list tables/models; or endpoints that reach functions touching a table; or, for a package, which tables sit on the attack paths to it (data at risk). Use when asked about data impact or which data an exploit could reach.",
     "input_schema": _schema({"table": {"type": ["string", "null"]}, "package": {"type": ["string", "null"]}}, ["table", "package"])},
    {"name": "probe_endpoints", "description": "SAFE LIVE CHECK: benign HEAD/GET/OPTIONS requests (no payloads, no credentials) to up to 15 endpoints on the connected deployment to confirm which are deployed and which need login. Only with i_am_authorized=true, i.e. the user owns or is authorized to test the deployment.",
     "input_schema": _schema({"endpoints": {"type": "array", "items": {"type": "string"}}, "i_am_authorized": {"type": "boolean"}}, ["endpoints", "i_am_authorized"])},
    {"name": "live_app_status", "description": "Live deployment vs code: which endpoints are confirmed deployed (OpenAPI), which are callable without authentication, which exist only in the live app or only in the code (drift). Call it when a live app is connected to prioritise findings.",
     "input_schema": _schema({}, [])},
    {"name": "shortest_attack_paths", "description": "GRAPH ALGORITHM (algo.SPpaths): minimum-hop paths from public HTTP handlers to the functions that use a package. Use it to produce the attack path for the report; optionally restrict to one endpoint.",
     "input_schema": _schema({"package": {"type": "string"}, "endpoint": {"type": ["string", "null"]}, "max_paths": {"type": "integer"}}, ["package", "endpoint", "max_paths"])},
    {"name": "choke_points", "description": "GRAPH ALGORITHM (algo.betweenness + algo.pageRank): functions on the attack paths to a package ranked by how many endpoints flow through them. Tells you where one validation/allow-list protects the most endpoints.",
     "input_schema": _schema({"package": {"type": "string"}, "top": {"type": "integer"}}, ["package", "top"])},
    {"name": "impact_radius", "description": "GRAPH ALGORITHM (algo.BFS): blast radius of one function: everything it can reach downstream (functions, packages with advisories) and how many callers/endpoints reach it.",
     "input_schema": _schema({"function": {"type": "string"}, "depth": {"type": "integer"}}, ["function", "depth"])},
    {"name": "past_decisions", "description": "Previous triage decisions recorded on the graph, optionally filtered by package.",
     "input_schema": _schema({"package": {"type": ["string", "null"]}}, ["package"])},
    {"name": "plan_fix", "description": "Compute the minimum version of a package that resolves all its known vulnerabilities, plus the latest on PyPI.",
     "input_schema": _schema({"package": {"type": "string"}}, ["package"])},
    {"name": "verify_fix", "description": "Check with OSV whether a proposed package version still has known vulnerabilities. Use after plan_fix and before applying.",
     "input_schema": _schema({"package": {"type": "string"}, "version": {"type": "string"}}, ["package", "version"])},
    {"name": "apply_dependency_fix", "description": "ACTION: create a git branch in the analysed repo and bump the package: pyproject.toml / requirements for Python, package.json for npm (transitive npm packages are pinned via an 'overrides' entry and the lockfile is refreshed). Commits and returns the diff.",
     "input_schema": _schema({"package": {"type": "string"}, "version": {"type": "string"}, "vulnerability_ids": {"type": "array", "items": {"type": "string"}}}, ["package", "version", "vulnerability_ids"])},
    {"name": "open_pull_request", "description": "ACTION: push the fix branch and open a pull request on the configured GitHub fork. If GitHub is not configured it writes a triage report file instead. Body should be markdown with: impact, affected endpoints, attack path, owners, fix.",
     "input_schema": _schema({"title": {"type": "string"}, "body": {"type": "string"}}, ["title", "body"])},
    {"name": "record_triage_decision", "description": "ACTION: persist a triage verdict on the graph for one or many advisories at once (EXPLOITABLE, NOT_REACHABLE, MITIGATED, NEEDS_REVIEW, FIX_PROPOSED) with a one-paragraph reason. Record every advisory you assessed, not just one.",
     "input_schema": _schema({"vulnerability_ids": {"type": "array", "items": {"type": "string"}}, "status": {"type": "string"}, "reason": {"type": "string"}}, ["vulnerability_ids", "status", "reason"])},
]
for t in TOOL_DEFS:
    t["strict"] = True


def dispatch(tools: GraphTools, name: str, args: dict) -> str:
    fn = getattr(tools, name, None)
    if not fn:
        return json.dumps({"error": f"unknown tool {name}"})
    try:
        return json.dumps(fn(**args), default=str)
    except Exception as e:
        return json.dumps({"error": f"{type(e).__name__}: {e}"})
