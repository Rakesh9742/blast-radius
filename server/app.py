"""FastAPI server: serves the UI, streams agent events over SSE, exposes graph endpoints."""
from __future__ import annotations
import asyncio, json, os, pathlib, queue, threading, time, uuid, re, subprocess, sys
from urllib.parse import urlparse, unquote
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, UploadFile, File, Form
import shutil, zipfile, tempfile
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, HTMLResponse
from server.report import render as render_report
from server.replay import render as render_replay
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from core.db import get_graph, rows, get_db
from agent.loop import Agent, MODEL
from ingest.discover import discover, apply_to_graph, norm_path

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE = {"graph": os.getenv("GRAPH_NAME", "mealie"), "repo": os.getenv("REPO_PATH", str(ROOT / "data" / "repos" / "mealie"))}


class _G:  # keep existing code reading _graph() / REPO as module globals working, but make them switchable
    pass


def _graph():
    return STATE["graph"]


def _repo():
    return STATE["repo"]
app = FastAPI(title="Blast Radius")
SESSIONS: dict[str, Agent] = {}
RUNS: dict[str, dict] = {}


def load_run(run_id: str) -> dict | None:
    if run_id in RUNS:
        return RUNS[run_id]
    f = ROOT / "data" / "reports" / f"run-{run_id}.json"
    if f.exists() and run_id.isalnum():
        RUNS[run_id] = json.loads(f.read_text())
        return RUNS[run_id]
    return None


class Ask(BaseModel):
    prompt: str
    session: str = "default"
    reset: bool = False


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/favicon.ico")
def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/api/health")
def health():
    g = get_graph(_graph())
    counts = rows(g.ro_query("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC"))
    live = rows(g.ro_query("MATCH (r:Repo) RETURN r.live_url AS url, r.live_version AS version, r.live_checked AS checked, r.live_framework AS framework, r.kind AS kind LIMIT 1"))
    live_counts = rows(g.ro_query("MATCH (e:Entrypoint) RETURN count(CASE WHEN e.live THEN 1 END) AS live, count(CASE WHEN e.source = 'openapi-only' THEN 1 END) AS only_live, "
                                  "count(CASE WHEN e.live IS NULL AND e.router <> 'live' THEN 1 END) AS only_code, count(CASE WHEN e.live AND e.auth_required = false THEN 1 END) AS live_unauth, count(CASE WHEN e.confirmed THEN 1 END) AS confirmed, count(CASE WHEN e.confirmed = false THEN 1 END) AS route_strings, count(CASE WHEN e.live AND coalesce(e.confirmed, true) AND e.auth_required IS NULL AND e.source <> 'bundle' THEN 1 END) AS auth_unknown"))[0]
    areas = rows(g.ro_query("MATCH (e:Entrypoint) WHERE e.live AND coalesce(e.confirmed, true) AND e.source <> 'bundle' WITH split(e.path, '/')[1] AS area, count(*) AS calls, "
                            "count(CASE WHEN e.auth_required = false THEN 1 END) AS public, count(CASE WHEN e.auth_required IS NULL THEN 1 END) AS unknown, "
                            "count(CASE WHEN e.method IN ['POST','PUT','PATCH','DELETE'] THEN 1 END) AS writes RETURN '/' + area AS area, calls, public, unknown, writes ORDER BY calls DESC LIMIT 8")) if live and live[0]["url"] else []
    return {"graph": _graph(), "model": MODEL, "counts": counts, "tools_via": os.getenv("BLAST_TOOLS", "mcp"), "live": ({**live[0], **live_counts, "areas": areas} if live and live[0]["url"] else None), "anthropic_key": bool(os.getenv("ANTHROPIC_API_KEY")),
            "github": bool(os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPO"))}


@app.get("/api/overview")
def overview():
    g = get_graph(_graph())
    pk = rows(g.ro_query("MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package) OPTIONAL MATCH (p)<-[:USES]-(fn:Function) "
                         "WITH p, collect(DISTINCT v) AS vs, count(DISTINCT fn) AS used "
                         "RETURN p.name AS package, p.version AS version, p.direct AS direct, size(vs) AS vulns, "
                         "size([x IN vs WHERE x.severity IN ['CRITICAL','HIGH']]) AS high, used ORDER BY used DESC, high DESC LIMIT 25"))
    decisions = rows(g.ro_query("MATCH (v:Vulnerability)-[:TRIAGED]->(d:Decision) MATCH (v)-[:AFFECTS]->(p:Package) "
                                "RETURN v.id AS id, p.name AS package, d.status AS status, d.decided_at AS at ORDER BY d.decided_at DESC LIMIT 10"))
    return {"packages": pk, "decisions": decisions}


_FUNNEL: dict = {}


@app.get("/api/funnel")
def funnel(refresh: bool = False):
    """Scanner view vs graph view: advisories -> in packages first-party code uses -> reachable from an endpoint -> high/critical reachable."""
    cache = _FUNNEL.setdefault(_graph(), {})
    if cache and not refresh:
        cache["triaged"] = rows(get_graph(_graph()).ro_query("MATCH (d:Decision) RETURN count(d) AS n"))[0]["n"]
        return cache
    g = get_graph(_graph())
    total = rows(g.ro_query("MATCH (v:Vulnerability) RETURN count(v) AS n"))[0]["n"]
    used = rows(g.ro_query("MATCH (v:Vulnerability)-[:AFFECTS]->(:Package)<-[:USES]-(:Function) RETURN count(DISTINCT v) AS n"))[0]["n"]
    used_pkgs = [r["p"] for r in rows(g.ro_query("MATCH (:Vulnerability)-[:AFFECTS]->(p:Package)<-[:USES]-(:Function) RETURN DISTINCT p.name AS p"))]
    reach_pkgs, exposed_eps = [], set()
    for pk in used_pkgs:  # one cheap path query per package (~50 ms each) instead of one giant one
        eps = rows(g.ro_query("MATCH (p:Package {name: $pk})<-[:USES]-(f:Function), (h:Function)-[:CALLS*0..4]->(f), (h)-[:EXPOSES]->(e:Entrypoint) RETURN DISTINCT e.id AS e", {"pk": pk}, timeout=5000))
        if eps:
            reach_pkgs.append(pk); exposed_eps.update(r["e"] for r in eps)
    reach = rows(g.ro_query("MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package) WHERE p.name IN $pk RETURN count(DISTINCT v) AS n, "
                            "count(DISTINCT CASE WHEN v.severity IN ['HIGH','CRITICAL'] THEN v END) AS hi", {"pk": reach_pkgs}))[0]
    endpoints = rows(g.ro_query("MATCH (e:Entrypoint) RETURN count(e) AS n"))[0]["n"]
    exposed = len(exposed_eps)
    decisions = rows(g.ro_query("MATCH (d:Decision) RETURN count(d) AS n"))[0]["n"]
    cache.update({"triaged": decisions, "advisories": total, "in_used_packages": used, "reachable": reach["n"], "reachable_high": reach["hi"],
                    "packages_reachable": len(reach_pkgs), "endpoints": endpoints, "endpoints_exposed": exposed})
    return cache


class AnalyzeReq(BaseModel):
    url: str
    ref: str = ""
    live_url: str = ""


class DiscoverReq(BaseModel):
    url: str


@app.post("/api/discover")
def discover_live(body: DiscoverReq):
    """Connect a live deployment: pull its OpenAPI/GraphQL/frontend API surface into the current graph and compute drift vs the code."""
    u = body.url.strip()
    if not re.match(r"^https?://", u):
        return JSONResponse({"error": "give a full URL like https://demo.mealie.io"}, status_code=400)
    host = (urlparse(u).hostname or "").lower()
    if host in ("github.com", "www.github.com", "gitlab.com", "bitbucket.org"):
        return JSONResponse({"error": f"{host} is a code-hosting site, not a running app: analysing it as a repository instead.", "suggest_analyze": True, "url": u}, status_code=409)
    cur = rows(get_graph(_graph()).ro_query("MATCH (r:Repo) RETURN r.kind AS kind, r.live_url AS live LIMIT 1"))
    if cur and cur[0]["kind"] == "live-only" and (urlparse(cur[0]["live"] or "").hostname or "").lower() != host:
        return JSONResponse({"error": f"'{_graph()}' is the surface graph of another host: building a separate surface graph for {host}.", "suggest_analyze": True, "url": u}, status_code=409)
    try:
        d = discover(u)
    except Exception as e:
        return JSONResponse({"error": f"discovery failed: {e}"}, status_code=502)
    if not d["endpoints"] and not d["graphql"] and not d["bundle_paths"]:
        dg = d.get("diag", {})
        why = (f"the site blocked or challenged the request (HTTP {dg.get('page_status')})" if dg.get("looks_blocked") else
               f"could not fetch the page ({dg.get('page_error')})" if dg.get("page_error") else
               f"page loaded (HTTP {dg.get('page_status')}, {dg.get('page_bytes', 0):,} bytes, {dg.get('scripts_downloaded', 0)} scripts) but no OpenAPI/Swagger document was found at the usual paths, GraphQL introspection is off, and the {dg.get('framework', 'unknown')} bundles ({', '.join(dg.get('bundles', [])[:4]) or 'none'}{'; skipped as too large: ' + ', '.join(dg['skipped_too_large']) if dg.get('skipped_too_large') else ''}) contain no API calls"
               + (" (the LLM pass also found nothing)" if not d.get("llm", {}).get("error") else f" (LLM pass error: {d['llm']['error']})"))
        print(f"[discover] {u} -> nothing found: {why}", flush=True)
        return JSONResponse({"error": f"No API surface found at {u}: {why}. If the API lives on another host (e.g. api.example.com) or behind a login, give that URL, or analyse the source repo instead.", "diag": dg}, status_code=404)
    print(f"[discover] {u} -> {len(d['endpoints'])} openapi, {len(d['bundle_paths'])} bundle paths, llm {d.get('llm', {}).get('endpoints_found', 0)}", flush=True)
    code_paths = {norm_path(r["path"]) for r in rows(get_graph(_graph()).ro_query("MATCH (e:Entrypoint) WHERE coalesce(e.router, '') <> 'live' RETURN e.path AS path"))}
    site_paths = {norm_path(e["path"]) for e in d["endpoints"]} | {norm_path(b["path"]) for b in d["bundle_paths"]}
    if code_paths and site_paths and not (code_paths & site_paths):
        host = urlparse(u).hostname or u
        return JSONResponse({"error": f"{host} does not look like the live deployment of '{_graph()}': none of its {len(site_paths)} paths match the {len(code_paths)} endpoints in this code graph. Building a separate surface graph for it instead.",
                             "suggest_analyze": True, "url": u, "framework": d.get("diag", {}).get("framework", "unknown")}, status_code=409)
    summary = apply_to_graph(_graph(), d)
    _FUNNEL.pop(_graph(), None)
    for a in SESSIONS.values():
        a.close()
    SESSIONS.clear()
    return {"url": u, **summary, "seconds": d["seconds"]}


@app.get("/api/graphs")
def graphs():
    """All analysed repos (one FalkorDB graph each) with headline counts."""
    db = get_db(); out = []
    for name in sorted(db.list_graphs()):
        try:
            g = db.select_graph(name)
            r = rows(g.ro_query("OPTIONAL MATCH (f:Function) WITH count(f) AS fns OPTIONAL MATCH (e:Entrypoint) WITH fns, count(e) AS eps "
                                "OPTIONAL MATCH (v:Vulnerability) WITH fns, eps, count(v) AS vulns OPTIONAL MATCH (r:Repo) RETURN fns, eps, vulns, r.url AS url, r.tag AS tag, r.dependency_source AS deps, r.kind AS kind, r.live_framework AS framework LIMIT 1"))
            if r and (r[0]["fns"] or r[0]["eps"]):
                out.append({"name": name, **r[0], "current": name == _graph()})
        except Exception:
            pass
    return {"graphs": out, "current": _graph()}


@app.post("/api/graph/select")
def select_graph(body: dict):
    name = body.get("name", "")
    if name not in get_db().list_graphs():
        return JSONResponse({"error": "unknown graph"}, status_code=404)
    STATE["graph"] = name
    r = rows(get_graph(name).ro_query("MATCH (r:Repo) RETURN r.path AS path LIMIT 1"))
    STATE["repo"] = r[0]["path"] if r and r[0]["path"] else ""   # surface-only graphs have no checkout: never inherit another repo's working copy
    for a in SESSIONS.values():
        a.close()
    SESSIONS.clear()
    return {"current": name, "repo": STATE["repo"]}


def _ingest_stream(dest: pathlib.Path, graph_name: str, url: str, pre_msgs: list[str] | None = None, live_url: str = "", source_dirs: str = ""):
    """SSE generator: run ingest.run as a subprocess and stream stage lines; switch the console to the new graph when done."""
    q: queue.Queue = queue.Queue()

    def say(stage, msg, **extra):
        q.put({"type": "progress", "stage": stage, "msg": msg, "t": time.time(), **extra})

    def work():
        t0 = time.time()
        try:
            for m_ in pre_msgs or []:
                say("clone", m_)
            say("parse", "parsing code: files, functions, calls, routes, dependency injection, models …")
            proc = subprocess.Popen([sys.executable, "-m", "ingest.run", "--repo", str(dest), "--graph", graph_name, "--url", url] + (["--source-dirs", source_dirs] if source_dirs else []),
                                    cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            stages = {"1/4": "parse", "2/4": "deps", "3/4": "git", "4/4": "load"}
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                st = next((v for k, v in stages.items() if line.startswith(k)), None)
                if st:
                    say(st, {"parse": "parsing code …", "deps": "reading lockfile and asking OSV.dev for advisories …", "git": "git history and blame for ownership …", "load": "loading the graph into FalkorDB …"}[st])
                elif line.startswith("    ") or line.startswith("done"):
                    say("detail", line.strip())
            proc.wait()
            if proc.returncode != 0:
                raise RuntimeError("ingestion failed, see server log")
            STATE["graph"], STATE["repo"] = graph_name, str(dest)
            for a in SESSIONS.values():
                a.close()
            SESSIONS.clear(); _FUNNEL.pop(graph_name, None)
            host = (urlparse(live_url).hostname or "").lower() if live_url else ""
            if live_url and host in ("github.com", "www.github.com", "gitlab.com", "bitbucket.org"):
                say("detail", f"ignored live URL {live_url}: a code-hosting site is not this app's deployment")
            elif live_url:
                say("live", f"connecting live app {live_url} …")
                try:
                    d = discover(live_url)
                    gg = get_graph(graph_name)
                    code_paths = {norm_path(r["path"]) for r in rows(gg.ro_query("MATCH (e:Entrypoint) WHERE coalesce(e.router, '') <> 'live' RETURN e.path AS path"))}
                    site_paths = {norm_path(e["path"]) for e in d["endpoints"]} | {norm_path(b["path"]) for b in d["bundle_paths"]}
                    if code_paths and site_paths and not (code_paths & site_paths):
                        say("detail", f"live URL {host} does not match this code (0 of {len(site_paths)} paths): not merged. Analyse it on its own to get a surface graph.")
                    else:
                        summ = apply_to_graph(graph_name, d)
                        say("detail", f"live: {summ['live_endpoints']} endpoints, {summ['matched_to_code']} matched to code, {summ['only_live']} only deployed, {summ['only_in_code']} only in code")
                except Exception as e:
                    say("detail", f"live app discovery failed: {e}")
            g = get_graph(graph_name)
            c = {r["label"]: r["n"] for r in rows(g.ro_query("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n"))}
            warn = []
            if not c.get("Entrypoint"):
                warn.append("no HTTP routes detected (FastAPI, Flask, Django, Express, Next.js and NestJS routes are supported)")
            if not c.get("Vulnerability"):
                warn.append("no advisories found: either the pins are clean or there is no lockfile / pinned requirements")
            q.put({"type": "done", "graph": graph_name, "counts": c, "seconds": round(time.time() - t0, 1), "warnings": warn})
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    async def stream():
        loop = asyncio.get_event_loop()
        while True:
            ev = await loop.run_in_executor(None, q.get)
            if ev is None:
                break
            yield f"data: {json.dumps(ev, default=str)}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def analyze_local(path: str):
    """Analyse a folder already on this machine (your own project), in place."""
    p = pathlib.Path(path).resolve()
    graph_name = re.sub(r"[^a-z0-9_-]", "-", p.name.lower()) or "local"
    return _ingest_stream(p, graph_name, f"file://{p}", pre_msgs=[f"using local folder {p}"])


async def analyze_surface(url: str):
    """App URL only, no code: build a surface-only graph of the live API (endpoints, auth flags). No advisories without code."""
    host = urlparse(url).hostname or "site"
    graph_name = "site-" + re.sub(r"[^a-z0-9_-]", "-", host.lower())
    q: queue.Queue = queue.Queue()

    def work():
        t0 = time.time()
        try:
            q.put({"type": "progress", "stage": "parse", "msg": f"no code given: mapping the live API surface of {host} …", "t": time.time()})
            d = discover(url)
            if not d["endpoints"] and not d["graphql"] and not d["bundle_paths"]:
                raise RuntimeError("no OpenAPI document, GraphQL schema or frontend API calls found at that URL")
            db = get_db()
            if graph_name in db.list_graphs():
                db.select_graph(graph_name).delete()
            g = db.select_graph(graph_name)
            g.query("MERGE (r:Repo {name: $n}) SET r.url = $u, r.kind = 'live-only', r.ingested_at = $t", {"n": graph_name, "u": url, "t": time.strftime("%Y-%m-%dT%H:%M:%S")})
            summ = apply_to_graph(graph_name, d)
            q.put({"type": "progress", "stage": "detail", "msg": f"{d.get('openapi_title') or (summ.get('framework', 'unknown') + ' app')} {d.get('openapi_version') or ''}: {summ['live_endpoints']} documented endpoints, {summ['frontend_api_paths']} paths referenced by the frontend ({summ.get('frontend_confirmed_calls', 0)} confirmed HTTP calls), {summ['graphql_fields']} GraphQL fields", "t": time.time()})
            STATE["graph"], STATE["repo"] = graph_name, ""
            for a in SESSIONS.values():
                a.close()
            SESSIONS.clear(); _FUNNEL.pop(graph_name, None)
            c = {r["label"]: r["n"] for r in rows(g.ro_query("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n"))}
            q.put({"type": "done", "graph": graph_name, "counts": c, "seconds": round(time.time() - t0, 1),
                   "warnings": ["surface-only graph: endpoints and auth flags from the live app. Add the source repository to get advisories, reachability and fixes."]})
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    async def stream():
        loop = asyncio.get_event_loop()
        while True:
            ev = await loop.run_in_executor(None, q.get)
            if ev is None:
                break
            yield f"data: {json.dumps(ev, default=str)}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), live_url: str = Form("")):
    """Upload a zip of a repository (e.g. GitHub's 'Download ZIP' or your own project) and analyse it."""
    name = (re.sub(r"[^a-z0-9_-]", "-", pathlib.Path(file.filename or "upload").stem.lower()) or "upload") + "-upload"   # never clobber a cloned repo of the same name
    dest = ROOT / "data" / "repos" / name
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="br-upload-"))
    zpath = tmp / "upload.zip"
    with open(zpath, "wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        with zipfile.ZipFile(zpath) as z:
            total = sum(i.file_size for i in z.infolist())
            if total > 2_000_000_000 or any(".." in i.filename or i.filename.startswith("/") for i in z.infolist()):
                return JSONResponse({"error": "zip rejected (too large or unsafe paths)"}, status_code=400)
            z.extractall(tmp / "x")
    except zipfile.BadZipFile:
        return JSONResponse({"error": "not a zip file"}, status_code=400)
    inner = [p for p in (tmp / "x").iterdir() if p.is_dir() and not p.name.startswith(("__MACOSX", "."))]
    src = inner[0] if len(inner) == 1 and not any((tmp / "x").glob("*.py")) else tmp / "x"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(src), str(dest))
    if not (dest / ".git").exists():   # ownership needs git history; give uploads a single baseline commit so blame still works
        subprocess.run(["git", "init", "-q"], cwd=dest); subprocess.run(["git", "add", "-A"], cwd=dest)
        subprocess.run(["git", "-c", "user.name=upload", "-c", "user.email=upload@local", "commit", "-q", "-m", "uploaded snapshot"], cwd=dest)
    return _ingest_stream(dest, name, f"upload://{file.filename}", pre_msgs=[f"unpacked {file.filename} ({len(list(dest.rglob('*')))} files)"], live_url=live_url)


@app.post("/api/analyze")
async def analyze(body: AnalyzeReq):
    """Clone any public Python repo and build its graph live. Streams progress lines over SSE, then switches the console to it."""
    raw = body.url.strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(?:tree|blob)/([^/]+)(?:/(.*?))?)?/?$", raw) or re.match(r"^git@github\.com:([\w.-]+)/([\w.-]+?)(?:\.git)?$", raw)
    if not m and raw.startswith("/") and pathlib.Path(raw).is_dir():
        return await analyze_local(raw)
    if not m and re.search(r"^(?:https?://)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)/", raw):
        return JSONResponse({"error": "that is a code-hosting URL but not a repository: use https://github.com/owner/repo or https://github.com/owner/repo/tree/branch/sub/folder"}, status_code=400)
    if not m and re.match(r"^https?://", raw):
        return await analyze_surface(raw)
    if not m:
        return JSONResponse({"error": "give a GitHub repo URL (https://github.com/owner/repo), a live app URL (https://…), or an absolute local folder path"}, status_code=400)
    owner, name = m.group(1), m.group(2)
    ref = (m.group(3) if m.lastindex and m.lastindex >= 3 else "") or body.ref
    sub = unquote(m.group(4) or "") if m.lastindex and m.lastindex >= 4 else ""
    if "/blob/" in raw and sub:
        sub = sub.rsplit("/", 1)[0] if "/" in sub else ""
    sub = sub.strip("/")
    token = os.getenv("GITHUB_TOKEN", "")
    clone_url = f"https://x-access-token:{token}@github.com/{owner}/{name}.git" if token else f"https://github.com/{owner}/{name}.git"
    graph_name = re.sub(r"[^a-z0-9_-]", "-", (name + ("-" + sub.replace("/", "-") if sub else "")).lower())
    dest = ROOT / "data" / "repos" / graph_name
    pre = []
    if not dest.exists():
        cmd = ["git", "clone", "-q", "--depth", "400"] + (["--branch", ref] if ref else []) + [clone_url, str(dest)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            err = (r.stderr or "").replace(token, "***") if token else (r.stderr or "")
            if "Authentication failed" in err or "could not read Username" in err or "Repository not found" in err:
                return JSONResponse({"error": "clone failed: private or missing repo. Set GITHUB_TOKEN in .env (a token with repo read access) to analyse private repositories."}, status_code=400)
            return JSONResponse({"error": err.strip()[-300:] or "git clone failed"}, status_code=400)
        if token:
            subprocess.run(["git", "-C", str(dest), "remote", "set-url", "origin", f"https://github.com/{owner}/{name}.git"], capture_output=True)
        pre.append(f"cloned github.com/{owner}/{name}" + (f" @ {ref}" if ref else ""))
    else:
        pre.append("repo already cloned, reusing")
    if sub:
        if not (dest / sub).is_dir():
            return JSONResponse({"error": f"folder '{sub}' does not exist in {owner}/{name}" + (f" at {ref}" if ref else "")}, status_code=400)
        pre.append(f"analysing sub-folder {sub}")
    return _ingest_stream(dest, graph_name, f"https://github.com/{owner}/{name}" + (f"/tree/{ref}/{sub}" if sub else ""), pre_msgs=pre, live_url=body.live_url, source_dirs=sub)


@app.get("/api/feed")
def feed(limit: int = 8):
    """Newest advisories affecting packages this code actually uses, for the live 'just dropped' feed."""
    g = get_graph(_graph())
    items = rows(g.ro_query("MATCH (v:Vulnerability)-[a:AFFECTS]->(p:Package)<-[:USES]-(fn:Function) "
                                     "OPTIONAL MATCH (v)-[:TRIAGED]->(d:Decision) "
                                     "WITH v, p, a, count(DISTINCT fn) AS fns, collect(d.status)[0] AS decision "
                                     "RETURN v.id AS id, v.cve AS cve, v.severity AS severity, v.published AS published, left(v.summary, 90) AS summary, "
                                     "p.name AS package, p.version AS installed, a.fixed_version AS fixed, fns AS functions_using, decision "
                                     "ORDER BY v.published DESC LIMIT 200", {}))
    seen, out = set(), []   # newest advisory per package, so the feed shows breadth not one noisy package
    for it in items:
        if it["package"] not in seen:
            seen.add(it["package"]); out.append(it)
        if len(out) >= limit:
            break
    return {"items": out}


@app.get("/api/graph/seed")
def seed():
    """Initial evidence graph: vulnerable packages that first-party code uses, and the functions using them."""
    g = get_graph(_graph())
    data = rows(g.ro_query("MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)<-[:USES]-(fn:Function) "
                           "WITH p, count(DISTINCT v) AS vulns, collect(DISTINCT fn)[0..6] AS fns RETURN p.name AS pkg, vulns, "
                           "[f IN fns | f.qualname] AS fns, size([(fn2)-[:EXPOSES]->() WHERE fn2 IN fns | fn2]) AS handlers"))
    nodes, edges = [], []
    for d in data:
        nodes.append({"id": f"pkg:{d['pkg']}", "label": "Package", "name": f"{d['pkg']} ({d['vulns']})"})
        for f in d["fns"]:
            nodes.append({"id": f, "label": "Function", "name": f.split(".")[-1]})
            edges.append({"source": f, "target": f"pkg:{d['pkg']}", "type": "USES"})
    if not nodes:
        # surface-only graph (no code): show the confirmed API calls grouped by area so the canvas is not empty
        areas = rows(g.ro_query("MATCH (e:Entrypoint) WHERE e.confirmed WITH split(e.path, '/')[1] AS area, collect(e)[0..5] AS eps, count(*) AS n "
                                "RETURN area, n, [x IN eps | {id: x.id, auth: x.auth_required}] AS eps ORDER BY n DESC LIMIT 12"))
        for a in areas:
            nodes.append({"id": f"area:{a['area']}", "label": "Package", "name": f"/{a['area']} ({a['n']})"})
            for e in a["eps"]:
                nodes.append({"id": e["id"], "label": "Entrypoint", "name": e["id"], "live": True, "auth_required": e["auth"], "attn": "public" if e["auth"] is False else ("unknown" if e["auth"] is None else "")})
                edges.append({"source": f"area:{a['area']}", "target": e["id"], "type": "EXPOSES"})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/endpoint")
def endpoint_detail(id: str):
    """Everything known about one endpoint: method, path, full URL, auth, where it was seen, evidence, parameters, body, handler, owners."""
    g = get_graph(_graph())
    r = rows(g.ro_query("MATCH (e:Entrypoint {id: $id}) OPTIONAL MATCH (h:Function)-[:EXPOSES]->(e) OPTIONAL MATCH (f:File)-[:CONTAINS]->(h) "
                        "RETURN properties(e) AS e, collect(DISTINCT {qualname: h.qualname, file: f.path, line: h.line})[0..5] AS handlers", {"id": id}))
    if not r:
        return JSONResponse({"error": "unknown endpoint"}, status_code=404)
    e, handlers = r[0]["e"], [h for h in r[0]["handlers"] if h.get("qualname")]
    repo = rows(g.ro_query("MATCH (r:Repo) RETURN r.live_url AS live_url, r.live_base_urls AS bases, r.url AS url, r.kind AS kind LIMIT 1"))
    repo = repo[0] if repo else {}
    base = (repo.get("live_url") or "").rstrip("/")
    bases = [b for b in (repo.get("bases") or []) if isinstance(b, str)]
    path = e.get("path") or ""
    prefix = ""
    if bases and base and not any(path.startswith(b.rstrip("/") + "/") for b in bases if b.startswith("/")):
        first = next((b for b in bases if b.startswith("/")), "")
        prefix = first.rstrip("/") if first and e.get("source") in ("bundle", "bundle-llm") else ""
    full_url = f"{base}{prefix}{path}" if base else ""
    path_params = re.findall(r"\{([^}]+)\}", path) + re.findall(r":(\w+)", path)
    owners = []
    if handlers and handlers[0].get("file"):
        owners = rows(g.ro_query("MATCH (a:Author)-[:AUTHORED]->(c:Commit)-[:MODIFIED]->(f:File {path: $p}) RETURN a.name AS name, count(c) AS commits ORDER BY commits DESC LIMIT 3", {"p": handlers[0]["file"]}))
    vulns = rows(g.ro_query("MATCH (h:Function)-[:EXPOSES]->(e:Entrypoint {id: $id}) MATCH path=(h)-[:CALLS*0..4]->(fn:Function)-[:USES]->(p:Package)<-[:AFFECTS]-(v:Vulnerability) "
                            "RETURN DISTINCT p.name AS package, v.id AS id, v.severity AS severity ORDER BY severity LIMIT 8", {"id": id})) if handlers else []
    return {"id": id, "method": e.get("method"), "path": path, "full_url": full_url, "base_url_note": (f"frontend prefixes calls with {prefix}" if prefix else ""),
            "auth_required": e.get("auth_required"), "live": e.get("live"), "confirmed": e.get("confirmed"), "source": e.get("source") or ("code" if handlers else "unknown"),
            "router": e.get("router"), "summary": e.get("summary") or "", "operation_id": e.get("operation_id") or "", "tags": e.get("tags") or [],
            "path_params": path_params, "params": e.get("params") or [], "body_fields": e.get("body_fields") or [], "content_type": e.get("content_type") or "",
            "frontend_calls": e.get("frontend_calls"), "handlers": handlers, "owners": owners, "vulnerabilities_on_paths": vulns, "repo_kind": repo.get("kind")}


@app.get("/api/graph/neighborhood")
def neighborhood(id: str, label: str):
    """Expand one node for the UI (double-click)."""
    g = get_graph(_graph())
    key = {"Function": "qualname", "Package": "name", "Vulnerability": "id", "Entrypoint": "id", "Author": "email", "File": "path"}.get(label, "id")
    val = id.split("pkg:", 1)[1] if label == "Package" and id.startswith("pkg:") else id
    data = rows(g.ro_query(f"MATCH (a:{label} {{{key}: $v}})-[r]-(b) RETURN labels(b)[0] AS blabel, type(r) AS rel, startNode(r) = a AS outgoing, "
                           f"coalesce(b.qualname, b.id, b.name, b.email, b.path) AS bid, coalesce(b.name, b.id, b.path, b.qualname) AS bname LIMIT 60", {"v": val}))
    nodes, edges = [], []
    for d in data:
        bid = f"pkg:{d['bid']}" if d["blabel"] == "Package" else d["bid"]
        nodes.append({"id": bid, "label": d["blabel"], "name": (d["bname"] or bid).split(".")[-1] if d["blabel"] == "Function" else d["bname"]})
        edges.append({"source": id if d["outgoing"] else bid, "target": bid if d["outgoing"] else id, "type": d["rel"]})
    return {"nodes": nodes, "edges": edges}


@app.post("/api/ask")
async def ask(body: Ask):
    if body.reset or body.session not in SESSIONS:
        old = SESSIONS.pop(body.session, None)
        if old:
            old.close()
        SESSIONS[body.session] = Agent(_graph(), _repo())
    agent = SESSIONS[body.session]
    q: queue.Queue = queue.Queue()
    events: list[dict] = []
    run_id = uuid.uuid4().hex[:8]
    started = time.time()
    agent.on_event = lambda e: (events.append(e), q.put(e))

    def work():
        try:
            out = agent.run(body.prompt)
            RUNS[run_id] = {"run_id": run_id, "prompt": body.prompt, "result": out, "events": events, "started": started,
                            "seconds": round(time.time() - started, 1), "graph_name": _graph()}
            rd = ROOT / "data" / "reports"; rd.mkdir(parents=True, exist_ok=True)
            (rd / f"run-{run_id}.json").write_text(json.dumps(RUNS[run_id], default=str))
            q.put({"type": "done", "run_id": run_id, "report_url": f"/api/report/{run_id}"})
        except Exception as e:
            q.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
        q.put(None)

    threading.Thread(target=work, daemon=True).start()

    async def stream():
        loop = asyncio.get_event_loop()
        while True:
            ev = await loop.run_in_executor(None, q.get)
            if ev is None:
                break
            yield f"data: {json.dumps(ev, default=str)}\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/report/{run_id}", response_class=HTMLResponse)
def report(run_id: str):
    run = load_run(run_id)
    if not run:
        return HTMLResponse("<p>unknown run</p>", status_code=404)
    out = render_report(run)
    path = ROOT / "data" / "reports" / f"run-{run_id}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(out)
    return HTMLResponse(out)


@app.get("/replay/{run_id}", response_class=HTMLResponse)
def replay(run_id: str):
    run = load_run(run_id)
    if not run:
        return HTMLResponse("<p>unknown run</p>", status_code=404)
    out = render_replay(run)
    path = ROOT / "data" / "reports" / f"replay-{run_id}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(out)
    return HTMLResponse(out)


@app.get("/api/cypher")
def cypher(q: str):
    try:
        return {"rows": rows(get_graph(_graph()).ro_query(q))}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


app.mount("/static", StaticFiles(directory=ROOT / "web"), name="static")
