"""Discover the API surface of a LIVE application from its URL and join it to the code graph.

Sources, in order: OpenAPI/Swagger document, GraphQL introspection, API paths referenced by the frontend JavaScript bundles.
Result on the graph: Entrypoint nodes gain live=true, source, operation_id, summary, auth_required; endpoints only seen live are created
(unmapped: code we did not analyse or routes added after the analysed revision); code endpoints not seen live are flagged (drift).
"""
from __future__ import annotations
import json, os, re, time
from urllib.parse import urljoin, urlparse
import httpx
from core.db import get_graph, rows

DOCS_PAGES = ["/docs", "/swagger", "/swagger-ui", "/swagger-ui.html", "/api/docs", "/redoc", "/api-docs", "/api/swagger-ui", "/openapi", "/api"]
OPENAPI_PATHS = ["/openapi.json", "/api/openapi.json", "/swagger.json", "/api/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json", "/docs/openapi.json", "/api/v1/openapi.json", "/openapi.yaml"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql"]
UA = {"User-Agent": "BlastRadius/0.1 (+security triage; read-only discovery)"}


def norm_path(p: str) -> str:
    """Normalise path params so /api/users/{id}, /api/users/:id, /api/users/${userId} and /api/users/<int:id> compare equal."""
    p = re.sub(r"\$\{[^}]*\}", "{p}", p)
    p = re.sub(r"<[^>]*>", "{p}", p)
    p = re.sub(r":[A-Za-z_][\w]*", "{p}", p)
    p = re.sub(r"\{[^}]*\}", "{p}", p)
    return p.rstrip("/") or "/"


def _load_spec(r: httpx.Response) -> dict | None:
    txt = r.text.lstrip()
    try:
        if txt.startswith("{"):
            d = r.json()
        else:
            import yaml
            d = yaml.safe_load(txt)
        return d if isinstance(d, dict) and "paths" in d else None
    except Exception:
        return None


def fetch_openapi(base: str, client: httpx.Client) -> tuple[dict | None, str | None]:
    for path in OPENAPI_PATHS:
        url = urljoin(base, path)
        try:
            r = client.get(url, timeout=20)
            if r.status_code == 200 and (d := _load_spec(r)):
                return d, url
        except Exception:
            continue
    # docs pages (Swagger UI / Redoc) embed the real spec URL: follow it
    from ingest.llm_extract import find_spec_url_in_docs
    for path in DOCS_PAGES:
        try:
            r = client.get(urljoin(base, path), timeout=20)
            if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
                continue
            spec = find_spec_url_in_docs(r.text, base)
            if spec:
                r2 = client.get(urljoin(str(r.url), spec), timeout=20)
                if r2.status_code == 200 and (d := _load_spec(r2)):
                    return d, str(r2.url)
        except Exception:
            continue
    return None, None


def _deref(spec: dict, schema: dict, depth: int = 0) -> dict:
    while isinstance(schema, dict) and "$ref" in schema and depth < 6:
        node = spec
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        schema = node; depth += 1
    return schema if isinstance(schema, dict) else {}


def _body_fields(spec: dict, op: dict) -> tuple[list[str], str]:
    content = (op.get("requestBody") or {}).get("content") or {}
    if not content:
        return [], ""
    ctype, media = next(iter(content.items()))
    schema = _deref(spec, media.get("schema") or {})
    for key in ("allOf", "anyOf", "oneOf"):
        if key in schema and schema[key]:
            schema = _deref(spec, schema[key][0])
    props = schema.get("properties") or {}
    req = set(schema.get("required") or [])
    fields = [f"{n}{'*' if n in req else ''}: {_deref(spec, d).get('type', 'object')}" for n, d in list(props.items())[:25]]
    if not fields and schema.get("type") == "array":
        fields = ["[array]"]
    return fields, ctype


def endpoints_from_openapi(spec: dict) -> list[dict]:
    out = []
    global_sec = bool(spec.get("security"))
    for path, ops in spec.get("paths", {}).items():
        shared = ops.get("parameters", []) if isinstance(ops, dict) else []
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            params = [f"{_deref(spec, p).get('in', '?')}:{_deref(spec, p).get('name', '?')}{'*' if _deref(spec, p).get('required') else ''}" for p in (shared + (op.get("parameters") or []))][:30]
            body, ctype = _body_fields(spec, op)
            out.append({"method": method.upper(), "path": path, "operation_id": op.get("operationId", ""), "summary": (op.get("summary") or "")[:120],
                        "tags": op.get("tags", [])[:3], "auth_required": bool(op.get("security")) or (global_sec and op.get("security") != []), "source": "openapi",
                        "params": params, "body_fields": body, "content_type": ctype})
    return out


def graphql_introspect(base: str, client: httpx.Client) -> list[dict]:
    q = {"query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}
    for path in GRAPHQL_PATHS:
        try:
            r = client.post(urljoin(base, path), json=q, timeout=20)
            if r.status_code == 200 and "__schema" in r.text:
                s = r.json()["data"]["__schema"]
                out = [{"method": "QUERY", "path": f"{path}#{f['name']}", "source": "graphql", "summary": "GraphQL query"} for f in (s.get("queryType") or {}).get("fields", [])]
                out += [{"method": "MUTATION", "path": f"{path}#{f['name']}", "source": "graphql", "summary": "GraphQL mutation"} for f in (s.get("mutationType") or {}).get("fields", [])]
                return out
        except Exception:
            continue
    return []


STATIC_EXT = re.compile(r"\.(css|js|mjs|map|html?|png|jpe?g|svg|gif|webp|ico|woff2?|ttf|otf|eot|json|wasm|mp[34]|pdf|txt|xml)$", re.I)
ROUTE_LITERAL = re.compile(r'["\'`](/[a-z][a-z0-9_\-]*(?:/[A-Za-z0-9_\-{}$:.<>]+)*)["\'`]')
NESTED_JS = [re.compile(r'(?:import\(|load\(|importScripts\()\s*["\'`]([^"\'`]+\.js)["\'`]'),
             re.compile(r'["\'`]([^"\'`\s]*main\.dart\.js)["\'`]'),
             re.compile(r'["\'`]([^"\'`\s]*(?:/_next/static/|/_nuxt/|/chunks?/|/assets/)[^"\'`\s]*\.js)["\'`]')]


def detect_framework(html: str, script_urls: list[str]) -> str:
    joined = " ".join(script_urls) + " " + html[:20000]
    for marker, name in (("flutter_bootstrap.js", "flutter"), ("main.dart.js", "flutter"), ("/_next/", "next"), ("/_nuxt/", "nuxt"),
                         ("ng-version=", "angular"), ("modulepreload", "vite"), ("webpack", "webpack")):
        if marker in joined:
            return name
    return "unknown"


def scan_bundles(base: str, client: httpx.Client, max_scripts: int = 14, max_bytes: int = 16_000_000) -> tuple[list[dict], dict[str, str], str, dict]:
    """Download the page's JavaScript plus one level of bundles those scripts load themselves (Flutter main.dart.js, Vite/Next chunks).
    Returns (route-like paths found by regex, {script: source}, page html, diag)."""
    try:
        html = client.get(base, timeout=20).text
    except Exception:
        return [], {}, "", {"framework": "unknown", "bundles": []}
    level0 = re.findall(r'<script[^>]+src="([^"]+)"', html) + re.findall(r'<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"', html)
    queue = list(dict.fromkeys(urljoin(base, s) for s in level0))[:max_scripts]
    seen: set[str] = set(); sources: dict[str, str] = {}; found: dict[str, dict] = {}; skipped_large: list[str] = []

    def fetch(url: str) -> str | None:
        if url in seen or len(sources) >= max_scripts:
            return None
        seen.add(url)
        try:
            r = client.get(url, timeout=60)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        if len(r.content) > max_bytes:
            skipped_large.append(url.rsplit("/", 1)[-1][:60]); return None
        name = url.rsplit("/", 1)[-1].split("?")[0][:60] or "index.js"
        sources[name] = r.text
        for m in ROUTE_LITERAL.finditer(r.text):
            p = m.group(1)
            if len(p) >= 4 and not STATIC_EXT.search(p) and "//" not in p:
                found.setdefault(norm_path(p), {"method": "ANY", "path": p, "source": "bundle", "summary": f"referenced by {name[:40]}"})
        return r.text

    nested: list[str] = []
    for url in queue:
        text = fetch(url)
        if text:
            for rx in NESTED_JS:
                nested += [urljoin(url, n) for n in rx.findall(text)[:6]]
    for url in dict.fromkeys(nested):
        fetch(url)
    diag = {"framework": detect_framework(html, list(seen)), "bundles": list(sources), "skipped_too_large": skipped_large}
    return list(found.values()), sources, html, diag


def handler_name_from_operation_id(op_id: str, path: str, method: str) -> str | None:
    """FastAPI default operationId = f"{function_name}_{path_slug}_{method}". Recover the function name."""
    if not op_id:
        return None
    slug = re.sub(r"[^0-9a-zA-Z_]", "_", path)
    suffix = f"{slug}_{method.lower()}"
    if op_id.endswith(suffix):
        return op_id[: -len(suffix)].rstrip("_") or None
    return op_id.split("_")[0] if "_" in op_id else op_id


def discover(base_url: str, use_llm: bool | None = None) -> dict:
    """use_llm: ask Claude to extract endpoints from the bundles (default: on when an API key is configured)."""
    base = base_url if base_url.endswith("/") else base_url + "/"
    t0 = time.time()
    diag: dict = {}
    with httpx.Client(headers=UA, follow_redirects=True) as c:
        try:
            r0 = c.get(base, timeout=20); diag["page_status"] = r0.status_code; diag["page_type"] = r0.headers.get("content-type", "")[:40]; diag["final_url"] = str(r0.url)
            diag["page_bytes"] = len(r0.content); diag["looks_blocked"] = r0.status_code in (401, 403, 429, 503) or "captcha" in r0.text.lower()[:5000] or "cloudflare" in r0.text.lower()[:5000]
        except Exception as e:
            diag["page_error"] = f"{type(e).__name__}: {e}"[:160]
        spec, spec_url = fetch_openapi(base, c)
        eps = endpoints_from_openapi(spec) if spec else []
        gql = graphql_introspect(base, c)
        bundle, sources, html, bdiag = scan_bundles(base, c)
        diag.update(bdiag); diag["scripts_downloaded"] = len(sources); diag["spec_found"] = bool(spec)
    llm = {"endpoints": [], "base_urls": [], "tokens_in": 0, "tokens_out": 0}
    if (use_llm if use_llm is not None else bool(os.getenv("ANTHROPIC_API_KEY"))) and sources:
        try:
            from ingest.llm_extract import extract_endpoints
            llm = extract_endpoints(sources, html)
        except Exception as e:
            llm["error"] = str(e)[:200]
    known = {norm_path(b["path"]) for b in bundle} | {norm_path(e["path"]) for e in eps}
    llm_new = [e for e in llm["endpoints"] if norm_path(e["path"]) not in known]
    return {"base_url": base_url, "openapi_url": spec_url, "openapi_title": (spec or {}).get("info", {}).get("title"), "openapi_version": (spec or {}).get("info", {}).get("version"),
            "endpoints": eps, "graphql": gql, "bundle_paths": bundle + llm_new, "llm": {"endpoints_found": len(llm["endpoints"]), "new_vs_regex_and_spec": len(llm_new), "base_urls": llm.get("base_urls", []),
            "tokens_in": llm.get("tokens_in", 0), "tokens_out": llm.get("tokens_out", 0), "error": llm.get("error")}, "diag": diag, "seconds": round(time.time() - t0, 1)}


def apply_to_graph(graph_name: str, disc: dict) -> dict:
    """Merge live endpoints into the graph, join to handlers, compute drift."""
    g = get_graph(graph_name)
    code_eps = rows(g.ro_query("MATCH (e:Entrypoint) OPTIONAL MATCH (h:Function)-[:EXPOSES]->(e) RETURN e.id AS id, e.method AS method, e.path AS path, coalesce(e.router, '') AS router, collect(h.qualname) AS handlers"))
    by_key = {(e["method"], norm_path(e["path"])): e for e in code_eps}
    matched, created, joined = 0, 0, 0
    rows_live = []
    for ep in disc["endpoints"]:
        key = (ep["method"], norm_path(ep["path"]))
        existing = by_key.get(key)
        handler = handler_name_from_operation_id(ep.get("operation_id", ""), ep["path"], ep["method"])
        rows_live.append({"id": existing["id"] if existing else f"{ep['method']} {ep['path']}", "method": ep["method"], "path": existing["path"] if existing else ep["path"],
                          "operation_id": ep.get("operation_id", ""), "summary": ep.get("summary", ""), "auth_required": ep.get("auth_required", False),
                          "tags": ep.get("tags", []), "handler": handler or "", "existed": bool(existing),
                          "params": ep.get("params", []), "body_fields": ep.get("body_fields", []), "content_type": ep.get("content_type", "")})
        matched += bool(existing); created += not existing
    g.query("UNWIND $rows AS r MERGE (e:Entrypoint {id: r.id}) ON CREATE SET e.method = r.method, e.path = r.path, e.router = 'live' "
            "SET e.live = true, e.source = CASE WHEN r.existed THEN 'code+openapi' ELSE 'openapi-only' END, e.operation_id = r.operation_id, e.summary = r.summary, e.auth_required = r.auth_required, e.tags = r.tags, e.params = r.params, e.body_fields = r.body_fields, e.content_type = r.content_type",
            {"rows": rows_live})
    # join openapi-only endpoints to a handler by the function name recovered from operationId
    res = g.query("UNWIND $rows AS r MATCH (e:Entrypoint {id: r.id}) WHERE NOT (:Function)-[:EXPOSES]->(e) AND r.handler <> '' "
                  "MATCH (f:Function {name: r.handler}) WITH e, f ORDER BY f.is_handler DESC LIMIT 1 MERGE (f)-[:EXPOSES]->(e) RETURN count(*) AS n", {"rows": rows_live})
    joined = rows(res)[0]["n"] if res.result_set else 0
    for gq in disc["graphql"]:
        g.query("MERGE (e:Entrypoint {id: $id}) SET e.method = $m, e.path = $p, e.live = true, e.source = 'graphql', e.summary = $s", {"id": f"{gq['method']} {gq['path']}", "m": gq["method"], "p": gq["path"], "s": gq["summary"]})
    bundle_matched = 0
    for b in disc["bundle_paths"]:
        k = norm_path(b["path"])
        hits = [e for (m, p), e in by_key.items() if p == k]
        if hits:
            bundle_matched += 1
            g.query("UNWIND $ids AS id MATCH (e:Entrypoint {id: id}) SET e.frontend_calls = true", {"ids": [h["id"] for h in hits]})
        elif b.get("source") == "bundle" and disc["endpoints"]:
            continue  # a spec exists and this literal is not in it: a client-side page route, not an API call
        elif not any(norm_path(ep["path"]) == k for ep in disc["endpoints"]):
            # seen only in the frontend code: record it so surface-only sites (no OpenAPI) still get an endpoint inventory
            g.query("MERGE (e:Entrypoint {id: $id}) SET e.method = $m, e.path = $p, e.router = 'live', e.live = true, e.source = $src, e.summary = $s, e.frontend_calls = true, "
                    "e.confirmed = $conf, e.params = $params, e.body_fields = $body, e.auth_required = CASE $auth WHEN 'requires-auth' THEN true WHEN 'public' THEN false ELSE null END",
                    {"id": f"{b['method']} {b['path']}", "m": b["method"], "p": b["path"], "src": b.get("source", "bundle"), "s": b.get("summary", ""), "auth": b.get("auth_hint", "unknown"), "conf": b.get("source") == "bundle-llm", "params": [f"query:{q}" for q in b.get("query_params", [])][:20], "body": list(b.get("body_fields", []))[:25]})
    live_keys = {(e["method"], norm_path(e["path"])) for e in disc["endpoints"]}
    drift = [e["id"] for (k, e) in by_key.items() if k not in live_keys and e["router"] != "live"] if disc["endpoints"] else []
    g.query("MATCH (r:Repo) SET r.live_url = $u, r.live_openapi = $o, r.live_version = $v, r.live_checked = $t, r.live_framework = $fw, r.live_base_urls = $bases",
            {"u": disc["base_url"], "o": disc.get("openapi_url") or "", "v": disc.get("openapi_version") or "", "t": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "fw": disc.get("diag", {}).get("framework", "unknown"), "bases": disc.get("llm", {}).get("base_urls", [])})
    summary = {"live_endpoints": len(disc["endpoints"]), "matched_to_code": matched, "only_live": created, "joined_by_operation_id": joined,
               "only_in_code": len(drift), "only_in_code_sample": drift[:15], "graphql_fields": len(disc["graphql"]), "frontend_api_paths": len(disc["bundle_paths"]),
               "frontend_paths_matched": bundle_matched, "frontend_confirmed_calls": sum(b.get("source") == "bundle-llm" for b in disc["bundle_paths"]), "framework": disc.get("diag", {}).get("framework", "unknown"), "openapi_title": disc.get("openapi_title"), "openapi_version": disc.get("openapi_version"), "llm": disc.get("llm", {})}
    return summary


if __name__ == "__main__":
    import sys
    d = discover(sys.argv[1]); print(json.dumps({k: (v if not isinstance(v, list) else len(v)) for k, v in d.items()}, indent=1))
    if len(sys.argv) > 2:
        print(json.dumps(apply_to_graph(sys.argv[2], d), indent=1))
