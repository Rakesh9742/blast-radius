"""LLM-assisted API extraction from frontend bundles and docs pages.

The regex pass in discover.py only catches literal "/api/..." strings. Real bundles build URLs from constants
(`${API_BASE}/users/${id}`), axios instances with baseURL, fetch wrappers, GraphQL operation names. We cut the
network-call neighbourhoods out of each bundle (cheap) and ask Claude for structured endpoints (precise)."""
from __future__ import annotations
import os, re, json
from pydantic import BaseModel
import anthropic

MODEL = os.getenv("BLAST_MODEL", "claude-opus-5-5")
KEYWORDS = r"(fetch\(|axios|\$http|XMLHttpRequest|\.get\(|\.post\(|\.put\(|\.patch\(|\.delete\(|baseURL|BASE_URL|API_URL|apiUrl|API_BASE|endpoint|graphql|useQuery|useMutation|\$fetch|ofetch|ky\.|superagent|/api/|/v[0-9]/|Uri\.parse|Uri\.https?\(|dio|Dio\(|baseUrl|_baseUrl|HttpClient|http\.get|http\.post)"


class Endpoint(BaseModel):
    method: str          # GET, POST, PUT, PATCH, DELETE, ANY, QUERY, MUTATION
    path: str            # normalised, starting with /, params as {name}
    auth_hint: str       # "requires-auth" | "public" | "unknown"
    evidence: str        # <= 50 chars of the code that proves it
    query_params: list[str]   # query-string parameter names visible near the call, else []
    body_fields: list[str]    # request body field names visible near the call (JSON keys, form fields), else []


class Extraction(BaseModel):
    base_urls: list[str]
    endpoints: list[Endpoint]


PATH_CALL = re.compile(r'["\'`](/[a-z][A-Za-z0-9_\-/{}$:.]{2,})["\'`]\s*[+,)]|[(,]\s*["\'`](/[a-z][A-Za-z0-9_\-/{}$:.]{2,})["\'`]')


def _windows(js: str, rx: re.Pattern, radius: int) -> list[list[int]]:
    spans: list[list[int]] = []
    for m in rx.finditer(js):
        a, b = max(0, m.start() - radius), min(len(js), m.end() + radius)
        if spans and a <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b])
    return spans


def snippets_from_bundle(js: str, radius: int = 220, max_chars: int = 45_000, max_chunks: int = 1) -> list[str]:
    """Windows around network code, path literals used as call arguments first (they are the API calls in minified Dart/JS),
    generic network keywords second. Returns up to max_chunks strings of <= max_chars each."""
    spans = _windows(js, PATH_CALL, radius)
    covered = 0
    for a, b in spans:
        covered += b - a
    if covered < max_chars * max_chunks:
        extra = [sp for sp in _windows(js, re.compile(KEYWORDS), radius) if not any(a <= sp[0] <= b for a, b in spans)]
        spans = sorted(spans + extra)
    chunks, cur, total = [], [], 0
    for a, b in spans:
        piece = js[a:b]
        if total + len(piece) > max_chars:
            if cur:
                chunks.append("\n…\n".join(cur))
            cur, total = [], 0
            if len(chunks) >= max_chunks:
                break
        cur.append(piece); total += len(piece)
    if cur and len(chunks) < max_chunks:
        chunks.append("\n…\n".join(cur))
    return chunks


PROMPT = ("You are extracting the HTTP API surface a web frontend talks to. Below are regions of its JavaScript bundles around network calls, "
          "plus the page HTML. Return every distinct backend endpoint the code can call.\n"
          "Rules: resolve base-URL constants and template literals (`${API}/users/${id}` -> /users/{id}); path params as {name}; "
          "method from the call (fetch default GET, axios.post -> POST, unknown -> ANY); GraphQL operations as QUERY/MUTATION with path '/graphql#OperationName'; "
          "auth_hint 'requires-auth' if an Authorization/bearer/cookie header is attached nearby, 'public' if clearly not, else 'unknown'; "
          "evidence = at most 50 characters of code proving the endpoint (keep it short: output size is the bottleneck); query_params and body_fields = parameter or JSON field names you can actually see being sent with that call, otherwise empty lists. Skip static assets (.js, .css, images), third-party SaaS hosts, and websocket URLs. "
          "Client-side page routes (router/navigation targets) are NOT endpoints: only paths passed to an HTTP call count. "
          "Do not invent endpoints that are not in the code.\n\n")


def _schema() -> dict:
    schema = Extraction.model_json_schema()
    schema["additionalProperties"] = False
    for d in schema.get("$defs", {}).values():
        d["additionalProperties"] = False
    return schema


def _ask(client: anthropic.Anthropic, parts: list[str]) -> tuple[Extraction, int, int]:
    # streaming: structured JSON output can run past the SDK's non-streaming time guard on big bundles
    with client.messages.stream(model=MODEL, max_tokens=32000, messages=[{"role": "user", "content": PROMPT + "\n\n".join(parts)}],
                                output_config={"format": {"type": "json_schema", "schema": _schema()}, "effort": "low"}) as stream:
        resp = stream.get_final_message()
    text = next((b.text for b in resp.content if b.type == "text"), "{}")
    return Extraction.model_validate_json(text), resp.usage.input_tokens, resp.usage.output_tokens


def extract_endpoints(bundles: dict[str, str], page_html: str = "", client: anthropic.Anthropic | None = None, max_chunks_per_bundle: int = 3) -> dict:
    """bundles: {script_name: js_source}. Bundles over 1 MB are split into up to max_chunks_per_bundle requests run in parallel.
    Returns {"base_urls": [...], "endpoints": [...], "tokens_in": n, "tokens_out": n, "requests": n}."""
    shared = client is not None
    head = ["### index.html (first 6k chars)\n" + page_html[:6000]] if page_html else []
    requests: list[list[str]] = []
    small, budget = [], 160_000
    for name, js in bundles.items():
        n_chunks = max_chunks_per_bundle if len(js) > 1_000_000 else 1
        for i, sn in enumerate(snippets_from_bundle(js, max_chunks=n_chunks)):
            if not sn.strip():
                continue
            piece = f"### {name} part {i + 1} (network-call regions only, {len(js):,} chars total)\n{sn}"
            if n_chunks > 1:
                requests.append(head + [piece])
            elif len(piece) <= budget:
                small.append(piece); budget -= len(piece)
    if small:
        requests.insert(0, head + small)
    if not requests:
        return {"base_urls": [], "endpoints": [], "tokens_in": 0, "tokens_out": 0, "requests": 0}
    # one client per request: a single client shared across threads stalled its streams indefinitely
    from concurrent.futures import ThreadPoolExecutor

    def one(parts):
        try:
            return _ask(client if shared else anthropic.Anthropic(timeout=120.0, max_retries=1), parts), None
        except Exception as e:
            return None, f"{type(e).__name__}: {str(e)[:120]}"
    with ThreadPoolExecutor(max_workers=4) as ex:
        outcomes = list(ex.map(one, requests))
    results = [r for r, _ in outcomes if r]; errors = [e for _, e in outcomes if e]
    seen, eps, bases, tin, tout = set(), [], [], 0, 0
    for ex_, i, o in results:
        tin += i; tout += o
        bases += [b for b in ex_.base_urls if b not in bases]
        for e in ex_.endpoints:
            p = e.path.strip()
            if not p.startswith("/") or re.search(r"\.(js|css|png|svg|woff2?|ico|map)$", p):
                continue
            key = (e.method.upper(), re.sub(r"\{[^}]*\}", "{p}", p))
            if key in seen:
                continue
            seen.add(key)
            eps.append({"method": e.method.upper(), "path": p, "source": "bundle-llm", "summary": e.evidence[:120], "auth_hint": e.auth_hint,
                        "query_params": [q[:40] for q in e.query_params][:20], "body_fields": [b[:40] for b in e.body_fields][:25]})
    return {"base_urls": bases, "endpoints": eps, "tokens_in": tin, "tokens_out": tout, "requests": len(requests), "errors": errors}


def find_spec_url_in_docs(html: str, base: str) -> str | None:
    """Swagger UI / Redoc pages embed the spec location: url: "/openapi.json", spec-url="...", SwaggerUIBundle({url: ...})."""
    for pat in (r"""url\s*:\s*['"]([^'"]+\.(?:json|yaml|yml)[^'"]*)['"]""", r"""spec-url=['"]([^'"]+)['"]""", r"""['"]([^'"]*(?:openapi|swagger)[^'"]*\.(?:json|yaml|yml))['"]"""):
        m = re.search(pat, html, re.I)
        if m:
            return m.group(1)
    return None
