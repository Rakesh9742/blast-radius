# Blast Radius

**Graph-native security triage.** Give it a CVE or a package. It walks a FalkorDB code graph to tell you which HTTP endpoints are *actually* reachable from the vulnerable code, who owns that code, and then it fixes it: plans the version bump, verifies it against OSV, commits on a branch, opens a PR (or writes a report), and records the decision back on the graph.

Built for the FalkorDB **Graph Hacks** hackathon, Track 1: *Agents That Act on Connected Data*.

```
Vulnerability -AFFECTS-> Package <-USES- Function <-CALLS*- Function(handler) -EXPOSES-> Entrypoint
                                            ^
                                   Author -OWNS-+   Author -AUTHORED-> Commit -MODIFIED-> File
```

## Demo video

Three minutes, captioned: [watch on Google Drive](https://drive.google.com/file/d/1X8aam-g2Rn-TDCO35Rv8r76NCgHlLjZU/view?usp=sharing) or [download / play the demo video](https://github.com/Rakesh9742/blast-radius/releases/download/v1.0-demo/blast-radius-demo.mp4) (hosted as a [GitHub release asset](https://github.com/Rakesh9742/blast-radius/releases/tag/v1.0-demo)). Scenes and narration are in [docs/demo-scenes.md](docs/demo-scenes.md).

## Graph data model and queries

The full node/edge model with properties, and every Cypher query and FalkorDB algorithm the product depends on, are in [docs/queries.md](docs/queries.md).

## Why a graph

A SCA scanner says "pillow 11.3.0 has 36 vulnerabilities". That is not a triage decision. The questions that matter are multi-hop:

1. Is the package imported by first-party code at all, or only transitively? (`Package <-DEPENDS_ON- Package <-IMPORTS- File`)
2. Which functions call the vulnerable API, and which HTTP endpoints can reach those functions? (`Entrypoint <-EXPOSES- handler -CALLS*1..4-> sink -USES-> Package`)
3. Who last touched that code? (`Author -OWNS-> Function`, via git blame)
4. What is the smallest version bump that clears every advisory, and is it clean? (OSV)

Each of those is one Cypher query in FalkorDB and one tool call for the agent. Every answer in the UI is shown next to the exact subgraph and the exact queries that produced it.

## Demo target

[mealie](https://github.com/mealie-recipes/mealie) at release **v3.0.0** (July 2025): a FastAPI app with 248 HTTP endpoints, 1,251 functions, 2,886 resolved call edges (including FastAPI `Depends` injection, which is how auth reaches every protected route), and a poetry.lock whose 142 pinned packages carry 329 published advisories (OSV), 89 of them HIGH or CRITICAL. Real code, real CVEs, nothing synthetic.

Example: Pillow advisories reach 6 endpoints (`POST /api/recipes/{slug}/image`, `PUT /api/recipes/timeline/events/{item_id}/image`, `POST /api/users/{id}/image`, ...) through `PillowMinifier.minify` in 2 to 4 hops, with high confidence. python-multipart's DoS reaches the upload/form endpoints plus the unauthenticated login form (`POST /api/auth/token`) through `Depends(CredentialsRequestForm)`. pyjwt's `jwt.decode` sits behind `get_current_user`, so its advisories reach 199 of 248 endpoints, and the agent says so. starlette is never imported directly but is one `DEPENDS_ON` hop behind fastapi, which 173 functions use.

## Connect a live app

Two header boxes, two jobs:

- **Analyze** takes a GitHub URL (also `/tree/<branch>/<sub/folder>` links), a zip, a local folder, or **just an app URL**. An app URL with no code builds a *surface graph* of the live API.
- **Connect** attaches the live deployment of the repo currently selected. If the URL does not belong to that repo (none of its paths match the code, or it is a GitHub link), Blast Radius refuses to merge it and builds a separate surface graph instead, so one site can never pollute another repo's graph.

Discovery pulls the OpenAPI/Swagger document (following Swagger UI / Redoc pages to the real spec, reading parameters and request-body schemas), tries GraphQL introspection, downloads the frontend bundles including the ones loaded by other bundles (Flutter `main.dart.js`, Vite/Next chunks, up to 16 MB), detects the framework (Flutter, Next, Nuxt, Vite, Angular), runs a route-literal regex pass, then has Claude read the network-call regions of every bundle in parallel chunks and extract endpoints built from base-URL constants and template strings, with method, auth hint, query parameters and body fields (structured output, deduplicated against the spec). Everything is joined to the code graph: endpoints gain `live=true` and `auth_required`, LLM-confirmed calls are marked `confirmed=true` while bare route strings stay unconfirmed, drift (only in deployment / only in code) is flagged, and the agent ranks **live + unauthenticated** findings first. Publicly callable endpoints and unknown-auth calls on file, certificate, export or payment paths are flagged red and amber in the graph, the live card, the answer and the report. Clicking any endpoint opens its detail card: full URL, auth, evidence, parameters, payload, handler, owners and advisories on its code paths.

Tested against mealie's public demo (273 documented endpoints, 271 matched to the v3.0.0 code, 14 only in code, parameters and body schemas on 260 of them) and against a compiled Flutter web app with no spec at all (127 API calls confirmed from an 8.7 MB bundle, 125 behind login, 1 public, base path `/v1` recovered, about 45 s).

## Analyze any repo

Four ways in, all from the header of the UI:

1. **GitHub URL** (public, or private with `GITHUB_TOKEN`): clone, parse, advisories, graph.
2. **Zip upload** (⬆ zip button): GitHub's "Download ZIP" or your own project folder zipped.
3. **Local folder path** (absolute path on the machine running Blast Radius): analysed in place.
4. **App URL only** (no code): a surface-only graph of the live API from its OpenAPI document, GraphQL schema and frontend bundles, with auth flags. Add the code later to get advisories and reachability.

Paste a public GitHub URL into the header of the UI. Blast Radius clones it, parses it, asks OSV for advisories, runs git blame, and loads a new FalkorDB graph (one graph per repo) with live progress. Supported: **Python** (FastAPI, Flask, Django URL tables and Django REST Framework routers; `poetry.lock`, `uv.lock`, pinned requirements) and **JavaScript/TypeScript** (Express-style routers, Next.js file routes, NestJS decorators; `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, advisories from OSV's npm feed). ORM models (SQLAlchemy, Django, Prisma, Mongoose, Sequelize) become `Table` nodes with `TOUCHES` edges so the agent can name the data at risk. Switch between analysed repos with the picker. **Private repositories:** set `GITHUB_TOKEN` (repo read scope) in `.env`; the token is used only for the clone and is not stored in the clone's remote URL.

## Run it

Requirements: Docker, Python 3.12+, an Anthropic API key.

```bash
git clone https://github.com/Rakesh9742/blast-radius.git && cd blast-radius
cp .env.example .env            # add ANTHROPIC_API_KEY (and optionally GITHUB_TOKEN + GITHUB_REPO=<your fork>)
make demo                       # venv + FalkorDB + clone mealie v3.0.0 + build graph (~1 min) + serve
```

Open http://localhost:8000. FalkorDB Browser is on http://localhost:3000 for raw Cypher.

Terminal mode:

```bash
make cli Q="Pillow has new CVEs. What is exposed, who owns it, fix it."
```

## What the agent does (Track 1 criteria)

| Criterion | How |
|---|---|
| Multi-hop reasoning | `reachability` runs `(:Package)<-[:USES]-(:Function)<-[:CALLS*0..4]-(:Function)-[:EXPOSES]->(:Entrypoint)` and returns ranked paths with a confidence derived from how each call edge was resolved. `transitive_exposure` walks `DEPENDS_ON*1..3`. |
| Graph queries and algorithms as agent tools | 20 tools; 9 are parameterised Cypher, 3 are FalkorDB graph algorithms (`algo.SPpaths`, `algo.betweenness` + `algo.pageRank`, `algo.BFS`), plus a read-only `run_cypher` escape hatch. |
| Tool selection through MCP | All 20 tools are exposed by a Model Context Protocol server; the agent discovers and calls them over MCP. The same server plugs into Claude Desktop. |
| Explainable results | The trace panel lists every Cypher query, row count and latency per tool call. The evidence graph highlights exactly the nodes and edges the agent touched. Decisions are persisted as `(:Vulnerability)-[:TRIAGED]->(:Decision)`. |
| Acts | `plan_fix` -> `verify_fix` (OSV) -> `apply_dependency_fix` (git branch + commit) -> `open_pull_request` (GitHub) or `write_triage_report` -> `record_triage_decision`. |

## Tools over MCP

Every tool the agent uses (20: graph queries, 3 FalkorDB algorithms, live-app status, data exposure, safe endpoint probes, actions) is served by `agent/mcp_server.py`, a Model Context Protocol server. The agent discovers the tool list from the server at start and calls tools through MCP (set `BLAST_TOOLS=direct` to bypass it). The same server works in Claude Desktop or Claude Code:

```json
{"mcpServers": {"blast-radius": {"command": "/path/to/blast-radius/.venv/bin/python", "args": ["-m", "agent.mcp_server"],
  "cwd": "/path/to/blast-radius", "env": {"BLAST_GRAPH": "mealie", "BLAST_REPO": "/path/to/blast-radius/data/repos/mealie"}}}}
```

Graph algorithm tools use FalkorDB procedures: `algo.SPpaths` (shortest attack paths), `algo.betweenness` + `algo.pageRank` (choke points), `algo.BFS` (impact radius).

A full real run with every MCP request, the Cypher each tool ran, and the response the model saw: [docs/example-tool-calls.md](docs/example-tool-calls.md).

## Layout

```
ingest/   parse_python.py (AST: files, classes, functions, calls, imports, route decorators -> Entrypoints)
          deps.py (poetry.lock -> packages + DEPENDS_ON; OSV querybatch + details)
          git_history.py (commits, authors, git blame line ownership per function)
          load.py / run.py (batched UNWIND MERGE into FalkorDB, indexes incl. full-text)
agent/    tools.py (Cypher tools + actions), loop.py (Claude tool-use loop with trace), cli.py
server/   app.py (FastAPI, SSE streaming of agent events, graph neighbourhood API)
web/      index.html (chat | Cytoscape evidence graph | reasoning trace)
```

## FalkorDB features used

Multi-graph (one graph per analysed repo or live site), variable-length path queries for reachability, `DEPENDS_ON` transitive closure, graph algorithms as agent tools (`algo.SPpaths` shortest attack paths, `algo.betweenness` + `algo.pageRank` choke points, `algo.BFS` blast radius), range indexes on every lookup key, full-text indexes on function source and advisory text, read-only query mode (`GRAPH.RO_QUERY`) for the agent's escape hatch, array properties for endpoint parameters and payload fields, and write-back of triage decisions so the graph is also the agent's memory.

## Data sources and licensing

- Code graphs are built only from **public** GitHub repositories (the demo uses mealie, AGPL-3.0). Nothing private, login-protected, or paywalled is loaded.
- Advisories come from the public [OSV.dev](https://osv.dev) API. Package versions from the repo's own lockfile.
- Ownership uses public commit metadata. Commit emails are **not stored**: authors are keyed by a short one-way hash; only the display name is kept.
- Live-app discovery reads only what a browser receives anonymously: the public OpenAPI document, GraphQL introspection if the server allows it, and the public JavaScript bundles. Nothing behind a login is fetched, no credentials are used, and endpoints are never probed unless the operator explicitly asserts authorization to the `probe_endpoints` tool. Only endpoint paths, methods, auth flags and parameter names are stored, never response data.

## Timeline

Prototype exploration (parser, agent loop, first UI) started on Oct 11, 2026, before the event window, to confirm the idea was feasible. The repository was created and all commits were made inside the Graph Hacks window (Oct 15-18, 2026). Work done during the window includes the live-app discovery for compiled frontends (nested bundles, framework detection, chunked LLM extraction with parameters and payloads), the Connect/Analyze separation with the mismatch guard, surface graphs with confirmed-call flags, the endpoint detail card, red/amber attention flags across graph, answer and report, the API-surface tour, zoom-aware graph labels, generated per-site scenarios, GitHub sub-folder analysis, and the regression and fresh-clone verification. This section exists so judges can assess rule 8 with full information.

## AI assistance disclosure

This project was built with an AI coding assistant (Claude Code, Anthropic). The agent inside the product runs on the Claude API. Design decisions, graph model, verification against real repositories, and the demo are the participant's responsibility; the participant can explain the graph model, the queries in `docs/queries.md`, and the architecture.
