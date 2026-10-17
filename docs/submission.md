# Submission form answers (WeMakeDevs panel) — paste field by field

## Part 1 · Project details

**Project title**
Blast Radius — CVE triage on a FalkorDB code graph

**Description** (what problem, for whom)
Dependency scanners tell a team that a package in their lockfile has 36 advisories; they cannot tell whether any of them are reachable, from which HTTP endpoint, or who should fix it. Security engineers and backend maintainers spend hours answering those three questions by hand. Blast Radius loads the repository into FalkorDB as one graph (files, classes, functions, call edges, HTTP routes, packages, OSV advisories, ORM tables, git-blame ownership) and lets a Claude agent walk it through 20 tools served over MCP, every one of them a Cypher query or a FalkorDB algorithm. Given "Pillow has new CVEs", it finds the exposed endpoints with hop counts and confidence, names the owners, verifies the safe version against OSV, bumps the dependency on a branch, opens a real pull request, and writes the decision back into the graph so the next run remembers it. Every step shows the exact query, rows and latency; the evidence graph replays the attack path hop by hop; a story view and an HTML report are generated per run. It also connects to the live deployment (OpenAPI, GraphQL, or the compiled frontend bundles read by the LLM) to rank deployed, unauthenticated endpoints first. Works on Python (FastAPI, Flask, Django) and JavaScript/TypeScript (Express, Next.js, NestJS) repositories.

**Track**
Track 1 — Agents That Act on Connected Data

**Repository**
https://github.com/Rakesh9742/blast-radius

**Demo video** (must be YouTube, public or unlisted)
<paste the YouTube link after uploading ~/Desktop/blast-radius-demo.mp4 — see below>
Mirror: https://github.com/Rakesh9742/blast-radius/releases/download/v1.0-demo/blast-radius-demo.mp4

**Live demo or deployment**
Not hosted (it needs an Anthropic key and clones repositories). Complete local setup is one command, `make demo` (Docker FalkorDB + venv + graph build in ~30 s + console on http://localhost:8000), documented in the README and verified on a clean machine.

**How did you use FalkorDB in your project?**
FalkorDB is the only database and the thing the product runs on. One graph per analysed repository or live site (multi-graph): ~14,000 nodes/edges for the demo repo, built in under 30 seconds with batched UNWIND/MERGE. The core question is a variable-length path query, Vulnerability -> Package <- USES - Function <- CALLS*1..6 - Handler - EXPOSES -> Endpoint, which answers "which endpoints reach this package" in under 100 ms over 1,251 functions; a flat scanner cannot express it at all. Graph algorithms are agent tools: algo.SPpaths ranks the shortest attack paths per endpoint, algo.betweenness plus algo.pageRank find the choke-point function whose fix protects the most endpoints, algo.BFS gives the blast radius of a function. Transitive DEPENDS_ON closure explains indirect exposure (starlette through fastapi). Range indexes on every lookup key and a full-text index over function names, docstrings and source power code search. GRAPH.RO_QUERY gives the agent a safe ad-hoc query escape hatch, and triage decisions are written back as Decision nodes so the graph is also the agent's memory. Live-deployment facts (live, auth_required, parameters, payload fields) are stored as properties on the same Entrypoint nodes, so one query ranks deployed, unauthenticated, reachable endpoints first. All queries: docs/queries.md.

**Blog link**
https://github.com/Rakesh9742/blast-radius/blob/main/docs/blog.md
(if you have time, paste the same text into dev.to or Medium and use that link instead)

## Part 2 · Feedback

**What did you like about FalkorDB?**
One engine for everything the agent needs: Cypher, variable-length paths, graph algorithms (SPpaths, betweenness, PageRank, BFS) and full-text search, all callable from the same Python client, so every agent tool is one query. Multi-graph made "one graph per repository" trivial and let us switch repos live. Reachability over a 14k-element graph returns in tens of milliseconds, which is what makes an interactive agent loop possible. GRAPH.RO_QUERY is exactly the primitive you want when an LLM is allowed to write its own queries. Docker image up in seconds, the Browser on :3000 was great for debugging, and the whole stack runs on a laptop.

**What improvements would you like to see in FalkorDB?**
1) EXISTS { } subqueries are not supported, so some filters had to be rewritten as OPTIONAL MATCH + WHERE or split into several queries. 2) Variable-length path queries across a dense call graph can time out; we had to split "all packages at once" into per-package queries with a timeout. Better cost hints or a documented pattern for bounded path search would help. 3) The algorithm procedures (algo.SPpaths, betweenness, pageRank, BFS) are powerful but thinly documented: argument maps, return shapes and limits took trial and error. 4) A built-in way to see query plans with timings in the Browser (EXPLAIN/PROFILE output rendered) would speed up tuning. 5) The Python client would benefit from an async API and from typed helpers for procedure calls.

## After pasting

Upload the video to YouTube (unlisted): youtube.com/upload -> drag ~/Desktop/blast-radius-demo.mp4 -> title "Blast Radius: CVE triage on a FalkorDB code graph (Graph Hacks 2026)" -> Visibility: Unlisted -> copy the link into the Demo video field. Then save the submission; you can edit until Oct 18, 23:59 IST.
