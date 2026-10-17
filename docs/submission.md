# Submission text (WeMakeDevs panel)

**Project name:** Blast Radius

**Track:** Track 1 — Agents That Act on Connected Data

**Tagline:** A security-triage agent that walks a FalkorDB code graph to answer "which endpoints does this CVE actually reach, who owns that code, and what is the fix" — then applies the fix and opens the pull request.

**Repository:** https://github.com/Rakesh9742/blast-radius

**Demo video:** <paste YouTube/Drive link>

**Live deployment:** Local setup (one command, `make demo`), instructions in the README. FalkorDB runs in Docker; the console runs on http://localhost:8000.

## Description

A dependency scanner tells you a package in your lockfile has 36 advisories. It cannot tell you whether any of them matter. Blast Radius loads a repository into FalkorDB as one graph — files, classes, functions, call edges, HTTP routes, packages, OSV advisories, ORM tables and git-blame ownership — and lets a Claude agent reason over it through 20 tools served over MCP. Every tool is a Cypher query or a FalkorDB graph algorithm.

Given "Pillow has new CVEs", the agent walks Advisory -> Package -> Function -> calls -> Handler -> Endpoint (4 to 6 hops), ranks the exposed endpoints with `algo.SPpaths`, finds the choke-point function with betweenness and PageRank, names the owners from blame, verifies the fix version against OSV, bumps the dependency on a branch, opens a pull request on the fork, and writes its decision back into the graph so the next run remembers it. Every step shows the exact query, its row count and latency; the evidence graph animates the attack path hop by hop; a full-screen story and an HTML report are generated per run.

It also connects to the live deployment: OpenAPI, GraphQL introspection and the frontend bundles (including compiled Flutter/Vite apps, read by the LLM in chunks) are joined to the code graph, so the agent can say which exposed endpoints are actually deployed and callable without login, and flag drift between code and deployment.

## How FalkorDB is used (and why it is not decoration)

- One graph per analysed repository or live site (multi-graph).
- Variable-length path queries for reachability; transitive `DEPENDS_ON` closure for indirect exposure.
- Graph algorithms as agent tools: `algo.SPpaths` (shortest attack paths), `algo.betweenness` + `algo.pageRank` (choke points), `algo.BFS` (blast radius).
- Range indexes on every lookup key, full-text index over function source and docs.
- `GRAPH.RO_QUERY` for the agent's read-only ad-hoc queries; write-back of triage decisions as `Decision` nodes.
- Remove FalkorDB and nothing works: there is no other database.

All queries and the data model: `docs/queries.md`.

## Data

Public repositories (demo: mealie-recipes/mealie v3.0.0, AGPL-3.0), public OSV.dev advisories, public commit metadata with hashed emails, the public demo deployment. Nothing private or login-protected is loaded.

## Built with

Python, FastAPI, FalkorDB (Docker), Claude API (tool use, MCP), Cytoscape.js. Built with an AI coding assistant (Claude Code); disclosed in the README together with the project timeline.
