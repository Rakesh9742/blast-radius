# Study guide: explain Blast Radius in your own words

Judges can reject a project the participant cannot explain (rules 12 and 13). Read this until you can answer each item without notes. Every answer is two to four sentences.

## 1. What problem does it solve?
A dependency scanner lists advisories; for mealie that is 329. A list is not a decision. Triage needs three answers: is the vulnerable code reachable, from which endpoints, and who owns it. Those are graph questions, so the graph is the agent's brain.

## 2. What is in the graph? (draw this on a whiteboard)
```
Vulnerability -AFFECTS-> Package <-USES- Function <-CALLS*- Function(handler) -EXPOSES-> Endpoint
Package -DEPENDS_ON-> Package          Author -OWNS-> Function          Vulnerability -TRIAGED-> Decision
```
Nodes: files, classes, functions, HTTP endpoints, packages, advisories, commits, authors, decisions. Built by parsing Python with the `ast` module, reading the lockfile, asking OSV for advisories, and running git blame. One FalkorDB graph per repository.

## 3. Why FalkorDB and not Postgres or a vector database?
The core question is a variable-length path: endpoint to vulnerable function across an unknown number of calls. In Cypher that is `[:CALLS*0..4]`, one line, under 200 ms. In SQL it is a recursive query per question. A vector store cannot answer "is X reachable from Y" at all. If you remove FalkorDB, nothing works: reachability, algorithms, ownership joins and the agent's memory all live there.

## 4. The one query to know by heart
```cypher
MATCH (p:Package {name:'pillow'})<-[:USES]-(sink:Function)
MATCH path = (h:Function)-[:CALLS*0..4]->(sink)
MATCH (h)-[:EXPOSES]->(e:Entrypoint)
RETURN e.id, [n IN nodes(path) | n.qualname], length(path)
```
Read it aloud: "find functions that use pillow, walk backwards up to four calls to a handler, and give me the endpoint that handler exposes."

## 5. What are the agent's tools?
21 tools served by our MCP server. Nine are Cypher queries (vulnerabilities, reachability, dependency chain, owners, read function, search, past decisions, read-only Cypher). Three are FalkorDB algorithms: `algo.SPpaths` for the shortest attack path, `algo.betweenness` plus `algo.pageRank` for choke points, `algo.BFS` for impact radius. One reads the connected live deployment (OpenAPI drift, unauthenticated endpoints), one maps data at risk (tables on attack paths), one does benign endpoint probes only when you confirm you own the app. Five are actions: plan the fix, verify it with OSV, bump on a git branch, open a PR or write a report, record the decision on the graph.

## 6. Where is MCP?
`agent/mcp_server.py` serves every tool over the Model Context Protocol. The agent (`agent/mcp_bridge.py`) connects, asks the server which tools exist, and Claude picks among them. Each result carries the Cypher it ran and the subgraph it touched, which is how the UI stays explainable across the process boundary. Claude Desktop can use the same server.

## 7. What does "confidence" mean?
Python call resolution is static and imperfect. Every `CALLS` edge records how it was resolved. If every edge on a path was resolved statically, the path is high confidence; if one was matched by method name only, it is medium and drawn dashed. The agent reports that instead of hiding it.

## 8. How does the agent act?
plan_fix finds the lowest version that clears every advisory and checks PyPI. verify_fix asks OSV whether that version is clean. apply_dependency_fix edits the pin on a branch and commits. open_pull_request pushes and opens the PR (or writes a report). record_triage_decision writes `(:Vulnerability)-[:TRIAGED]->(:Decision)` so the graph remembers.

## 9. Why is the graph also memory?
Decisions are stored on the graph next to the advisories. Next week, or the next engineer, asks "was pillow already triaged" and the answer comes from the same database with the reasons. No separate memory store.

## 10. What are the limits?
Python (FastAPI, Flask, Django, DRF) and JavaScript/TypeScript (Express, Next.js, NestJS) with pinned dependencies. Unpinned requirements give empty advisories, and the UI says so. Static call graphs miss dynamic dispatch. Tests are not run after the bump yet; CI does that on the PR.

## 11. What did the AI assistant do, and what did you do?
Say it plainly: the code was written with Claude Code. You chose the problem, the track, the graph model, the target repository, verified results against the real code (Pillow reachable through the image minifier, Polar clean), tested on six other repositories, and you can explain every piece in this guide. Rule 11 requires the disclosure; it is already in the README.

## Numbers to remember
mealie v3.0.0 · 1,251 functions · 248 endpoints · 142 packages · 329 advisories · pillow reaches 8 endpoints · python-multipart reaches the unauthenticated login form · pyjwt reaches 199 of 248 endpoints through `get_current_user` · graph builds in ~9 s · reachability query < 200 ms · full triage with fix in 30 to 60 s.
