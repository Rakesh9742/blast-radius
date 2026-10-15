# From "pillow has 36 CVEs" to a merged fix: triaging vulnerabilities as a graph problem

*Built in four days for FalkorDB Graph Hacks, Track 1: agents that act on connected data.*

Every dependency scanner produces the same artifact: a list. For mealie, a popular open-source recipe manager, the v3.0.0 lockfile pins 142 Python packages, and OSV knows 329 published advisories against those exact versions. 89 are rated high or critical. Pillow alone has 36.

None of that is a decision. The engineer on call needs three answers the list cannot give:

1. Does our code actually call the vulnerable library, or is it only installed?
2. From which HTTP endpoints can an attacker reach that code?
3. Who owns it, and what is the smallest upgrade that clears every advisory?

Each of those is a path through connected data. So I built Blast Radius: an agent whose tools are graph queries, running on FalkorDB, that answers those questions and then acts on them.

## The graph

The ingestion step parses the repository with Python's `ast` module and loads one graph per repo:

```
(:Vulnerability)-[:AFFECTS]->(:Package)<-[:USES]-(:Function)<-[:CALLS*]-(:Function)-[:EXPOSES]->(:Entrypoint)
(:Package)-[:DEPENDS_ON]->(:Package)        from poetry.lock
(:Author)-[:OWNS {lines, share}]->(:Function)   from git blame
(:Author)-[:AUTHORED]->(:Commit)-[:MODIFIED]->(:File)
```

For mealie that is 1,251 functions, 248 FastAPI endpoints (router prefixes resolved across nested `include_router` calls), 2,886 call edges, including FastAPI `Depends()` injection resolved through the controller class hierarchy, 142 packages with 167 dependency edges, 329 advisories, and 1,823 ownership edges. FalkorDB loads all of it in about nine seconds with batched `UNWIND ... MERGE`.

Two details made the graph useful rather than decorative. First, import names are not package names: `PIL` is `pillow`, `jwt` is `pyjwt`, `multipart` is `python-multipart`. Second, frameworks mediate some usage: a FastAPI handler that takes `UploadFile` never imports python-multipart, but it is exactly the code a multipart parsing bug hits. A small table of implicit uses fixes that.

## One query that replaces an afternoon

The question "which endpoints can reach Pillow" is a variable-length path:

```cypher
MATCH (p:Package {name: 'pillow'})<-[:USES]-(sink:Function)
MATCH path = (h:Function)-[:CALLS*0..4]->(sink)
MATCH (h)-[:EXPOSES]->(e:Entrypoint)
RETURN e.id, sink.qualname, [n IN nodes(path) | n.qualname], length(path)
```

FalkorDB answers it in well under 200 ms over the full graph. The result: six endpoints, including `POST /api/recipes/{slug}/image`, `PUT /api/recipes/timeline/events/{item_id}/image` and `POST /api/users/{id}/image`, all funnelling into `PillowMinifier.minify` within two to four hops. The other 242 endpoints never touch Pillow. That is the blast radius.

Static call resolution is imperfect, so every `CALLS` edge records how it was resolved. A path made only of statically resolved edges is reported with high confidence; a path that relied on matching a method name alone is reported as medium and drawn dashed in the UI. The agent passes that confidence through to its verdict instead of hiding it.

## The agent

Claude drives a tool-use loop over 17 tools, all served by an MCP server so the model discovers and selects them rather than having them hard-coded. Nine are parameterised Cypher queries: vulnerability lookup, reachability, transitive exposure (`DEPENDS_ON*1..3`, which is how it explains that starlette matters even though nothing imports it directly), ownership, function detail, full-text code search, past decisions, and a read-only Cypher escape hatch for questions I did not anticipate. Three are FalkorDB graph algorithms: shortest attack paths with `algo.SPpaths`, choke points with `algo.betweenness` and `algo.pageRank`, and impact radius with `algo.BFS`. Five are actions: plan the fix (the lowest version that clears every advisory, cross-checked with PyPI), verify it against OSV, bump the constraint on a git branch, open a pull request, and write the decision back to the graph as a `(:Decision)` node.

That last tool matters more than it looks. The graph is not only the evidence; it is the agent's memory. Ask next week whether pillow was already triaged and the answer comes from the same database.

## Explainability by construction

The UI has three panels: the conversation, the evidence graph, and the reasoning trace. The trace lists every Cypher query the agent ran with its row count and latency. The graph highlights exactly the nodes and edges those queries touched. Nothing in the answer can come from anywhere else, because the model only sees tool results.

## What I would do next

Type-aware call resolution for `self.repo.get_one()`-style dispatch, a vector index on function docstrings for semantic search alongside the full-text index, and running the target's test suite in a sandbox after the bump.

Code: `<repo link>`. Demo video: `<link>`.
