# Cypher queries and graph algorithms the product depends on

All run against FalkorDB (one graph per analysed repository). `$pkg`, `$t`, etc. are query parameters. Source: `agent/tools.py`, `server/app.py`, `ingest/load.py`.

## Graph data model

| Node | Key | Properties |
|---|---|---|
| `Repo` | `name` | path, url, tag, ingested_at, dependency_source, source_dirs |
| `File` | `path` | module, loc, package |
| `Class` | `qualname` | name, module, file, lineno, bases |
| `Function` | `qualname` | name, module, file, cls, lineno, end_lineno, is_async, doc, source, is_handler |
| `Entrypoint` | `id` (`METHOD /path`) | method, path, router, live, source, operation_id, summary, auth_required, frontend_calls |
| `Package` | `name` | version, description, groups, direct |
| `Vulnerability` | `id` (GHSA/PYSEC) | cve, aliases, summary, details, severity, cvss, published, references |
| `Commit` | `sha` | short, date, subject |
| `Author` | `email` (hashed id) | name |
| `Decision` | `vuln` | status, reason, decided_at, by |
| `Table` | `name` | model, file, kind (sqlalchemy/django/prisma/mongoose/sequelize) |

| Edge | From → To | Properties |
|---|---|---|
| `CONTAINS` | Repo→File, File→Function/Class | |
| `HAS_METHOD` | Class→Function | |
| `CALLS` | Function→Function | `how` (self / import / local / unique / name-match / Depends) |
| `EXPOSES` | Function→Entrypoint | |
| `USES` | Function→Package | |
| `IMPORTS` | File→Package | |
| `DEPENDS_ON` | Repo→Package (`direct`), Package→Package | |
| `AFFECTS` | Vulnerability→Package | installed_version, fixed_version |
| `MODIFIED` | Commit→File | |
| `AUTHORED` | Author→Commit | |
| `OWNS` | Author→Function | lines, share, last_touched |
| `TRIAGED` | Vulnerability→Decision | |
| `DEFINES` | File→Table | |
| `TOUCHES` | Function→Table | |

Indexes: range indexes on every key above plus `Vulnerability.severity`; full-text indexes on `Function(name, doc, source)` and `Vulnerability(summary, details)`.

## 1. Reachability (the core multi-hop query)
Which public endpoints can reach code that uses a vulnerable package, with the call path and how each edge was resolved.
```cypher
MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function)
MATCH path = (h:Function)-[:CALLS*0..4]->(sink)
MATCH (h)-[:EXPOSES]->(e:Entrypoint)
RETURN e.id AS endpoint, sink.qualname AS sink,
       [n IN nodes(path) | n.qualname] AS functions,
       [r IN relationships(path) | r.how] AS resolution,
       length(path) AS hops
ORDER BY hops LIMIT 400
```
Confidence: `high` if no edge was resolved by `name-match`, else `medium`.

## 2. Transitive exposure (dependency chain)
```cypher
MATCH (p:Package {name: $pkg})<-[:DEPENDS_ON*1..3]-(parent:Package)
OPTIONAL MATCH (parent)<-[:USES]-(fn:Function)
OPTIONAL MATCH (fn)-[:EXPOSES]->(e:Entrypoint)
RETURN DISTINCT parent.name, parent.version, parent.direct,
       count(DISTINCT fn) AS functions_using_parent, count(DISTINCT e) AS endpoints_directly_in_handlers
```

## 3. Ownership (git blame on the graph)
```cypher
MATCH (a:Author)-[o:OWNS]->(fn:Function) WHERE fn.qualname = $t OR fn.file = $t
RETURN a.name, a.email AS author_id, sum(o.lines) AS lines,
       round(avg(o.share) * 100) / 100 AS avg_share, max(o.last_touched) AS last_touched
ORDER BY lines DESC LIMIT 6
```
```cypher
MATCH (a:Author)-[:AUTHORED]->(c:Commit)-[:MODIFIED]->(f:File {path: $f})
RETURN c.short, c.date, a.name, c.subject ORDER BY c.date DESC LIMIT 8
```

## 4. Shortest attack path (algorithm: `algo.SPpaths`)
```cypher
MATCH (h:Function {qualname: $h}), (p:Package {name: $pkg})
CALL algo.SPpaths({sourceNode: h, targetNode: p, relTypes: ['CALLS','USES'], maxLen: 8, pathCount: 1})
YIELD path, pathWeight
RETURN [n IN nodes(path) | coalesce(n.qualname, n.name)] AS nodes,
       [r IN relationships(path) | coalesce(r.how, type(r))] AS edges, pathWeight
```

## 5. Choke points (algorithms: `algo.betweenness`, `algo.pageRank`)
Functions on the attack paths, ranked by how many endpoints flow through them.
```cypher
MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function),
      path=(h:Function)-[:CALLS*0..5]->(sink), (h)-[:EXPOSES]->(e:Entrypoint)
UNWIND nodes(path) AS n
WITH n, collect(DISTINCT e.id) AS eps RETURN n.qualname AS fn, size(eps) AS endpoints_through_it
```
```cypher
CALL algo.betweenness({nodeLabels: ['Function'], relationshipTypes: ['CALLS']}) YIELD node, score
WHERE node.qualname IN $fns RETURN node.qualname AS fn, score
```
```cypher
CALL algo.pageRank('Function', 'CALLS') YIELD node, score
WHERE node.qualname IN $fns RETURN node.qualname AS fn, score
```

## 6. Impact radius (algorithm: `algo.BFS`)
```cypher
MATCH (f:Function {qualname: $f}) CALL algo.BFS(f, $d, 'CALLS') YIELD nodes
RETURN [n IN nodes | n.qualname] AS reached
```
```cypher
MATCH (c:Function)-[:CALLS*1..3]->(f:Function {qualname: $f})
OPTIONAL MATCH (c)-[:EXPOSES]->(e:Entrypoint)
RETURN count(DISTINCT c) AS callers, count(DISTINCT e) AS endpoints
```

## 7. Full-text search
```cypher
CALL db.idx.fulltext.queryNodes('Function', $q) YIELD node, score
RETURN node.qualname, node.file, node.lineno, left(node.doc, 160) AS doc, score ORDER BY score DESC LIMIT $lim
```

## 8. Write-back: the graph as the agent's memory
```cypher
UNWIND $ids AS id MATCH (v:Vulnerability {id: id})
MERGE (v)-[:TRIAGED]->(d:Decision {vuln: id})
SET d.status = $status, d.reason = $reason, d.decided_at = $at, d.by = 'blast-radius-agent'
RETURN v.id
```
```cypher
MATCH (v:Vulnerability)-[:TRIAGED]->(d:Decision) MATCH (v)-[:AFFECTS]->(p:Package)
WHERE $pkg = '' OR p.name = $pkg
RETURN v.id, p.name, d.status, d.reason, d.decided_at ORDER BY d.decided_at DESC LIMIT 25
```

## 9. Funnel (UI headline numbers)
```cypher
MATCH (v:Vulnerability) RETURN count(v)                                                   -- advisories
MATCH (v:Vulnerability)-[:AFFECTS]->(:Package)<-[:USES]-(:Function) RETURN count(DISTINCT v)   -- in packages the code calls
MATCH (p:Package {name: $pk})<-[:USES]-(f:Function), (h:Function)-[:CALLS*0..4]->(f), (h)-[:EXPOSES]->(e:Entrypoint)
RETURN DISTINCT e.id                                                                       -- per vulnerable package, endpoints exposed
```

## 10. Loading (batched upserts)
Every node and edge type is loaded with `UNWIND $rows AS r MERGE (...) SET ...` in batches of 500 (`ingest/load.py`), ~9 s for 13,900 nodes and edges. Read-only tools use `GRAPH.RO_QUERY`; only `record_triage_decision` writes.

## 11. Data at risk (tables on attack paths)
```cypher
MATCH (p:Package {name: $pkg})<-[:USES]-(sink:Function), path=(h:Function)-[:CALLS*0..4]->(sink), (h)-[:EXPOSES]->(e:Entrypoint)
UNWIND nodes(path) AS n MATCH (n)-[:TOUCHES]->(t:Table)
RETURN t.name AS table, count(DISTINCT e) AS endpoints_on_vulnerable_paths
```

## 12. Live deployment vs code (drift)
```cypher
MATCH (e:Entrypoint)
RETURN count(CASE WHEN e.live THEN 1 END) AS live,
       count(CASE WHEN e.source = 'openapi-only' THEN 1 END) AS only_in_deployment,
       count(CASE WHEN e.live IS NULL AND e.router <> 'live' THEN 1 END) AS only_in_code,
       count(CASE WHEN e.live AND NOT coalesce(e.auth_required, false) THEN 1 END) AS live_unauthenticated
```
