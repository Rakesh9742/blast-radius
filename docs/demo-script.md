# Demo video script (target 3:00)

Record at 1600x900, UI at http://localhost:8000, FalkorDB Browser in a second tab. Fresh graph (`make ingest`, which also clears old decisions), repo reset (`make reset-repo`), server running (`make serve`). Hide the browser bookmarks bar.

## 0:00-0:30 Problem
- Point at the funnel tiles top-right: 329 advisories in the lockfile -> 123 in packages the code actually calls -> 30 high/critical reachable from an endpoint. Then the "Just dropped" feed underneath: newest advisory per package, each with a Triage button.
- Line: "A scanner gives you a list. A security engineer needs to know three things: is this reachable, from where, and who fixes it. Those are graph questions."

## 0:30-0:50 The graph
- FalkorDB Browser: run
  `MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)<-[:USES]-(f:Function) RETURN p.name, count(DISTINCT v), count(DISTINCT f) ORDER BY 2 DESC`
- Line: "Every function, call, import, endpoint, package, advisory and git-blame owner of the codebase is one graph in FalkorDB. Built in nine seconds."

## 0:50-2:10 Live triage (the core)
- Click "Pillow image CVEs".
- Narrate the phase bar (Identify -> Reach -> Owners -> Fix -> Act -> Record) and the numbered steps on the right as they fill: "Scan vulnerable packages", "Trace endpoints that reach pillow: 8 of 248", "Find owners", "Plan fix 11.3.0 -> 12.3.0", "Verify fix with OSV: clean", "Bump dependency on a branch", "Open pull request", "Record triage decision".
- Click one step card (the reachability one) to reveal the actual Cypher query and its latency. Line: "Every step is a graph query you can read."
- When the answer lands, the console narrates the attack path hop by hop, then about 2 s later the full-screen STORY opens by itself: Question -> Investigation (graph grows one agent step at a time, each with its Cypher) -> Attack path (hop by hop, narrated) -> Verdict with actions and a link to the full HTML report. It autoplays (~1.5 min); use -> to skip ahead, space to pause, Esc to return to the console. Add ?story=0 to the URL if you ever want to disable the auto-open.
- Open step 8 ("Bump dependency on a branch") to show the pyproject.toml diff in red/green.
- Scroll the answer to the top: red EXPLOITABLE badge, endpoints table with hops and confidence, attack path, owners (Hayden ~89% of minify.py), fix to 12.3.0 verified clean by OSV, branch + PR/report, and the note that 7 advisories were marked FIX_PROPOSED and 11 NOT_REACHABLE.

## 2:10-2:35 Act + memory
- Show the PR on GitHub (or the report file). The diff is already on screen in step 8.
- Point at the funnel's 4th tile ("Triaged by the agent, on the graph") ticking up, and the feed item now showing a green decision instead of a Triage button. Line: "The graph is also the agent's memory."

## 2:35-3:00 Why FalkorDB / wrap
- One sentence each: multi-hop in one query, sub-100 ms reachability over 1,251 functions, full-text + range indexes, read-only query mode for the agent's escape hatch, write-back of decisions.
- Close: "Blast Radius: from advisory to merged fix, with every hop explained."
