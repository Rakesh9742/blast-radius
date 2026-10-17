# Demo video: scenes and narration

The video is produced by a browser driver that performs the demo on the local console, shows each line as an on-screen caption while a text-to-speech voice reads it, then mixes the audio onto the screen recording (`scripts/record_demo.md` explains how to re-render it). Target length: about three and a half minutes.

| # | What is on screen | Narration |
|---|---|---|
| 1 | Console idle on the mealie graph; mouse over the four funnel tiles | A dependency scanner tells you this codebase has 329 advisories in its lockfile. It cannot tell you whether any of them matter. Blast Radius loads the whole repository into FalkorDB as one graph, and lets an agent walk it. Top right: 329 advisories, 123 in packages the code actually calls, 30 high or critical ones reachable from an HTTP endpoint. |
| 2 | "20 tools via MCP" badge, hover over graph nodes | Every file, function, call, route, package, advisory, data table and git-blame owner is a node or an edge in FalkorDB. All twenty agent tools are Cypher queries or FalkorDB graph algorithms, served to the agent over MCP. |
| 3 | Click "Pillow image CVEs"; phase bar lights up Identify, Reach, Owners, Fix, Act, Record while step cards fill on the right | Identify: eighteen advisories on Pillow, and the live deployment status. Reach: one variable-length path query walks from the package through the call graph to the HTTP handlers; SPpaths ranks the attack paths, betweenness and PageRank find the choke point. Owners: git blame on the graph. Fix: the safe version is verified against OSV. Act: dependency bumped on a branch, pull request opened on the fork. Record: the decision is written back into FalkorDB. |
| 4 | Answer scrolled to the top: red EXPLOITABLE badge, endpoints table, red "needs attention" lines | Verdict: exploitable. Eight endpoints pass uploaded or scraped images into Pillow with no format check. Anything that needs a human is flagged in red. |
| 5 | Reachability step card opened (Cypher, rows, latency); then the dependency-fix card with the pyproject diff | Every step is a real graph query you can read. And the fix is a real change: the pyproject diff the agent committed. |
| 6 | Evidence graph replays the attack path hop by hop with captions | The request enters at the upload endpoint, is handled by the controller, which calls the minifier, which reaches Pillow. |
| 7 | GitHub: the pull request on the fork | The pull request is real: Pillow 11.3.0 to 12.3.0, with advisories, reachable endpoints and owners in the description. |
| 8 | Console reloaded: "Triaged" tile reads 18, feed shows the decision | The graph is also the agent's memory. |
| 9 | Full-screen story: Question, Investigation, Attack path, Verdict | Every run also produces a story and an HTML report for reviewers. |
| 10 | Console | Blast Radius: from advisory to merged fix, with every hop explained, running on FalkorDB. github.com/Rakesh9742/blast-radius. |
