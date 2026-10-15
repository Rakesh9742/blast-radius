"""Load parsed data into FalkorDB with batched UNWIND/MERGE statements."""
from __future__ import annotations
import sys, time
from core.db import get_db

BATCH = 500


def _batches(rows, n=BATCH):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


class Loader:
    def __init__(self, graph_name: str, fresh: bool = True):
        self.db = get_db()
        if fresh and graph_name in self.db.list_graphs():
            self.db.select_graph(graph_name).delete()
        self.g = self.db.select_graph(graph_name)
        self.stats: dict[str, int] = {}

    def run(self, label: str, query: str, rows: list[dict]):
        t = time.time(); n = 0
        for b in _batches(rows):
            self.g.query(query, {"rows": b})
            n += len(b)
        self.stats[label] = n
        print(f"  {label:<28} {n:>6} rows  {time.time() - t:5.1f}s", flush=True)

    def indexes(self):
        for q in [
            "CREATE INDEX FOR (n:Function) ON (n.name)",
            "CREATE INDEX FOR (n:Function) ON (n.qualname)",
            "CREATE INDEX FOR (n:File) ON (n.path)",
            "CREATE INDEX FOR (n:Package) ON (n.name)",
            "CREATE INDEX FOR (n:Vulnerability) ON (n.id)",
            "CREATE INDEX FOR (n:Vulnerability) ON (n.severity)",
            "CREATE INDEX FOR (n:Entrypoint) ON (n.path)",
            "CREATE INDEX FOR (n:Author) ON (n.email)",
            "CREATE INDEX FOR (n:Commit) ON (n.sha)",
            "CREATE INDEX FOR (n:Class) ON (n.qualname)",
            "CREATE INDEX FOR (n:Table) ON (n.name)",
            "CREATE FULLTEXT INDEX FOR (n:Function) ON (n.name, n.doc, n.source)",
            "CREATE FULLTEXT INDEX FOR (n:Vulnerability) ON (n.summary, n.details)",
        ]:
            try:
                self.g.query(q)
            except Exception as e:  # index may already exist
                if "already" not in str(e).lower():
                    print("  index warning:", q, e, file=sys.stderr)


def load_all(graph_name: str, repo: dict, parsed, packages: dict, dep_edges, direct_deps: set[str], vulns, commits, authors, modified, ownership, tables=(), table_uses=()):
    L = Loader(graph_name)
    print(f"Loading graph '{graph_name}'")
    L.run("Repo", "UNWIND $rows AS r MERGE (x:Repo {name: r.name}) SET x += r", [repo])
    L.run("File", "UNWIND $rows AS r MERGE (f:File {path: r.path}) SET f.module = r.module, f.loc = r.loc, f.package = r.package "
          "WITH f MATCH (x:Repo {name: $rows[0].repo}) MERGE (x)-[:CONTAINS]->(f)",
          [{**f, "repo": repo["name"]} for f in parsed.files])
    L.run("Class", "UNWIND $rows AS r MERGE (c:Class {qualname: r.qualname}) SET c.name = r.name, c.module = r.module, c.file = r.file, c.lineno = r.lineno, c.bases = r.bases "
          "WITH c, r MATCH (f:File {path: r.file}) MERGE (f)-[:CONTAINS]->(c)", parsed.classes)
    handlers = {e["handler"] for e in parsed.entrypoints}
    fn_rows = [{"qualname": f.qualname, "name": f.name, "module": f.module, "file": f.file, "cls": f.cls or "", "lineno": f.lineno,
                "end_lineno": f.end_lineno, "is_async": f.is_async, "doc": f.doc, "source": f.source, "is_handler": f.qualname in handlers,
                "class_qualname": f"{f.module}.{f.cls}" if f.cls else ""} for f in parsed.functions]
    L.run("Function", "UNWIND $rows AS r MERGE (fn:Function {qualname: r.qualname}) SET fn.name = r.name, fn.module = r.module, fn.file = r.file, "
          "fn.cls = r.cls, fn.lineno = r.lineno, fn.end_lineno = r.end_lineno, fn.is_async = r.is_async, fn.doc = r.doc, fn.source = r.source, fn.is_handler = r.is_handler "
          "WITH fn, r MATCH (f:File {path: r.file}) MERGE (f)-[:CONTAINS]->(fn)", fn_rows)
    L.run("Class-HAS_METHOD", "UNWIND $rows AS r MATCH (c:Class {qualname: r.class_qualname}), (fn:Function {qualname: r.qualname}) MERGE (c)-[:HAS_METHOD]->(fn)",
          [r for r in fn_rows if r["class_qualname"]])
    L.run("CALLS", "UNWIND $rows AS r MATCH (a:Function {qualname: r.a}), (b:Function {qualname: r.b}) MERGE (a)-[c:CALLS]->(b) SET c.how = r.how",
          [{"a": a, "b": b, "how": h} for a, b, h in parsed.calls])
    L.run("Entrypoint", "UNWIND $rows AS r MERGE (e:Entrypoint {id: r.id}) SET e.method = r.method, e.path = r.path, e.router = r.router "
          "WITH e, r MATCH (fn:Function {qualname: r.handler}) MERGE (fn)-[:EXPOSES]->(e)",
          [{**e, "id": f"{e['method']} {e['path']}"} for e in parsed.entrypoints])
    L.run("Package", "UNWIND $rows AS r MERGE (p:Package {name: r.name}) SET p.version = r.version, p.description = r.description, p.groups = r.groups, p.direct = r.direct",
          [{**p, "direct": p["name"] in direct_deps} for p in packages.values()])
    L.run("Repo-DEPENDS_ON", "UNWIND $rows AS r MATCH (x:Repo {name: r.repo}), (p:Package {name: r.pkg}) MERGE (x)-[d:DEPENDS_ON]->(p) SET d.direct = r.direct",
          [{"repo": repo["name"], "pkg": p, "direct": p in direct_deps} for p in packages])
    L.run("Package-DEPENDS_ON", "UNWIND $rows AS r MATCH (a:Package {name: r.a}), (b:Package {name: r.b}) MERGE (a)-[:DEPENDS_ON]->(b)",
          [{"a": a, "b": b} for a, b in dep_edges])
    L.run("File-IMPORTS", "UNWIND $rows AS r MATCH (f:File {path: r.file}), (p:Package {name: r.pkg}) MERGE (f)-[:IMPORTS]->(p)",
          [{"file": f, "pkg": d} for f, d in parsed.file_imports if d in packages])
    L.run("Function-USES", "UNWIND $rows AS r MATCH (fn:Function {qualname: r.fn}), (p:Package {name: r.pkg}) MERGE (fn)-[:USES]->(p)",
          [{"fn": f, "pkg": d} for f, d in parsed.function_uses if d in packages])
    L.run("Vulnerability", "UNWIND $rows AS r MERGE (v:Vulnerability {id: r.id}) SET v.cve = r.cve, v.aliases = r.aliases, v.summary = r.summary, v.details = r.details, "
          "v.severity = r.severity, v.cvss = r.cvss, v.published = r.published, v.references = r.references "
          "WITH v, r MATCH (p:Package {name: r.package}) MERGE (v)-[a:AFFECTS]->(p) SET a.installed_version = r.installed_version, a.fixed_version = r.fixed_version",
          [{**v, "cve": v["cve"] or "", "fixed_version": v["fixed_version"] or ""} for v in vulns])
    L.run("Author", "UNWIND $rows AS r MERGE (a:Author {email: r.email}) SET a.name = r.name", authors)
    L.run("Commit", "UNWIND $rows AS r MERGE (c:Commit {sha: r.sha}) SET c.short = r.short, c.date = r.date, c.subject = r.subject "
          "WITH c, r MATCH (a:Author {email: r.author_email}) MERGE (a)-[:AUTHORED]->(c)", commits)
    L.run("Commit-MODIFIED", "UNWIND $rows AS r MATCH (c:Commit {sha: r.sha}), (f:File {path: r.file}) MERGE (c)-[:MODIFIED]->(f)",
          [{"sha": s, "file": f} for s, f in modified])
    L.run("Author-OWNS", "UNWIND $rows AS r MERGE (a:Author {email: r.email}) ON CREATE SET a.name = r.name "
          "WITH a, r MATCH (fn:Function {qualname: r.function}) MERGE (a)-[o:OWNS]->(fn) SET o.lines = r.lines, o.share = r.share, o.last_touched = r.last_touched",
          ownership)
    L.run("Table", "UNWIND $rows AS r MERGE (t:Table {name: r.table}) SET t.model = r.model, t.file = r.file, t.kind = r.kind "
          "WITH t, r MATCH (f:File {path: r.file}) MERGE (f)-[:DEFINES]->(t)", list(tables))
    L.run("Function-TOUCHES", "UNWIND $rows AS r MATCH (fn:Function {qualname: r.fn}), (t:Table {name: r.table}) MERGE (fn)-[:TOUCHES]->(t)",
          [{"fn": f, "table": t} for f, t in table_uses])
    L.indexes()
    return L.stats
