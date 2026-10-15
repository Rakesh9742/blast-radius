"""End-to-end ingestion: repo on disk -> FalkorDB graph.

usage: python -m ingest.run --repo data/repos/mealie --graph mealie --source-dirs mealie --route-prefix /api
"""
from __future__ import annotations
import argparse, json, pathlib, re, subprocess, time
from ingest.parse_python import parse_repo
from ingest.parse_js import parse_repo_js
from ingest.deps import load_dependencies, fetch_vulnerabilities
from ingest.git_history import commits, ownership
from ingest.load import load_all
from ingest.models import python_models, js_models, function_table_uses


def detect_language(repo: pathlib.Path) -> str:
    skip = {"node_modules", ".venv", "venv", ".git", "dist", "build", ".next"}
    py = js = 0
    for p in repo.rglob("*"):
        if set(p.parts) & skip or not p.is_file():
            continue
        if p.suffix == ".py": py += 1
        elif p.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"): js += 1
    return "python" if py >= js else "javascript"


def detect_js_dirs(repo: pathlib.Path) -> list[str]:
    cands = [d.name for d in repo.iterdir() if d.is_dir() and d.name in ("src", "app", "pages", "server", "api", "routes", "lib", "backend", "apps", "packages", "controllers", "services")]
    return cands


def direct_dependencies_js(repo: pathlib.Path) -> set[str]:
    out = set()
    for pj in sorted(repo.rglob("package.json"), key=lambda p: len(p.parts))[:5]:
        if "node_modules" in pj.parts:
            continue
        try:
            d = json.loads(pj.read_text(errors="ignore"))
        except Exception:
            continue
        for k in ("dependencies", "devDependencies"):
            out |= set((d.get(k) or {}).keys())
    return out


def detect_source_dirs(repo: pathlib.Path) -> list[str]:
    """Top-level python packages (dirs with __init__.py), excluding tests/docs/examples. Falls back to all .py files."""
    skip = {"tests", "test", "docs", "doc", "examples", "example", "scripts", "migrations", "alembic", "node_modules", ".venv", "venv", "frontend", "build", "dist"}
    pk = sorted(d.name for d in repo.iterdir() if d.is_dir() and (d / "__init__.py").exists() and d.name not in skip and not d.name.startswith("."))
    if pk:
        return pk
    # monorepo layout like backend/app: look one level down
    for sub in sorted(d for d in repo.iterdir() if d.is_dir() and d.name not in skip and not d.name.startswith(".")):
        inner = sorted(f"{sub.name}/{d.name}" for d in sub.iterdir() if d.is_dir() and (d / "__init__.py").exists() and d.name not in skip)
        if inner:
            return inner
    return []


def direct_dependencies(pyproject: pathlib.Path) -> set[str]:
    if not pyproject.exists():
        return set()
    txt = pyproject.read_text(errors="ignore")
    out = set()
    for sec in re.finditer(r"(?ms)^\[tool\.poetry(?:\.group\.[a-z]+)?\.dependencies\]\s*\n(.*?)(?=^\[|\Z)", txt):
        for line in sec.group(1).splitlines():
            m = re.match(r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=', line)
            if m and m.group(1).lower() != "python":
                out.add(m.group(1).lower())
    for sec in re.finditer(r"(?ms)^dependencies\s*=\s*\[(.*?)^\]", txt):
        for m in re.finditer(r'"([A-Za-z0-9_.\-]+)', sec.group(1)):
            out.add(m.group(1).lower())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--source-dirs", default="")
    ap.add_argument("--route-prefix", default="")
    ap.add_argument("--url", default="")
    args = ap.parse_args()
    repo = pathlib.Path(args.repo).resolve()
    t0 = time.time()

    lang = detect_language(repo)
    print(f"1/4 parsing {lang} ...", flush=True)
    if lang == "python":
        src = args.source_dirs.split(",") if args.source_dirs else detect_source_dirs(repo)
        print(f"    source dirs: {src or 'all'}")
        sub = src[0].split("/")[0] if src and "/" in src[0] else None     # monorepo: backend/app -> module root is repo/backend
        parsed = parse_repo(repo, source_dirs=[d.split("/")[-1] for d in src] if src else None, module_root=(repo / sub) if sub else None)
    else:
        src = args.source_dirs.split(",") if args.source_dirs else None   # JS: whole repo minus node_modules/dist/tests unless told otherwise
        print(f"    source dirs: {src or 'all (excluding node_modules, dist, tests)'}")
        parsed = parse_repo_js(repo, source_dirs=src)
    if args.route_prefix:
        for e in parsed.entrypoints:
            if not e["path"].startswith(args.route_prefix):
                e["path"] = args.route_prefix + e["path"]
    print(f"    files={len(parsed.files)} functions={len(parsed.functions)} calls={len(parsed.calls)} entrypoints={len(parsed.entrypoints)}")

    if lang == "python":
        tables, by_class = python_models(repo, [d.split("/")[-1] for d in src] if src else None, (repo / sub) if sub else None)
    else:
        tables, by_class = js_models(repo)
    table_uses = function_table_uses(parsed.functions, by_class)
    print(f"    data layer: {len(tables)} tables/models, {len(table_uses)} function->table references")

    print("2/4 dependencies + OSV ...", flush=True)
    packages, dep_edges, dep_source = load_dependencies(repo, lang)
    print(f"    dependency source: {dep_source}")
    pyprojects = sorted(repo.rglob("pyproject.toml"), key=lambda p: len(p.parts))
    direct = ((direct_dependencies(pyprojects[0]) if pyprojects else set()) if lang == "python" else direct_dependencies_js(repo)) & set(packages)
    if not direct and "requirements" in dep_source:
        direct = set(packages)   # a pinned requirements file lists direct dependencies by definition
    vulns = fetch_vulnerabilities(packages)
    print(f"    packages={len(packages)} direct={len(direct)} dep_edges={len(dep_edges)} vulns={len(vulns)}")

    print("3/4 git history + blame ...", flush=True)
    files = {f["path"] for f in parsed.files}
    cm, authors, modified = commits(repo, files)
    own = ownership(repo, parsed.functions)
    print(f"    commits={len(cm)} authors={len(authors)} modified={len(modified)} ownership_rows={len(own)}")

    print("4/4 loading into FalkorDB ...", flush=True)
    try:
        tag = subprocess.run(["git", "-C", str(repo), "describe", "--tags", "--always"], capture_output=True, text=True).stdout.strip()
    except Exception:
        tag = ""
    repo_row = {"name": args.graph, "path": str(repo), "url": args.url, "tag": tag, "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "dependency_source": dep_source, "source_dirs": src, "language": lang}
    stats = load_all(args.graph, repo_row, parsed, packages, dep_edges, direct, vulns, cm, authors, modified, own, tables, table_uses)
    print(f"done in {time.time() - t0:.1f}s; nodes/edges loaded: {sum(stats.values())}")


if __name__ == "__main__":
    main()
