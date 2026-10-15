"""Parse poetry.lock into packages + dependency edges, and fetch vulnerabilities from OSV.dev."""
from __future__ import annotations
import json, pathlib, re, time
from concurrent.futures import ThreadPoolExecutor
import httpx
from packaging.version import Version, InvalidVersion

OSV = "https://api.osv.dev/v1"
CACHE = pathlib.Path(__file__).resolve().parent.parent / "data" / "cache"


def parse_poetry_lock(path: str | pathlib.Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """Returns ({name: {version, description, groups}}, [(pkg, depends_on_pkg)])."""
    txt = pathlib.Path(path).read_text(errors="ignore")
    blocks = re.split(r"(?m)^\[\[package\]\]\s*$", txt)[1:]
    pkgs, edges = {}, []
    for b in blocks:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', b)
        ver = re.search(r'(?m)^version\s*=\s*"([^"]+)"', b)
        if not name or not ver:
            continue
        n = name.group(1).lower()
        desc = re.search(r'(?m)^description\s*=\s*"([^"]*)"', b)
        groups = re.search(r'(?m)^groups\s*=\s*\[([^\]]*)\]', b)
        pkgs[n] = {"name": n, "version": ver.group(1), "description": (desc.group(1) if desc else "")[:200],
                   "groups": [g.strip().strip('"') for g in groups.group(1).split(",")] if groups else ["main"]}
        deps = re.search(r"(?ms)^\[package\.dependencies\]\s*\n(.*?)(?=^\[|\Z)", b)
        if deps:
            for line in deps.group(1).splitlines():
                m = re.match(r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=', line)
                if m:
                    edges.append((n, m.group(1).lower()))
    edges = [(a, b) for a, b in edges if b in pkgs]
    return pkgs, edges


def parse_uv_lock(path: str | pathlib.Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """uv.lock: [[package]] name/version blocks with dependencies = [{ name = "x" }, ...]."""
    txt = pathlib.Path(path).read_text(errors="ignore")
    blocks = re.split(r"(?m)^\[\[package\]\]\s*$", txt)[1:]
    pkgs, edges = {}, []
    for b in blocks:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', b); ver = re.search(r'(?m)^version\s*=\s*"([^"]+)"', b)
        if not name or not ver:
            continue
        n = name.group(1).lower()
        pkgs[n] = {"name": n, "version": ver.group(1), "description": "", "groups": ["main"]}
        deps = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)^\]", b)
        if deps:
            edges += [(n, m.group(1).lower()) for m in re.finditer(r'name\s*=\s*"([^"]+)"', deps.group(1))]
    return pkgs, [(a, b) for a, b in edges if b in pkgs]


def parse_requirements(paths: list[pathlib.Path]) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """Pinned requirements*.txt files (name==version). No dependency edges available."""
    pkgs = {}
    for p in paths:
        for line in p.read_text(errors="ignore").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#\\]*)", line)
            if m:
                n = m.group(1).lower().replace("_", "-")
                pkgs.setdefault(n, {"name": n, "version": m.group(2), "description": "", "groups": [p.name]})
    return pkgs, []


def parse_package_lock(path: pathlib.Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """npm package-lock.json v2/v3 ("packages") or v1 ("dependencies")."""
    d = json.loads(path.read_text(errors="ignore")); pkgs, edges = {}, []
    if "packages" in d:
        for key, meta in d["packages"].items():
            if not key or "node_modules/" not in key:
                continue
            name = key.split("node_modules/")[-1]
            if not meta.get("version"):
                continue
            pkgs.setdefault(name, {"name": name, "version": meta["version"], "description": "", "groups": ["dev"] if meta.get("dev") else ["main"]})
            edges += [(name, dep) for dep in list(meta.get("dependencies", {})) + list(meta.get("optionalDependencies", {}))]
    else:
        def rec(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    pkgs.setdefault(name, {"name": name, "version": meta["version"], "description": "", "groups": ["dev"] if meta.get("dev") else ["main"]})
                    edges.extend((name, dep) for dep in (meta.get("requires") or {}))
                    rec(meta.get("dependencies"))
        rec(d.get("dependencies"))
    return pkgs, [(a, b) for a, b in edges if b in pkgs]


def parse_yarn_lock(path: pathlib.Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    """yarn.lock v1: `"name@^1.0.0", name@~1:` header lines followed by `  version "x"`."""
    pkgs, edges, cur = {}, [], None
    for line in path.read_text(errors="ignore").splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            first = line.split(",")[0].strip().strip('"')
            cur = first.rsplit("@", 1)[0] if first.count("@") > (1 if first.startswith("@") else 0) else first
        elif cur and line.strip().startswith("version "):
            pkgs.setdefault(cur, {"name": cur, "version": line.split('"')[1], "description": "", "groups": ["main"]})
    return pkgs, edges


def parse_pnpm_lock(path: pathlib.Path) -> tuple[dict[str, dict], list[tuple[str, str]]]:
    pkgs = {}
    for m in re.finditer(r"(?m)^  /?('?)((?:@[^/]+/)?[^@'\s]+)@([0-9][^('\s:]*)", path.read_text(errors="ignore")):
        pkgs.setdefault(m.group(2), {"name": m.group(2), "version": m.group(3), "description": "", "groups": ["main"]})
    return pkgs, []


def _npm_lock(repo: pathlib.Path, find) -> tuple[dict, list, str] | None:
    for fname, fn in (("package-lock.json", parse_package_lock), ("yarn.lock", parse_yarn_lock), ("pnpm-lock.yaml", parse_pnpm_lock)):
        if (c := find(fname)):
            pk, ed = fn(c[0])
            if pk:
                for p_ in pk.values():
                    p_["ecosystem"] = "npm"
                return pk, ed, str(c[0].relative_to(repo))
    return None


def load_dependencies(repo: str | pathlib.Path, language: str = "python") -> tuple[dict[str, dict], list[tuple[str, str]], str]:
    """Find the dependency source matching the code language. Returns (packages, edges, source_description).
    Python: poetry.lock, uv.lock, pinned requirements. Node: package-lock.json, yarn.lock, pnpm-lock.yaml.
    A Python app with a JS frontend keeps its Python lockfile; the frontend's npm lock is ignored (and vice versa)."""
    repo = pathlib.Path(repo)
    skip = {".git", "node_modules", ".venv", "venv", "site-packages"}
    def find(name):
        return sorted((p for p in repo.rglob(name) if not (set(p.parts) & skip)), key=lambda p: len(p.parts))
    if language != "python":
        if (r := _npm_lock(repo, find)):
            return r
    if (c := find("poetry.lock")):
        pk, ed = parse_poetry_lock(c[0]); return pk, ed, str(c[0].relative_to(repo))
    if (c := find("uv.lock")):
        pk, ed = parse_uv_lock(c[0]); return pk, ed, str(c[0].relative_to(repo))
    reqs = [p for p in repo.rglob("*.txt") if (p.name.startswith("requirements") or p.parent.name == "requirements") and not (set(p.parts) & skip)]
    if reqs:
        pk, ed = parse_requirements(reqs)
        if pk:
            return pk, ed, ", ".join(sorted({p.name for p in reqs})[:4])
    if language == "python" and (r := _npm_lock(repo, find)):   # last resort: a Python repo with only an npm lock
        return r
    return {}, [], "no poetry.lock, uv.lock, pinned requirements or npm lockfile found"


def _cached_get(url: str) -> dict:
    key = CACHE / (re.sub(r"[^A-Za-z0-9]", "_", url) + ".json")
    if key.exists():
        return json.loads(key.read_text())
    for attempt in range(3):
        r = httpx.get(url, timeout=60)
        if r.status_code == 200:
            key.write_text(r.text)
            return r.json()
        time.sleep(1 + attempt)
    r.raise_for_status()


def _fixed_version(vuln: dict, pkg: str, current: str, ecosystem: str = "PyPI") -> str | None:
    fixes = []
    for a in vuln.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") != ecosystem or p.get("name", "").lower() != pkg.lower():
            continue
        for rng in a.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixes.append(ev["fixed"])
    try:
        cur = Version(current)
        cands = sorted((Version(f) for f in fixes if _safe(f) and Version(f) > cur))
        return str(cands[0]) if cands else (fixes[0] if fixes else None)
    except InvalidVersion:
        return fixes[0] if fixes else None


def _safe(v):
    try:
        Version(v); return True
    except InvalidVersion:
        return False


def _severity(vuln: dict) -> tuple[str, str]:
    label = (vuln.get("database_specific") or {}).get("severity", "")
    cvss = ""
    for s in vuln.get("severity", []):
        if s.get("type", "").startswith("CVSS"):
            cvss = s.get("score", "")
    if not label and cvss:
        m = re.search(r"CVSS:3\.\d/", cvss)
        label = "UNKNOWN"
    return (label or "UNKNOWN").upper(), cvss


def fetch_vulnerabilities(pkgs: dict[str, dict]) -> list[dict]:
    """Batch-query OSV for every pinned package, then fetch details for each hit."""
    names = sorted(pkgs)
    queries = [{"package": {"name": n, "ecosystem": pkgs[n].get("ecosystem", "PyPI")}, "version": pkgs[n]["version"]} for n in names]
    hits: dict[str, list[str]] = {}
    for i in range(0, len(queries), 500):
        r = httpx.post(f"{OSV}/querybatch", json={"queries": queries[i:i + 500]}, timeout=120)
        r.raise_for_status()
        for q, res in zip(queries[i:i + 500], r.json()["results"]):
            if res.get("vulns"):
                hits[q["package"]["name"]] = [v["id"] for v in res["vulns"]]
    out = []
    pairs = [(pkg, vid) for pkg, ids in hits.items() for vid in ids]
    with ThreadPoolExecutor(max_workers=12) as ex:
        details = dict(zip(pairs, ex.map(lambda pv: _cached_get(f"{OSV}/vulns/{pv[1]}"), pairs)))
    for pkg, vid in pairs:
            v = details[(pkg, vid)]
            sev, cvss = _severity(v)
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            out.append({
                "id": vid, "cve": cve, "aliases": aliases, "package": pkg, "installed_version": pkgs[pkg]["version"],
                "summary": (v.get("summary") or v.get("details", "")[:200]).strip(),
                "details": (v.get("details") or "")[:1500],
                "severity": sev, "cvss": cvss, "published": (v.get("published") or "")[:10],
                "fixed_version": _fixed_version(v, pkg, pkgs[pkg]["version"], pkgs[pkg].get("ecosystem", "PyPI")),
                "references": [r["url"] for r in v.get("references", [])[:3]],
            })
    return out


if __name__ == "__main__":
    import sys, collections
    pkgs, edges = parse_poetry_lock(sys.argv[1])
    print(f"packages={len(pkgs)} dep_edges={len(edges)}")
    vulns = fetch_vulnerabilities(pkgs)
    print(f"vulns={len(vulns)} severities={collections.Counter(v['severity'] for v in vulns)}")
    for v in [x for x in vulns if x['severity'] in ('HIGH','CRITICAL')][:8]:
        print(f"  {v['id']} {v['cve']} {v['package']}=={v['installed_version']} fixed={v['fixed_version']} :: {v['summary'][:70]}")
