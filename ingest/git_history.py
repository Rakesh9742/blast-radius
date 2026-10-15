"""Commits, authors, and line-level ownership (via git blame) for the parsed functions."""
from __future__ import annotations
import subprocess, pathlib, re
from collections import defaultdict
from datetime import datetime, timezone
import hashlib


def _aid(email: str) -> str:
    """Stable, non-reversible author id from the commit email; raw addresses are never stored in the graph."""
    return "author:" + hashlib.sha1(email.strip().lower().encode()).hexdigest()[:12]


def _git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def commits(repo: str | pathlib.Path, files: set[str], max_commits: int = 6000) -> tuple[list[dict], list[dict], list[tuple[str, str]]]:
    """Returns (commits, authors, [(sha, file)]) restricted to files we parsed."""
    out = _git(repo, "log", f"-n{max_commits}", "--name-only", "--no-merges", "--format=%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f%s")
    commits, modified, authors = [], [], {}
    for chunk in out.split("\x1e")[1:]:
        head, _, body = chunk.partition("\n")
        parts = head.split("\x1f")
        if len(parts) < 5:
            continue
        sha, name, email, date, subject = parts
        touched = [f for f in body.strip().splitlines() if f in files]
        if not touched:
            continue
        commits.append({"sha": sha, "short": sha[:8], "author_email": _aid(email), "date": date, "subject": subject[:200]})
        authors[_aid(email)] = {"email": _aid(email), "name": name}
        modified += [(sha, f) for f in touched]
    return commits, list(authors.values()), modified


def ownership(repo: str | pathlib.Path, functions: list) -> list[dict]:
    """git blame each file once; aggregate authored lines per function.
    Returns [{function, email, name, lines, last_touched}] with share computed per function."""
    by_file = defaultdict(list)
    for fn in functions:
        by_file[fn.file].append(fn)
    rows = []
    for path, fns in by_file.items():
        try:
            blame = _git(repo, "blame", "-w", "--line-porcelain", "HEAD", "--", path)
        except subprocess.CalledProcessError:
            continue
        line_author: dict[int, tuple[str, str, int]] = {}
        cur_mail = cur_name = None; cur_time = 0; lineno = None
        for line in blame.splitlines():
            m = re.match(r"^[0-9a-f]{40} \d+ (\d+)", line)
            if m:
                lineno = int(m.group(1)); continue
            if line.startswith("author "): cur_name = line[7:]
            elif line.startswith("author-mail "): cur_mail = line[12:].strip("<>").lower()
            elif line.startswith("author-time "): cur_time = int(line[12:])
            elif line.startswith("\t") and lineno is not None:
                line_author[lineno] = (cur_mail, cur_name, cur_time)
        for fn in fns:
            agg: dict[str, list] = {}
            for ln in range(fn.lineno, fn.end_lineno + 1):
                if ln in line_author:
                    mail, name, t = line_author[ln]
                    a = agg.setdefault(mail, [name, 0, 0])
                    a[1] += 1; a[2] = max(a[2], t)
            total = sum(a[1] for a in agg.values()) or 1
            for mail, (name, n, t) in agg.items():
                rows.append({"function": fn.qualname, "email": _aid(mail or ""), "name": name, "lines": n, "share": round(n / total, 3),
                             "last_touched": datetime.fromtimestamp(t, tz=timezone.utc).date().isoformat()})
    return rows


if __name__ == "__main__":
    import sys
    from ingest.parse_python import parse_repo
    r = parse_repo(sys.argv[1], source_dirs=["mealie"])
    files = {f["path"] for f in r.files}
    c, a, m = commits(sys.argv[1], files)
    print(f"commits={len(c)} authors={len(a)} modified_edges={len(m)}")
    own = ownership(sys.argv[1], r.functions[:200])
    print(f"ownership rows (first 200 fns)={len(own)}", own[:2])
