"""Data-layer nodes: ORM models -> Table nodes, and which functions touch them.
Python: SQLAlchemy (__tablename__ / Base subclasses), Django (models.Model). JS: Prisma schema models, Mongoose models, Sequelize define()."""
from __future__ import annotations
import ast, pathlib, re

SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "migrations", "alembic", "tests", "test"}


def python_models(repo: pathlib.Path, source_dirs: list[str] | None, module_root: pathlib.Path | None) -> tuple[list[dict], dict[str, str]]:
    """Returns ([{table, model, file, kind}], {model class name -> table})."""
    mroot = module_root or repo
    out, by_class = [], {}
    for p in mroot.rglob("*.py"):
        rel = p.relative_to(mroot)
        if set(rel.parts) & SKIP or (source_dirs and rel.parts[0] not in source_dirs):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [ast.unparse(b) for b in node.bases]
            table = None; kind = None
            for st in node.body:
                if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in st.targets) and isinstance(st.value, ast.Constant):
                    table = str(st.value.value); kind = "sqlalchemy"
            if table is None and any(b.endswith("models.Model") or b == "Model" for b in bases):
                table = re.sub(r"(?<!^)(?=[A-Z])", "_", node.name).lower(); kind = "django"
            if table is None and any(b in ("SqlAlchemyBase", "Base", "DeclarativeBase", "SQLModel") for b in bases):
                table = re.sub(r"(?<!^)(?=[A-Z])", "_", node.name).lower(); kind = "sqlalchemy"
            if table:
                out.append({"table": table, "model": node.name, "file": str(p.relative_to(repo)), "kind": kind}); by_class[node.name] = table
    return out, by_class


def js_models(repo: pathlib.Path) -> tuple[list[dict], dict[str, str]]:
    out, by_name = [], {}
    for p in repo.rglob("schema.prisma"):
        if set(p.parts) & SKIP: continue
        for m in re.finditer(r"(?m)^model\s+(\w+)\s*\{", p.read_text(errors="ignore")):
            out.append({"table": m.group(1), "model": m.group(1), "file": str(p.relative_to(repo)), "kind": "prisma"}); by_name[m.group(1)] = m.group(1); by_name[m.group(1)[0].lower() + m.group(1)[1:]] = m.group(1)
    for p in list(repo.rglob("*.js")) + list(repo.rglob("*.ts")):
        if set(p.parts) & SKIP: continue
        txt = p.read_text(errors="ignore")
        for m in re.finditer(r"mongoose\.model\(\s*['\"](\w+)['\"]", txt):
            out.append({"table": m.group(1), "model": m.group(1), "file": str(p.relative_to(repo)), "kind": "mongoose"}); by_name[m.group(1)] = m.group(1)
        for m in re.finditer(r"sequelize\.define\(\s*['\"](\w+)['\"]", txt):
            out.append({"table": m.group(1), "model": m.group(1), "file": str(p.relative_to(repo)), "kind": "sequelize"}); by_name[m.group(1)] = m.group(1)
    return out, by_name


def function_table_uses(functions, by_class: dict[str, str]) -> list[tuple[str, str]]:
    """(function qualname, table) when the function's source references a model class name as a word."""
    if not by_class:
        return []
    pat = re.compile(r"\b(" + "|".join(re.escape(k) for k in sorted(by_class, key=len, reverse=True)) + r")\b")
    out = set()
    for fn in functions:
        for m in pat.finditer(fn.source or ""):
            out.add((fn.qualname, by_class[m.group(1)]))
    return sorted(out)
