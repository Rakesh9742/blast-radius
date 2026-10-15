"""Parse a Python repo into graph nodes/edges using the stdlib ast module.

Produces: File, Module, Class, Function nodes; CONTAINS, CALLS, IMPORTS (file->package),
USES (function->package), EXPOSES (function->entrypoint) edges.
"""
from __future__ import annotations
import ast
import pathlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

# import name -> PyPI distribution name, for the cases where they differ
IMPORT_TO_DIST = {
    "PIL": "pillow", "jwt": "pyjwt", "yaml": "pyyaml", "bs4": "beautifulsoup4",
    "multipart": "python-multipart", "dateutil": "python-dateutil", "slugify": "python-slugify",
    "ldap": "python-ldap", "dotenv": "python-dotenv", "pillow_heif": "pillow-heif",
    "recipe_scrapers": "recipe-scrapers", "ingredient_parser": "ingredient-parser-nlp",
    "text_unidecode": "text-unidecode", "paho": "paho-mqtt", "pydantic_settings": "pydantic-settings",
    "humps": "pyhumps", "psycopg2": "psycopg2-binary", "typing_extensions": "typing-extensions",
    "sqlalchemy": "sqlalchemy", "jinja2": "jinja2", "starlette": "starlette", "fastapi": "fastapi",
    "lxml_html_clean": "lxml-html-clean", "google": "google-api-python-client", "OpenSSL": "pyopenssl",
    "nacl": "pynacl", "Crypto": "pycryptodome", "markdown": "markdown", "dns": "dnspython",
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "alembic", "migrations", "frontend", "docs"}
ROUTER_RE = re.compile(r"(router|blueprint|^bp$|_bp$|^app$|^api$|^cli$)", re.I)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route", "websocket", "command"}
# source-text markers that imply use of a package even without a direct import (framework-mediated)
IMPLICIT_USES = {"UploadFile": "python-multipart", "File(": "python-multipart", "Form(": "python-multipart"}
GENERIC_NAMES = {"get", "set", "update", "create", "delete", "run", "main", "execute", "handle", "process", "__init__", "all", "one"}


@dataclass
class FunctionInfo:
    qualname: str          # module.Class.method or module.func
    name: str
    module: str
    file: str
    cls: str | None
    lineno: int
    end_lineno: int
    is_async: bool
    doc: str
    source: str
    calls: list[tuple[str, str | None]] = field(default_factory=list)   # (callee simple name, receiver: "self"|module alias|None)
    uses: set[str] = field(default_factory=set)                           # external import aliases referenced
    entrypoints: list[dict] = field(default_factory=list)


@dataclass
class ParseResult:
    files: list[dict] = field(default_factory=list)
    classes: list[dict] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    file_imports: list[tuple[str, str]] = field(default_factory=list)       # (file, dist)
    function_uses: list[tuple[str, str]] = field(default_factory=list)      # (func qualname, dist)
    calls: list[tuple[str, str, str]] = field(default_factory=list)         # (caller, callee, resolution)
    entrypoints: list[dict] = field(default_factory=list)
    unresolved_imports: dict[str, int] = field(default_factory=lambda: defaultdict(int))


def module_name(root: pathlib.Path, path: pathlib.Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _str(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _callee(node: ast.Call) -> tuple[str | None, str | None]:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id, None
    if isinstance(f, ast.Attribute):
        recv = f.value
        if isinstance(recv, ast.Name):
            return f.attr, recv.id
        if isinstance(recv, ast.Attribute):
            return f.attr, recv.attr
        if isinstance(recv, ast.Call):
            inner, _ = _callee(recv)
            return f.attr, inner
        return f.attr, None
    return None, None


def _depends_in(expr: ast.AST | None) -> list[tuple[str, str | None]]:
    """Depends(x) calls found anywhere inside an annotation expression, e.g. Annotated[User, Depends(get_user)]."""
    out = []
    if expr is None:
        return out
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "Depends" and node.args:
            dep = node.args[0]
            if isinstance(dep, ast.Name):
                out.append((dep.id, None))
            elif isinstance(dep, ast.Attribute) and isinstance(dep.value, ast.Name):
                out.append((dep.attr, dep.value.id))
    return out


def _module_dep_aliases(tree: ast.AST) -> dict[str, list[tuple[str, str | None]]]:
    """Module-level `CurrentUser = Annotated[User, Depends(get_user)]` -> {"CurrentUser": [("get_user", None)]}."""
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            deps = _depends_in(node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if deps and isinstance(t, ast.Name):
                    out[t.id] = deps
    return out


def _route_prefixes(tree: ast.AST) -> dict[str, str]:
    """router = APIRouter(prefix="/recipes") -> {"router": "/recipes"}; prefix may be a module-level constant."""
    consts = {t.id: _str(n.value) for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
              if isinstance(t, ast.Name) and _str(n.value) is not None}
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            fname = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if "Router" in fname or "Route" in fname or "Blueprint" in fname:
                prefix = ""
                for kw in node.value.keywords:
                    if kw.arg in ("prefix", "url_prefix"):
                        prefix = _str(kw.value) if _str(kw.value) is not None else consts.get(getattr(kw.value, "id", ""), "")
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = prefix
    return out


def _router_includes(tree: ast.AST, mod: str, internal_alias: dict[str, str]) -> list[tuple[str, str, str]]:
    """parent.include_router(child.router, prefix=X) -> [(parent_var, child_key "module.var", prefix)]"""
    consts = {t.id: _str(n.value) for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
              if isinstance(t, ast.Name) and _str(n.value) is not None}
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("include_router", "register_blueprint")):
            continue
        parent = node.func.value.id if isinstance(node.func.value, ast.Name) else None
        if not parent or not node.args:
            continue
        a = node.args[0]
        child = None
        if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name) and a.value.id in internal_alias:
            child = f"{internal_alias[a.value.id]}.{a.attr}"
        elif isinstance(a, ast.Name):
            child = internal_alias.get(a.id, f"{mod}.{a.id}")
        if not child:
            continue
        prefix = ""
        for kw in node.keywords:
            if kw.arg in ("prefix", "url_prefix"):
                prefix = _str(kw.value) if _str(kw.value) is not None else consts.get(getattr(kw.value, "id", ""), "")
        out.append((parent, child, prefix))
    return out


def _decorator_entrypoints(fn: ast.FunctionDef, prefixes: dict[str, str]) -> list[dict]:
    eps = []
    for d in fn.decorator_list:
        if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute):
            continue
        method = d.func.attr
        recv = d.func.value
        recv_name = recv.id if isinstance(recv, ast.Name) else getattr(recv, "attr", "")
        if method in HTTP_METHODS and (ROUTER_RE.search(recv_name) or method == "route"):
            path = _str(d.args[0]) if d.args else ""
            if path is None:
                path = ""
            methods = [method.upper()]
            if method in ("route", "api_route"):  # Flask / FastAPI generic route: methods=[...] kwarg, default GET
                methods = ["GET"]
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [m for m in (_str(x) for x in kw.value.elts) if m] or ["GET"]
            for m in methods:
                eps.append({"method": m, "path": path or "", "router": recv_name, "own_prefix": prefixes.get(recv_name, "")})
    return eps


def parse_repo(root: str | pathlib.Path, top_packages: set[str] | None = None, source_dirs: list[str] | None = None, module_root: str | pathlib.Path | None = None) -> ParseResult:
    """root: git repo root (file paths are relative to it). module_root: where import names start (e.g. repo/backend for backend/app)."""
    root = pathlib.Path(root).resolve()
    mroot = pathlib.Path(module_root).resolve() if module_root else root
    res = ParseResult()
    py_files = []
    for p in mroot.rglob("*.py"):
        rel = p.relative_to(mroot)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if source_dirs and rel.parts[0] not in source_dirs:
            continue
        py_files.append(p)
    top_packages = top_packages or {p.parts[0] for p in (f.relative_to(mroot) for f in py_files)}

    by_qualname: dict[str, FunctionInfo] = {}
    by_simple: dict[str, list[str]] = defaultdict(list)
    by_module_name: dict[tuple[str, str], str] = {}          # (module, funcname) -> qualname
    class_methods: dict[str, dict[str, str]] = defaultdict(dict)  # class qualname -> {method: qualname}
    file_internal_imports: dict[str, dict[str, str]] = {}     # file -> {alias: "module.symbol"}
    class_level_deps: dict[str, list[tuple[str, str | None]]] = {}   # class qualname -> Depends() targets declared as class attributes
    dep_aliases: dict[str, list[tuple[str, str | None]]] = {}        # "module.Alias" -> Depends() targets (Annotated type aliases)
    dj_entries: dict[str, list[tuple[str, ast.AST, str]]] = {}        # urls module -> [(route, view expr, kind)]
    dj_includes: dict[str, list[tuple[str, str]]] = {}                # urls module -> [(prefix, child urls module)]
    dj_aliases: dict[str, dict[str, str]] = {}                        # urls module -> internal alias map (for resolving views)
    pending_annots: list[tuple] = []                                   # (FunctionInfo, annotation Name id, file) resolved after all modules are read
    file_external_alias: dict[str, dict[str, str]] = {}       # file -> {alias: dist}
    router_own_prefix: dict[str, str] = {}                    # "module.var" -> own prefix
    router_parent: dict[str, tuple[str, str]] = {}            # child "module.var" -> (parent "module.var", include prefix)

    for p in py_files:
        try:
            src = p.read_text(errors="ignore")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        mod = module_name(mroot, p)
        lines = src.splitlines()
        res.files.append({"path": rel, "module": mod, "loc": len(lines), "package": rel.split("/")[0]})
        internal_alias, external_alias = {}, {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    alias = a.asname or top
                    if top in top_packages:
                        internal_alias[alias] = a.name
                    else:
                        external_alias[alias] = IMPORT_TO_DIST.get(top, top.lower().replace("_", "-"))
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    base = mod.split(".")
                    base = base[: len(base) - node.level + (0 if p.name == "__init__.py" else 0)]
                    if p.name != "__init__.py":
                        base = mod.split(".")[:-node.level]
                    else:
                        base = mod.split(".")[: len(mod.split(".")) - node.level + 1]
                    modname = ".".join(base + ([node.module] if node.module else []))
                    for a in node.names:
                        internal_alias[a.asname or a.name] = f"{modname}.{a.name}"
                    continue
                top = (node.module or "").split(".")[0]
                if top in top_packages:
                    for a in node.names:
                        internal_alias[a.asname or a.name] = f"{node.module}.{a.name}"
                elif top:
                    dist = IMPORT_TO_DIST.get(top, top.lower().replace("_", "-"))
                    for a in node.names:
                        external_alias[a.asname or a.name] = dist
                    external_alias.setdefault(top, dist)
        file_internal_imports[rel] = internal_alias
        file_external_alias[rel] = external_alias
        for dist in sorted(set(external_alias.values())):
            res.file_imports.append((rel, dist))

        for alias, deps in _module_dep_aliases(tree).items():
            dep_aliases[f"{mod}.{alias}"] = deps
        # Django: path()/re_path()/url() entries, include(), DRF router.register()
        dj_e, dj_i = [], []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if fname in ("path", "re_path", "url") and len(node.args) >= 2 and _str(node.args[0]) is not None:
                route = _str(node.args[0]); view = node.args[1]
                if isinstance(view, ast.Call) and getattr(view.func, "id", "") == "include":
                    tgt = view.args[0] if view.args else None
                    if tgt is not None and _str(tgt) is not None:
                        dj_i.append((route, _str(tgt)))
                    elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) and tgt.value.id in internal_alias:
                        dj_i.append((route, internal_alias[tgt.value.id]))
                    elif isinstance(tgt, ast.Tuple) and tgt.elts and _str(tgt.elts[0]) is not None:
                        dj_i.append((route, _str(tgt.elts[0])))
                elif isinstance(view, ast.Call) and getattr(view.func, "id", "") == "include":
                    pass
                else:
                    dj_e.append((route, view, "django"))
            elif fname == "register" and isinstance(node.func, ast.Attribute) and len(node.args) >= 2 and _str(node.args[0]) is not None and ROUTER_RE.search(getattr(node.func.value, "id", "")):
                dj_e.append((_str(node.args[0]), node.args[1], "drf"))
        if dj_e or dj_i:
            dj_entries[mod] = dj_e; dj_includes[mod] = dj_i; dj_aliases[mod] = internal_alias
        prefixes = _route_prefixes(tree)
        for var, pre in prefixes.items():
            router_own_prefix[f"{mod}.{var}"] = pre
        for parent_var, child_key, inc_prefix in _router_includes(tree, mod, internal_alias):
            router_parent.setdefault(child_key, (f"{mod}.{parent_var}", inc_prefix))

        def class_deps(cls: ast.ClassDef) -> list[tuple[str, str | None]]:
            """class attributes like `user: PrivateUser = Depends(get_current_user)` apply to every handler method."""
            out = []
            for node in cls.body:
                val = getattr(node, "value", None)
                if isinstance(node, (ast.AnnAssign, ast.Assign)) and isinstance(val, ast.Call) and getattr(val.func, "id", getattr(val.func, "attr", "")) == "Depends":
                    dep = val.args[0] if val.args else getattr(node, "annotation", None)
                    if isinstance(dep, ast.Name):
                        out.append((dep.id, None))
                    elif isinstance(dep, ast.Attribute) and isinstance(dep.value, ast.Name):
                        out.append((dep.attr, dep.value.id))
            return out

        def visit_fn(fn: ast.FunctionDef | ast.AsyncFunctionDef, cls: ast.ClassDef | None):
            qual = f"{mod}.{cls.name + '.' if cls else ''}{fn.name}"
            doc = ast.get_docstring(fn) or ""
            seg = "\n".join(lines[fn.lineno - 1: fn.end_lineno])
            info = FunctionInfo(qual, fn.name, mod, rel, cls.name if cls else None, fn.lineno, fn.end_lineno,
                                isinstance(fn, ast.AsyncFunctionDef), doc[:500], seg[:4000])
            info.entrypoints = _decorator_entrypoints(fn, prefixes)
            # FastAPI dependency injection: `x: T = Depends(f)` is a call to f; `x: Cls = Depends()` is a call to Cls (-> __init__)
            pos = fn.args.posonlyargs + fn.args.args
            for arg in pos + fn.args.kwonlyargs:
                info.calls.extend(_depends_in(arg.annotation))          # x: Annotated[T, Depends(f)]
                ann = arg.annotation
                if isinstance(ann, ast.Name):
                    pending_annots.append((info, ann.id, rel))           # x: CurrentUser  (alias defined here or imported)
                elif isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name) and ann.value.id == "Annotated":
                    for inner in getattr(ann.slice, "elts", [ann.slice]):
                        if isinstance(inner, ast.Name):
                            pending_annots.append((info, inner.id, rel))
            pairs = list(zip(pos[len(pos) - len(fn.args.defaults):], fn.args.defaults)) + [(a, d) for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults) if d is not None]
            for arg, dflt in pairs:
                if not (isinstance(dflt, ast.Call) and getattr(dflt.func, "id", getattr(dflt.func, "attr", "")) == "Depends"):
                    continue
                dep = dflt.args[0] if dflt.args else arg.annotation
                if isinstance(dep, ast.Name):
                    info.calls.append((dep.id, None))
                elif isinstance(dep, ast.Attribute) and isinstance(dep.value, ast.Name):
                    info.calls.append((dep.attr, dep.value.id))
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    name, recv = _callee(node)
                    if name:
                        info.calls.append((name, recv))
                if isinstance(node, ast.Name) and node.id in external_alias:
                    info.uses.add(node.id)
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in external_alias:
                    info.uses.add(node.value.id)
            for marker, dist in IMPLICIT_USES.items():
                if marker in seg:
                    external_alias.setdefault(f"__implicit_{dist}", dist)
                    info.uses.add(f"__implicit_{dist}")
            by_qualname[qual] = info
            by_simple[fn.name].append(qual)
            by_module_name[(mod, fn.name)] = qual
            if cls:
                class_methods[f"{mod}.{cls.name}"][fn.name] = qual
            res.functions.append(info)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_fn(node, None)
            elif isinstance(node, ast.ClassDef):
                class_level_deps[f"{mod}.{node.name}"] = class_deps(node)
                bases = [ast.unparse(b) for b in node.bases]
                res.classes.append({"qualname": f"{mod}.{node.name}", "name": node.name, "module": mod, "file": rel,
                                    "lineno": node.lineno, "bases": bases})
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit_fn(sub, node)

    # class inheritance map for self.method() resolution through bases
    class_bases = {c["qualname"]: c["bases"] for c in res.classes}
    class_by_simple = defaultdict(list)
    for c in res.classes:
        class_by_simple[c["name"]].append(c["qualname"])

    def resolve_in_class(cls_qual: str, method: str, depth=0) -> str | None:
        if method in class_methods.get(cls_qual, {}):
            return class_methods[cls_qual][method]
        if depth > 4:
            return None
        for b in class_bases.get(cls_qual, []):
            simple = b.split(".")[-1].split("[")[0]
            for cq in class_by_simple.get(simple, []):
                r = resolve_in_class(cq, method, depth + 1)
                if r:
                    return r
        return None

    # ---- Django URL resolution (after every module is known)
    def _dj_norm(route: str) -> str:
        r = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", route)                 # <int:pk> -> {pk}
        r = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", r)                  # (?P<pk>[0-9]+) -> {pk}
        r = re.sub(r"\([^)]*\)", "{p}", r).replace("^", "").replace("$", "").replace("\\", "")
        return "/" + r.strip("/")
    dj_parent: dict[str, tuple[str, str]] = {}
    for parent, incs in dj_includes.items():
        for prefix, child in incs:
            dj_parent.setdefault(child, (parent, prefix))
    def _dj_prefix(m: str, depth=0) -> str:
        if depth > 10 or m not in dj_parent:
            return ""
        pm, pre = dj_parent[m]
        return (_dj_prefix(pm, depth + 1).rstrip("/") + _dj_norm(pre)).rstrip("/")
    DRF = {"list": ["GET", ""], "create": ["POST", ""], "retrieve": ["GET", "/{pk}"], "update": ["PUT", "/{pk}"], "partial_update": ["PATCH", "/{pk}"], "destroy": ["DELETE", "/{pk}"]}
    for m, entries in dj_entries.items():
        base = _dj_prefix(m)
        alias_map = dj_aliases[m]
        for route, view, kind in entries:
            full = (base.rstrip("/") + _dj_norm(route)).rstrip("/") or "/"
            targets: list[tuple[str, str]] = []      # (qualname, method)
            cls_key = None
            if isinstance(view, ast.Call) and getattr(view.func, "attr", "") == "as_view" and isinstance(view.func.value, ast.Name):
                cls_key = alias_map.get(view.func.value.id, f"{m}.{view.func.value.id}")
            elif isinstance(view, ast.Name):
                q = alias_map.get(view.id, f"{m}.{view.id}")
                if q in by_qualname:
                    targets.append((q, "ANY"))
                else:
                    cls_key = q
            elif isinstance(view, ast.Attribute) and isinstance(view.value, ast.Name):
                tm = alias_map.get(view.value.id, f"{m}.{view.value.id}")
                q = by_module_name.get((tm, view.attr)) or f"{tm}.{view.attr}"
                if q in by_qualname:
                    targets.append((q, "ANY"))
                else:
                    cls_key = q
            if cls_key and cls_key in class_methods:
                methods = class_methods[cls_key]
                if kind == "drf":
                    for mname, (http, suffix) in DRF.items():
                        if mname in methods:
                            targets.append((methods[mname], http + " " + suffix))
                    for mname, q in methods.items():      # @action(detail=...) custom routes
                        if mname not in DRF and mname not in ("get_queryset", "get_serializer_class", "get_permissions", "perform_create", "perform_update", "perform_destroy", "get_object", "get_serializer"):
                            fi = by_qualname[q]
                            if any("action" in ast.unparse(d) for d in (ast.parse(fi.source.lstrip() if fi.source.lstrip().startswith(("def", "async", "@")) else "def _x(): pass").body[0].decorator_list if hasattr(ast.parse(fi.source.lstrip() if fi.source.lstrip().startswith(("def", "async", "@")) else "def _x(): pass").body[0], "decorator_list") else [])):
                                targets.append((q, f"ANY /{mname.replace('_', '-')}"))
                else:
                    hit = False
                    for mname in ("get", "post", "put", "patch", "delete"):
                        if mname in methods:
                            targets.append((methods[mname], mname.upper())); hit = True
                    if not hit and methods:
                        targets.append((next(iter(methods.values())), "ANY"))
            for q, http in targets:
                info = by_qualname.get(q)
                if not info:
                    continue
                method, _, suffix = http.partition(" ")
                info.entrypoints.append({"method": method, "path": (full + suffix.strip()) if suffix.strip() else full, "router": "django" if kind == "django" else "drf"})

    # type-alias dependencies: `auth: CurrentUser` where CurrentUser = Annotated[..., Depends(f)] in this or another module
    for info, name, rel in pending_annots:
        key = file_internal_imports[rel].get(name, f"{info.module}.{name}")
        if key in dep_aliases:
            info.calls.extend(dep_aliases[key])

    # inherited class-level Depends() apply to every handler method of the class and its subclasses
    def inherited_deps(cls_qual: str, depth=0) -> list:
        out = list(class_level_deps.get(cls_qual, []))
        if depth < 5:
            for b in class_bases.get(cls_qual, []):
                for cq in class_by_simple.get(b.split(".")[-1].split("[")[0], []):
                    out += inherited_deps(cq, depth + 1)
        return out
    for info in res.functions:
        if info.cls and info.entrypoints:
            info.calls.extend(inherited_deps(f"{info.module}.{info.cls}"))

    # resolve calls
    for info in res.functions:
        internal_alias = file_internal_imports[info.file]
        external_alias = file_external_alias[info.file]
        seen = set()
        for name, recv in info.calls:
            target, how = None, None
            if recv in ("self", "cls") and info.cls:
                target = resolve_in_class(f"{info.module}.{info.cls}", name)
                how = "self"
            elif recv and recv in internal_alias:
                # module alias: from mealie.services import foo -> foo.bar()
                target_mod = internal_alias[recv]
                target = by_module_name.get((target_mod, name)) or (f"{target_mod}.{name}" if f"{target_mod}.{name}" in by_qualname else None)
                if not target:  # alias might be a class: Cls.method()
                    target = class_methods.get(target_mod, {}).get(name)
                how = "import"
            elif recv and recv in external_alias:
                info.uses.add(recv)
                continue
            elif recv is None:
                if name in internal_alias:
                    target = internal_alias[name] if internal_alias[name] in by_qualname else None
                    if not target:  # imported class instantiation -> __init__
                        target = class_methods.get(internal_alias[name], {}).get("__init__")
                    how = "import"
                elif (info.module, name) in by_module_name:
                    target = by_module_name[(info.module, name)]
                    how = "local"
                elif name in external_alias:
                    info.uses.add(name)
                    continue
            if not target and recv is None and len(by_simple.get(name, [])) == 1:
                target = by_simple[name][0]
                how = "unique"
            if not target and recv and recv not in ("self", "cls") and name in by_simple and len(by_simple[name]) == 1:
                target = by_simple[name][0]
                how = "unique-attr"
            if not target and recv not in ("self", "cls") and name not in GENERIC_NAMES and 1 <= len(by_simple.get(name, [])) <= 8:
                for cand in by_simple[name]:
                    if cand != info.qualname and cand not in seen:
                        seen.add(cand)
                        res.calls.append((info.qualname, cand, "name-match"))
                continue
            if target and target != info.qualname and target not in seen:
                seen.add(target)
                res.calls.append((info.qualname, target, how))
        for alias in sorted(info.uses):
            res.function_uses.append((info.qualname, external_alias[alias]))
        for ep in info.entrypoints:
            # the router/blueprint variable may be imported from another module: resolve to where it was defined
            if ep["router"] in ("django", "drf", "nest", "next"):
                res.entrypoints.append({"method": ep["method"], "path": ep["path"] or "/", "router": ep["router"], "handler": info.qualname, "file": info.file}); continue
            key = file_internal_imports[info.file].get(ep["router"], f"{info.module}.{ep['router']}")
            full = _full_prefix(key, router_own_prefix, router_parent) + ep["path"]
            res.entrypoints.append({"method": ep["method"], "path": full or "/", "router": ep["router"], "handler": info.qualname, "file": info.file})
    return res


def _full_prefix(key: str, own: dict[str, str], parent: dict[str, tuple[str, str]], depth: int = 0) -> str:
    pre = own.get(key, "")
    if depth > 10 or key not in parent:
        return pre
    pkey, inc = parent[key]
    return _full_prefix(pkey, own, parent, depth + 1) + inc + pre


if __name__ == "__main__":
    import sys, collections
    r = parse_repo(sys.argv[1], source_dirs=sys.argv[2].split(",") if len(sys.argv) > 2 else None)
    print(f"files={len(r.files)} classes={len(r.classes)} functions={len(r.functions)} calls={len(r.calls)} "
          f"file_imports={len(r.file_imports)} function_uses={len(r.function_uses)} entrypoints={len(r.entrypoints)}")
    print("call resolution:", collections.Counter(h for _, _, h in r.calls))
    print("top external dists:", collections.Counter(d for _, d in r.function_uses).most_common(15))
    print("sample entrypoints:", r.entrypoints[:5])
