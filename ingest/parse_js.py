"""Parse a JavaScript / TypeScript repo into the same graph shape as parse_python, using tree-sitter.

Covers: functions, class methods, arrow functions bound to names, imports (ESM + require), calls, external package usage,
Express-style routes (app/router.get|post|..., app.use('/prefix', router)), Next.js file routes (pages/api/**, app/api/**/route.*),
NestJS decorators (@Controller('x') + @Get('y')).
"""
from __future__ import annotations
import pathlib, re
from collections import defaultdict
from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs, tree_sitter_typescript as tsts
from ingest.parse_python import FunctionInfo, ParseResult, GENERIC_NAMES

LANGS = {".js": Language(tsjs.language()), ".jsx": Language(tsjs.language()), ".mjs": Language(tsjs.language()), ".cjs": Language(tsjs.language()),
         ".ts": Language(tsts.language_typescript()), ".tsx": Language(tsts.language_tsx())}
SKIP_DIRS = {"node_modules", "dist", "build", ".next", "out", "coverage", ".git", "vendor", "public", "__tests__", "test", "tests", "e2e", "cypress", "storybook", ".storybook"}
HTTP = {"get", "post", "put", "patch", "delete", "all", "head", "options"}
ROUTER_RE = re.compile(r"(router|^app$|^api$|^server$|^r$|routes?$)", re.I)
NEST_METHODS = {"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "All": "ANY"}
GENERIC_JS = GENERIC_NAMES | {"then", "catch", "map", "filter", "forEach", "push", "json", "send", "status", "log", "error", "warn", "info", "find", "findOne", "save", "toString", "length", "keys", "values", "stringify", "parse", "resolve", "reject", "next", "on", "emit", "use", "require", "default"}


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(errors="ignore")


def _str(node, src) -> str | None:
    if node is None:
        return None
    if node.type in ("string", "template_string"):
        t = _text(node, src)
        return t[1:-1] if len(t) >= 2 else ""
    return None


def _dist(spec: str) -> str | None:
    """'@scope/pkg/sub' -> '@scope/pkg'; 'lodash/fp' -> 'lodash'; relative/alias -> None."""
    if spec.startswith((".", "/", "@/", "~", "#")) or spec.startswith("node:"):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]


def _module_name(root: pathlib.Path, p: pathlib.Path) -> str:
    rel = p.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "index":
        parts = parts[:-1]
    return ".".join(parts) or "index"


def _resolve_relative(cur_mod: str, spec: str, is_index_file: bool) -> str:
    base = cur_mod.split(".") if cur_mod != "index" else []
    if not is_index_file:
        base = base[:-1]
    for seg in spec.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            base = base[:-1]
        else:
            base.append(re.sub(r"\.(js|jsx|ts|tsx|mjs|cjs)$", "", seg))
    if base and base[-1] == "index":
        base = base[:-1]
    return ".".join(base) or "index"


def _next_route(rel: str) -> tuple[str, str] | None:
    """Next.js file-based API routes -> (path, kind)."""
    m = re.match(r"^(?:src/)?pages/api/(.+)\.(?:js|jsx|ts|tsx)$", rel)
    if m:
        p = "/api/" + m.group(1); p = re.sub(r"/index$", "", p); return re.sub(r"\[\.\.\.(\w+)\]", r"{\1}", re.sub(r"\[(\w+)\]", r"{\1}", p)), "pages"
    m = re.match(r"^(?:src/)?app/(.+?)/route\.(?:js|ts)$", rel)
    if m:
        return re.sub(r"\[\.\.\.(\w+)\]", r"{\1}", re.sub(r"\[(\w+)\]", r"{\1}", "/" + m.group(1))), "app"
    return None


def parse_repo_js(root: str | pathlib.Path, source_dirs: list[str] | None = None, module_root: str | pathlib.Path | None = None) -> ParseResult:
    root = pathlib.Path(root).resolve(); mroot = pathlib.Path(module_root).resolve() if module_root else root
    res = ParseResult()
    files = []
    for p in mroot.rglob("*"):
        if p.suffix not in LANGS or not p.is_file():
            continue
        rel = p.relative_to(mroot)
        if any(part in SKIP_DIRS for part in rel.parts) or re.search(r"\.(test|spec|stories|d)\.(js|jsx|ts|tsx)$", p.name) or p.name.endswith(".min.js"):
            continue
        if source_dirs and rel.parts[0] not in source_dirs:
            continue
        files.append(p)

    by_qualname: dict[str, FunctionInfo] = {}; by_simple: dict[str, list[str]] = defaultdict(list); by_module_name: dict[tuple[str, str], str] = {}
    class_methods: dict[str, dict[str, str]] = defaultdict(dict)
    file_internal: dict[str, dict[str, str]] = {}; file_external: dict[str, dict[str, str]] = {}
    router_own_prefix: dict[str, str] = {}; router_parent: dict[str, tuple[str, str]] = {}
    pending_handlers: list[tuple] = []   # (FunctionInfo or None, module, handler name/None, method, path, router var, rel, inline FunctionInfo)

    for p in files:
        src = p.read_bytes()
        try:
            tree = Parser(LANGS[p.suffix]).parse(src)
        except Exception:
            continue
        rel = str(p.relative_to(root)); mod = _module_name(mroot, p); is_index = p.stem == "index"
        lines = src.decode(errors="ignore").splitlines()
        res.files.append({"path": rel, "module": mod, "loc": len(lines), "package": rel.split("/")[0]})
        internal, external = {}, {}

        def walk(node):
            yield node
            for c in node.children:
                yield from walk(c)

        # ---- imports
        for n in walk(tree.root_node):
            if n.type == "import_statement":
                spec_node = n.child_by_field_name("source"); spec = _str(spec_node, src) or ""
                dist = _dist(spec)
                target_mod = None if dist else _resolve_relative(mod, spec, is_index)
                for c in walk(n):
                    if c.type == "import_specifier":
                        name = _text(c.child_by_field_name("name"), src); alias = _text(c.child_by_field_name("alias") or c.child_by_field_name("name"), src)
                        (external.__setitem__(alias, dist) if dist else internal.__setitem__(alias, f"{target_mod}.{name}"))
                    elif c.type == "namespace_import":
                        alias = _text(c.children[-1], src); (external.__setitem__(alias, dist) if dist else internal.__setitem__(alias, target_mod))
                    elif c.type == "import_clause" and c.children and c.children[0].type == "identifier":
                        alias = _text(c.children[0], src); (external.__setitem__(alias, dist) if dist else internal.__setitem__(alias, f"{target_mod}.default"))
            elif n.type == "variable_declarator":
                val = n.child_by_field_name("value"); name_node = n.child_by_field_name("name")
                if val is not None and val.type == "call_expression" and _text(val.child_by_field_name("function"), src) == "require":
                    args = val.child_by_field_name("arguments"); spec = _str(args.children[1], src) if args and len(args.children) > 1 else None
                    if spec is not None and name_node is not None:
                        dist = _dist(spec); tm = None if dist else _resolve_relative(mod, spec, is_index)
                        if name_node.type == "identifier":
                            (external.__setitem__(_text(name_node, src), dist) if dist else internal.__setitem__(_text(name_node, src), tm))
                        elif name_node.type == "object_pattern":
                            for c in name_node.children:
                                if c.type in ("shorthand_property_identifier_pattern", "pair_pattern"):
                                    nm = _text(c, src).split(":")[-1].strip()
                                    (external.__setitem__(nm, dist) if dist else internal.__setitem__(nm, f"{tm}.{nm}"))
        file_internal[rel] = internal; file_external[rel] = external
        for d in sorted(set(external.values())):
            res.file_imports.append((rel, d))

        # ---- routers: const router = express.Router() / Router(); app.use('/prefix', router)
        for n in walk(tree.root_node):
            if n.type == "variable_declarator":
                val = n.child_by_field_name("value"); nm = n.child_by_field_name("name")
                if val is not None and nm is not None and nm.type == "identifier" and val.type == "call_expression":
                    callee = _text(val.child_by_field_name("function"), src)
                    if callee.endswith("Router") or callee in ("express", "Fastify", "fastify", "new Hono", "Hono", "new Koa", "Koa"):
                        router_own_prefix[f"{mod}.{_text(nm, src)}"] = ""
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                if fn is not None and fn.type == "member_expression" and _text(fn.child_by_field_name("property"), src) in ("use", "register"):
                    args = [a for a in n.child_by_field_name("arguments").children if a.type not in ("(", ")", ",")]
                    if len(args) >= 2 and _str(args[0], src) is not None:
                        prefix = _str(args[0], src); child = args[-1]
                        if child.type == "identifier":
                            cname = _text(child, src); key = internal.get(cname, f"{mod}.{cname}")
                            if key.endswith(".default"):
                                key = key[:-8] + ".router"
                            router_parent.setdefault(key, (f"{mod}.{_text(fn.child_by_field_name('object'), src)}", prefix))
                        for a in args[1:]:
                            if a.type == "call_expression" and (_text(a.child_by_field_name("function"), src) or "").endswith("Router"):
                                pass

        # ---- functions
        def add_fn(name: str, node, cls: str | None, body_node=None) -> FunctionInfo:
            qual = f"{mod}.{cls + '.' if cls else ''}{name}"
            if qual in by_qualname:   # overloads / duplicates: suffix with line
                qual = f"{qual}@{node.start_point[0] + 1}"
            seg = "\n".join(lines[node.start_point[0]: node.end_point[0] + 1])
            info = FunctionInfo(qual, name, mod, rel, cls, node.start_point[0] + 1, node.end_point[0] + 1, "async" in seg[:60], "", seg[:4000])
            for c in walk(body_node or node):
                if c.type == "call_expression":
                    f = c.child_by_field_name("function")
                    if f is None:
                        continue
                    if f.type == "identifier":
                        info.calls.append((_text(f, src), None))
                    elif f.type == "member_expression":
                        prop = f.child_by_field_name("property"); obj = f.child_by_field_name("object")
                        if prop is not None:
                            recv = _text(obj, src) if obj is not None and obj.type in ("identifier", "this") else (_text(obj.child_by_field_name("property"), src) if obj is not None and obj.type == "member_expression" and obj.child_by_field_name("property") is not None else None)
                            info.calls.append((_text(prop, src), recv))
                if c.type == "identifier" and _text(c, src) in external:
                    info.uses.add(_text(c, src))
            by_qualname[qual] = info; by_simple[name].append(qual); by_module_name[(mod, name)] = qual
            if cls:
                class_methods[f"{mod}.{cls}"][name] = qual
            res.functions.append(info)
            return info

        nest_prefix = None
        for n in walk(tree.root_node):
            if n.type == "function_declaration":
                nm = n.child_by_field_name("name"); add_fn(_text(nm, src) if nm is not None else "anonymous", n, None)
            elif n.type == "class_declaration" or n.type == "class":
                cname_node = n.child_by_field_name("name"); cname = _text(cname_node, src) if cname_node is not None else "AnonymousClass"
                res.classes.append({"qualname": f"{mod}.{cname}", "name": cname, "module": mod, "file": rel, "lineno": n.start_point[0] + 1, "bases": []})
                # NestJS @Controller('prefix')
                for d in n.children:
                    if d.type == "decorator":
                        dt = _text(d, src); m = re.match(r"@Controller\((?:['\"]([^'\"]*)['\"])?", dt)
                        if m:
                            nest_prefix = "/" + (m.group(1) or "").strip("/")
                body = n.child_by_field_name("body")
                if body is not None:
                    for m_ in body.children:
                        if m_.type == "method_definition":
                            mn = m_.child_by_field_name("name"); mname = _text(mn, src) if mn is not None else "method"
                            fi = add_fn(mname, m_, cname)
                            for d in m_.children:
                                if d.type == "decorator":
                                    dm = re.match(r"@(Get|Post|Put|Patch|Delete|All)\((?:['\"]([^'\"]*)['\"])?", _text(d, src))
                                    if dm:
                                        path = (nest_prefix or "") + ("/" + dm.group(2).strip("/") if dm.group(2) else "")
                                        fi.entrypoints.append({"method": NEST_METHODS[dm.group(1)], "path": re.sub(r":(\w+)", r"{\1}", path) or "/", "router": "nest"})
            elif n.type == "variable_declarator":
                val = n.child_by_field_name("value"); nm = n.child_by_field_name("name")
                if val is not None and nm is not None and nm.type == "identifier" and val.type in ("arrow_function", "function_expression", "function"):
                    add_fn(_text(nm, src), n, None, val)
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left"); right = n.child_by_field_name("right")
                if left is not None and right is not None and left.type == "member_expression" and right.type in ("arrow_function", "function_expression", "function"):
                    lt = _text(left, src)
                    if lt.startswith(("exports.", "module.exports.")):
                        add_fn(lt.split(".")[-1], n, None, right)
            elif n.type == "export_statement":
                decl = n.child_by_field_name("declaration")
                if decl is not None and decl.type in ("arrow_function", "function_expression", "function") and not decl.child_by_field_name("name"):
                    add_fn("default", n, None, decl)

        # ---- Express-style routes: app.get('/path', ...handlers)
        for n in walk(tree.root_node):
            if n.type != "call_expression":
                continue
            f = n.child_by_field_name("function")
            if f is None or f.type != "member_expression":
                continue
            prop = _text(f.child_by_field_name("property"), src); obj = f.child_by_field_name("object")
            recv = _text(obj, src) if obj is not None and obj.type == "identifier" else ""
            if prop in HTTP and (ROUTER_RE.search(recv) or not recv):
                args = [a for a in n.child_by_field_name("arguments").children if a.type not in ("(", ")", ",")]
                if not args or _str(args[0], src) is None:
                    continue
                path = re.sub(r":(\w+)", r"{\1}", _str(args[0], src)); method = "ANY" if prop == "all" else prop.upper()
                handler = args[-1] if len(args) > 1 else None
                if handler is not None and handler.type == "identifier":
                    pending_handlers.append((None, mod, _text(handler, src), method, path, recv, rel, None))
                elif handler is not None and handler.type == "member_expression":   # userController.getLogin
                    obj = handler.child_by_field_name("object"); prop = handler.child_by_field_name("property")
                    if obj is not None and prop is not None and obj.type == "identifier":
                        pending_handlers.append((None, mod, f"{_text(obj, src)}.{_text(prop, src)}", method, path, recv, rel, None))
                elif handler is not None and handler.type in ("arrow_function", "function_expression", "function"):
                    fi = add_fn(f"{method} {path}", n, None, handler); fi.name = f"handler:{method} {path}"
                    pending_handlers.append((fi, mod, None, method, path, recv, rel, fi))

        # ---- Next.js file routes
        nr = _next_route(rel)
        if nr:
            path, kind = nr
            if kind == "pages":
                for fi in res.functions:
                    if fi.file == rel and fi.name == "default":
                        fi.entrypoints.append({"method": "ANY", "path": path, "router": "next"})
            else:
                for fi in res.functions:
                    if fi.file == rel and fi.name in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                        fi.entrypoints.append({"method": fi.name, "path": path, "router": "next"})

    # ---- resolve route handlers given by name, and router prefixes
    def full_prefix(key, depth=0):
        pre = router_own_prefix.get(key, "")
        if depth > 10 or key not in router_parent:
            return pre
        pk, inc = router_parent[key]
        return full_prefix(pk, depth + 1) + inc + pre
    for fi, mod, hname, method, path, recv, rel, inline in pending_handlers:
        key = f"{mod}.{recv}" if recv else f"{mod}.router"
        if key not in router_own_prefix and key not in router_parent:   # router declared in another module (imported) or exported default
            alt = [k for k in router_parent if k.startswith(mod + ".")]
            key = alt[0] if alt else key
        full = full_prefix(key) + path
        target = fi
        if hname:
            internal = file_internal[rel]
            if "." in hname:                      # module alias + exported function: controller.method
                alias, fname = hname.split(".", 1)
                tm = internal.get(alias)
                if tm:
                    tm = tm[:-8] if tm.endswith(".default") else tm
                    q = by_module_name.get((tm, fname)) or class_methods.get(tm, {}).get(fname)
                    target = by_qualname.get(q) if q else None
                    if target is None:          # `exports.getLogin = (req,res)=>{}` style: function named getLogin anywhere in that module
                        cands = [c for c in by_simple.get(fname, []) if c.startswith(tm + ".")]
                        target = by_qualname.get(cands[0]) if cands else None
                else:
                    target = None
                if target is None and len(by_simple.get(fname, [])) == 1:
                    target = by_qualname[by_simple[fname][0]]
            else:
                q = internal.get(hname)
                target = by_qualname.get(q) if q else by_qualname.get(by_module_name.get((mod, hname), ""))
                if target is None and len(by_simple.get(hname, [])) == 1:
                    target = by_qualname[by_simple[hname][0]]
        if target is not None:
            target.entrypoints.append({"method": method, "path": full or "/", "router": recv or "router"})

    # ---- resolve calls
    class_of = {}
    for cq, methods in class_methods.items():
        for m, q in methods.items():
            class_of[q] = cq
    for info in res.functions:
        internal = file_internal[info.file]; external = file_external[info.file]; seen = set()
        for name, recv in info.calls:
            target, how = None, None
            if recv == "this" and info.cls:
                target = class_methods.get(f"{info.module}.{info.cls}", {}).get(name); how = "self"
            elif recv and recv in internal:
                tm = internal[recv]; target = by_module_name.get((tm, name)) or class_methods.get(tm, {}).get(name); how = "import"
            elif recv and recv in external:
                info.uses.add(recv); continue
            elif recv is None:
                if name in internal:
                    q = internal[name]; target = q if q in by_qualname else by_qualname.get(by_module_name.get((q.rsplit(".", 1)[0], q.rsplit(".", 1)[-1]), "")) and by_module_name.get((q.rsplit(".", 1)[0], q.rsplit(".", 1)[-1])); how = "import"
                    if target is None and q.endswith(".default"):
                        target = by_module_name.get((q[:-8], "default")); how = "import"
                elif (info.module, name) in by_module_name:
                    target = by_module_name[(info.module, name)]; how = "local"
                elif name in external:
                    info.uses.add(name); continue
            if not target and recv != "this" and name not in GENERIC_JS and 1 <= len(by_simple.get(name, [])) <= 8:
                for cand in by_simple[name]:
                    if cand != info.qualname and cand not in seen:
                        seen.add(cand); res.calls.append((info.qualname, cand, "name-match"))
                continue
            if target and target != info.qualname and target not in seen:
                seen.add(target); res.calls.append((info.qualname, target, how))
        for alias in sorted(info.uses):
            if alias in external:
                res.function_uses.append((info.qualname, external[alias]))
        for ep in info.entrypoints:
            res.entrypoints.append({"method": ep["method"], "path": ep["path"], "router": ep["router"], "handler": info.qualname, "file": info.file})
    return res


if __name__ == "__main__":
    import sys, collections
    r = parse_repo_js(sys.argv[1])
    print(f"files={len(r.files)} functions={len(r.functions)} calls={len(r.calls)} entrypoints={len(r.entrypoints)} file_imports={len(r.file_imports)} uses={len(r.function_uses)}")
    print(collections.Counter(h for _, _, h in r.calls)); print(r.entrypoints[:6]); print(collections.Counter(d for _, d in r.function_uses).most_common(8))
