#!/usr/bin/env python3
"""Static taint analyzer for Python MCP / AI-agent tool servers.

A tool/resource/prompt handler's parameters are attacker-influenced (the LLM client controls
them), so they are taint sources; this flags that input reaching a dangerous sink. Covers MCP
(`mcp`, FastMCP) and LangChain (`@tool`), with cross-function / cross-file resolution: a tainted
argument forwarded into a resolvable function is followed into it (bounded depth, cycle-safe,
ambiguous names skipped, guards not descended into). Parses with `ast` only — the target is NEVER
imported or executed. Emits a JSON list of findings on stdout.

Usage: python3 mcpscan.py <file.py | project-dir>
"""
import ast
import json
import os
import re
import sys

INJECTION = re.compile(
    r"ignore\s+(?:all\s+|the\s+)?(?:previous|above|prior)\s+(?:instructions|context|messages)"
    r"|disregard\s+(?:the\s+)?(?:previous|above|prior)"
    r"|do\s+not\s+(?:tell|inform|mention|notify|reveal).{0,20}\buser\b"
    r"|without\s+(?:telling|informing|notifying).{0,20}\buser\b"
    r"|exfiltrat|<important>|<secret>|\bsystem\s+prompt\b"
    r"|you\s+must\s+(?:always|secretly|silently)"
    r"|send\s+(?:the\s+|all\s+|any\s+)?(?:data|files?|contents?|credentials?|secrets?|keys?|\.env)\b"
    r"|read\s+(?:the\s+)?(?:~/\.ssh|\.env|id_rsa|credentials)",
    re.I,
)
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
HANDLER_DECO = re.compile(r"(?:^|\.)(tool|call_tool|resource|read_resource|prompt|get_prompt)$")
SKIP_PARAMS = {"self", "cls", "ctx", "context"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "build", "dist", ".tox", "site-packages"}
MAX_DEPTH = 4


def dotted(node):
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def is_mcp_file(src):
    return re.search(r"\b(mcp|fastmcp|modelcontextprotocol)\b|fastapi[_-]?mcp|FastApiMCP|langchain|llama_index|llama-index", src, re.I) is not None


# FastAPI routes exposed as MCP tools via `fastapi-mcp` (FastApiMCP(app)) — the route function params
# are the attacker-controlled tool input. Only treated as handlers when the project imports fastapi-mcp.
FASTAPI_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
FASTAPI_SKIP = {"request", "response", "background_tasks", "websocket", "bg"}


def names_in(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def refs_taint(node, taint):
    return bool(node) and bool(names_in(node) & taint)


SANITIZER = re.compile(r"sanitiz|escape|allowlist|whitelist|validate|is_allowed|shlex\.quote|secure_filename", re.I)


def _unwrap_await(node):
    return node.value if isinstance(node, ast.Await) else node


def is_sanitized(node):
    node = _unwrap_await(node)
    return isinstance(node, ast.Call) and bool(SANITIZER.search(dotted(node.func)))


def strips_traversal(node):
    node = _unwrap_await(node)
    return isinstance(node, ast.Call) and dotted(node.func).endswith("basename")


VALIDATOR_METHODS = {"startswith", "endswith", "match", "search", "fullmatch"}


def _body_bounces(body):
    for s in body:
        if isinstance(s, (ast.Raise, ast.Return)):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and dotted(s.value.func).split(".")[-1] in ("exit", "_exit"):
            return True
    return False


def guard_validated(fn, taint):
    """Names content-validated by a bouncer guard (predicate / membership); presence/None checks don't count."""
    validated = set()

    def add(node):
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in taint:
                validated.add(n.id)

    for n in ast.walk(fn):
        if isinstance(n, ast.If) and _body_bounces(n.body):
            for sub in ast.walk(n.test):
                if isinstance(sub, ast.Call):
                    for a in sub.args:
                        add(a)
                    if isinstance(sub.func, ast.Attribute) and sub.func.attr in VALIDATOR_METHODS:
                        add(sub.func.value)
                elif isinstance(sub, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops):
                    add(sub)
    return validated


def taint_of(fn, sources):
    taint = set(sources)
    for _ in range(6):
        before = len(taint)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and not is_sanitized(n.value) and refs_taint(n.value, taint):
                for t in n.targets:
                    taint |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
            elif isinstance(n, ast.AugAssign) and refs_taint(n.value, taint):
                taint |= names_in(n.target)
        if len(taint) == before:
            break
    taint -= guard_validated(fn, taint)
    return taint


def fn_params(fn):
    """Positional params aligned with call args (self/cls dropped so method calls map correctly)."""
    a = fn.args
    ps = list(a.posonlyargs) + list(a.args)
    if ps and ps[0].arg in ("self", "cls"):
        ps = ps[1:]
    return [p.arg for p in ps] + [p.arg for p in a.kwonlyargs]


def depends_params(fn):
    """FastAPI params whose default is Depends()/Security() — injected deps, not attacker input."""
    a = fn.args
    pos = list(a.posonlyargs) + list(a.args)
    out = set()
    defaults = list(a.defaults)
    if defaults:  # defaults align to the LAST N positional params
        for p, d in zip(pos[len(pos) - len(defaults):], defaults):
            if isinstance(d, ast.Call) and dotted(d.func).split(".")[-1] in ("Depends", "Security"):
                out.add(p.arg)
    for p, d in zip(a.kwonlyargs, a.kw_defaults):
        if isinstance(d, ast.Call) and dotted(d.func).split(".")[-1] in ("Depends", "Security"):
            out.add(p.arg)
    return out


def handler_sources(fn, fastapi=False):
    names = [p for p in fn_params(fn) if p not in SKIP_PARAMS]
    if fastapi:
        dep = depends_params(fn)
        names = [n for n in names if n not in FASTAPI_SKIP and n not in dep]
    return names


def meta_strings(fn):
    out = []
    doc = ast.get_docstring(fn)
    if doc:
        out.append(doc)
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            for kw in d.keywords:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    out.append(kw.value.value)
            for arg in d.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    out.append(arg.value)
    return out


def is_handler(fn, allow_fastapi=False):
    for d in fn.decorator_list:
        name = dotted(d)
        last = name.split(".")[-1] if name else ""
        if HANDLER_DECO.search(name) or last == "tool":
            return last
        # FastAPI route exposed as an MCP tool (only when the project uses fastapi-mcp)
        if allow_fastapi and isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in FASTAPI_METHODS:
            return "tool"
    return None


# ---- function index (cross-function resolution) ----------------------------

def build_index(parsed):
    idx = {}

    def add(key, fn, file):
        idx.setdefault(key, []).append((fn, file))

    for file, tree in parsed:
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add(n.name, n, file)
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        add(m.name, m, file)
                        add(f"{n.name}.{m.name}", m, file)
    return idx


def resolve_call(callee, idx):
    keys = []
    d = dotted(callee)
    if d:
        keys.append(d)
        keys.append(d.split(".")[-1])  # bare method/function name
    for k in keys:
        hit = idx.get(k)
        if hit and len(hit) == 1:
            return hit[0]
    return None


# ---- sinks -----------------------------------------------------------------

CMD = re.compile(r"(?:^|\.)(system|popen|getoutput|getstatusoutput|create_subprocess_shell|create_subprocess_exec)$|(?:^|\.)(run|call|check_output|check_call|Popen)$")
CMD_OBJ = re.compile(r"subprocess|^os$|\bos\.|commands|^sh$|\bsh\.|pexpect")
NET = re.compile(r"(?:^|\.)(get|post|put|patch|delete|request|urlopen|Request|send)$")
NET_OBJ = re.compile(r"requests|httpx|urllib|aiohttp|urllib3|\bhttp\b")
SQL = re.compile(r"(?:^|\.)(execute|executemany|executescript|text)$")
DESER = re.compile(r"(?:^|\.)(loads?|load)$")
DESER_OBJ = re.compile(r"pickle|cpickle|_pickle|dill|marshal|jsonpickle|shelve")


def taint_arg(args, taint):
    return any(refs_taint(a, taint) for a in args)


def has_shell_true(call):
    return any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords)


def raw_sql_arg(a):
    return isinstance(a, ast.JoinedStr) or (isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Mod, ast.Add)))


def analyze_fn(fn, seed, file, ctx, depth, visited, via):
    if not fn or id(fn) in visited or depth > MAX_DEPTH:
        return
    visited.add(id(fn))
    taint = taint_of(fn, seed)
    label = ctx["label"] + (f" (via {via})" if via else "")
    where = f"MCP {label}"
    out = ctx["out"]
    idx = ctx["idx"]

    def emit(_id, cwe, sev, title, detail, line):
        out.append({"id": _id, "cwe": cwe, "severity": sev, "title": f"{title} in {where}",
                    "detail": detail, "file": file, "line": line, "handler": label})

    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = dotted(n.func)
            last = name.split(".")[-1] if name else ""
            args = list(n.args)

            if (CMD.search(name) and (CMD_OBJ.search(name) or last in ("system", "popen", "getoutput", "create_subprocess_shell", "create_subprocess_exec"))) and (has_shell_true(n) or taint_arg(args, taint)):
                emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command sink",
                     f"Attacker-influenced MCP input flows into `{name}(...)`" + (" with shell=True" if has_shell_true(n) else "") + ". Use a fixed argv list and never shell=True with tool input.", n.lineno)

            if last in ("eval", "exec", "compile") and not name.count(".") and taint_arg(args, taint):
                emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
                     f"Attacker-influenced MCP input flows into `{last}(...)` — arbitrary code execution.", n.lineno)

            is_open = last == "open" or name.endswith("aiofiles.open") or last in ("read_text", "write_text", "read_bytes", "write_bytes")
            if is_open and args and not strips_traversal(args[0]) and refs_taint(args[0], taint):
                emit("path-traversal", "CWE-22", "HIGH", "Tool input reaches a filesystem path sink",
                     f"Attacker-influenced MCP input is the path in `{name}(...)` with no traversal guard — a crafted `../` reads/writes arbitrary files. Resolve against a fixed root and reject escapes.", n.lineno)

            if NET.search(name) and NET_OBJ.search(name) and args:
                if refs_taint(args[0], taint):
                    emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
                         f"Attacker-influenced MCP input is the URL of `{name}(...)` — SSRF (internal metadata/localhost reachable). Allowlist hosts.", n.lineno)
                elif taint_arg(args[1:], taint) or any(refs_taint(kw.value, taint) for kw in n.keywords):
                    emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
                         f"Attacker-influenced MCP input is in the body/params of `{name}(...)` (data egress, not URL control).", n.lineno)

            if SQL.search(name) and args and raw_sql_arg(args[0]) and refs_taint(args[0], taint):
                emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
                     f"Attacker-influenced MCP input is f-string/%/+ interpolated into `{name}(...)` instead of bound parameters — SQL injection.", n.lineno)

            if DESER.search(name) and DESER_OBJ.search(name) and taint_arg(args, taint):
                emit("deserialization", "CWE-502", "HIGH", "Tool input is deserialized with an unsafe loader",
                     f"Attacker-influenced MCP input flows into `{name}(...)` (pickle/dill/marshal) — deserializing untrusted data is arbitrary code execution.", n.lineno)
            if name.endswith("yaml.load") and taint_arg(args, taint):
                safe = any(kw.arg == "Loader" and dotted(kw.value).endswith(("SafeLoader", "CSafeLoader")) for kw in n.keywords)
                if not safe:
                    emit("deserialization", "CWE-502", "HIGH", "Tool input is parsed with unsafe yaml.load",
                         "Attacker-influenced MCP input goes to `yaml.load(...)` without SafeLoader — can execute arbitrary Python. Use `yaml.safe_load`.", n.lineno)

            # cross-function forward (not into guards)
            if not is_sanitized(n):
                resolved = resolve_call(n.func, idx)
                if resolved and id(resolved[0]) not in visited:
                    cfn, cfile = resolved
                    params = fn_params(cfn)
                    next_seed = set()
                    for i, a in enumerate(args):
                        if refs_taint(a, taint) and i < len(params):
                            next_seed.add(params[i])
                    for kw in n.keywords:
                        if kw.arg and refs_taint(kw.value, taint) and kw.arg in params:
                            next_seed.add(kw.arg)
                    if next_seed:
                        analyze_fn(cfn, next_seed, cfile, ctx, depth + 1, visited, f"{via} -> {name}" if via else name)

        # secret exposure: whole os.environ (not os.environ['X'])
    _scan_environ(fn, where, label, file, out)


def _scan_environ(fn, where, label, file, out):
    seen = set()

    class V(ast.NodeVisitor):
        def visit_Subscript(self, node):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ" and dotted(node.value.value) == "os":
                seen.add(id(node.value))
            self.generic_visit(node)
    V().visit(fn)
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr == "environ" and dotted(n.value) == "os" and id(n) not in seen:
            out.append({"id": "secret-exposure", "cwe": "CWE-200", "severity": "MEDIUM",
                        "title": f"Whole `os.environ` is used (secret exposure risk) in {where}",
                        "detail": f"The {label} uses the entire `os.environ` (not a single `os.environ['X']` / `os.getenv`). If returned, serialized, or sent, every secret leaks to the client.",
                        "file": file, "line": n.lineno, "handler": label})


# ---- entry -----------------------------------------------------------------

def collect_files(path):
    if os.path.isfile(path):
        return [path] if path.endswith(".py") else []
    out = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def scan_project(path):
    parsed = []
    for f in collect_files(path):
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        try:
            parsed.append((f, ast.parse(src), src))
        except SyntaxError:
            continue
    idx = build_index([(f, t) for f, t, _ in parsed])
    fastapi_mcp = any(re.search(r"fastapi[_-]?mcp|FastApiMCP", s) for _, _, s in parsed)
    out = []
    for file, tree, src in parsed:
        if not is_mcp_file(src):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = is_handler(node, allow_fastapi=fastapi_mcp)
                if not kind:
                    continue
                k = "resource" if "resource" in kind else ("prompt" if "prompt" in kind else "tool")
                label = f'{k} "{node.name}"'
                for s in meta_strings(node):
                    if INVISIBLE.search(s):
                        out.append({"id": "tool-poisoning", "cwe": "CWE-94", "severity": "HIGH",
                                    "title": f"Hidden (invisible-unicode) text in the tool description in MCP {label}",
                                    "detail": f"The {label} docstring/description contains zero-width / bidi / unicode-tag characters — a hidden channel for model instructions (tool poisoning).",
                                    "file": file, "line": node.lineno, "handler": label})
                        break
                    if INJECTION.search(s):
                        out.append({"id": "tool-poisoning", "cwe": "CWE-94", "severity": "HIGH",
                                    "title": f"Prompt-injection instructions in the tool description in MCP {label}",
                                    "detail": f'The {label} docstring/description contains model-directed instructions ("{s[:60].strip()}…") — a malicious or rug-pulled server steering the client model.',
                                    "file": file, "line": node.lineno, "handler": label})
                        break
                analyze_fn(node, handler_sources(node, fastapi=fastapi_mcp), file, {"idx": idx, "out": out, "label": label}, 0, set(), "")
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: mcpscan.py <file.py | project-dir>", file=sys.stderr)
        sys.exit(2)
    json.dump(scan_project(sys.argv[1]), sys.stdout)


if __name__ == "__main__":
    main()
