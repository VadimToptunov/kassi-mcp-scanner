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
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "build", "dist", ".tox", "site-packages",
             # test/spec trees: fixtures/seams are not a running server's attack surface (they dominated
             # the sweep's FP funnel). Mirrors the TS CLI walker's skip set.
             "test", "tests", "__tests__", "spec", "specs", "e2e"}


def _is_test_file(name):
    """A pytest/unittest file (test_*.py, *_test.py, conftest.py) — not server attack surface."""
    return name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py")
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
    return re.search(r"\b(mcp|fastmcp|modelcontextprotocol)\b|fastapi[_-]?mcp|FastApiMCP|langchain|llama_index|llama-index|\bcrewai\b|\b(py)?autogen\b|\blanggraph\b", src, re.I) is not None


# CrewAI / LangChain class tools: `class X(BaseTool): def _run(self, query): …` — _run/_arun is the handler.
BASE_TOOL = re.compile(r"(^|\.)(BaseTool|StructuredTool|Tool)$")
# AutoGen: a function registered for the LLM to call is a tool handler.
AUTOGEN_DECO = {"register_function", "register_for_execution"}


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
# A named validator BOUNCER called as a statement (it raises on bad input: `validate_file_path(p)`,
# `self._require_valid_file_path(p)`, `ensure_within_base(p)`) clears its tainted argument downstream.
BOUNCER_FUNC = re.compile(r"(validate|require|ensure|verify|guard)", re.I)
# Path-containment bouncers: `resolved.relative_to(base)` raises ValueError when `resolved` escapes base.
CONTAINMENT_METHODS = {"relative_to"}


def _body_bounces(body):
    for s in body:
        if isinstance(s, (ast.Raise, ast.Return)):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and dotted(s.value.func).split(".")[-1] in ("exit", "_exit"):
            return True
    return False


def _validated_in(node, taint):
    """Tainted names an expression content-validates: a predicate call's args, a validator-method
    receiver (`x.startswith(...)`), or a membership test (`x in allow`). Presence/None checks: none."""
    found = set()

    def add(x):
        for m in ast.walk(x):
            if isinstance(m, ast.Name) and m.id in taint:
                found.add(m.id)

    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            for a in sub.args:
                add(a)
            if isinstance(sub.func, ast.Attribute) and sub.func.attr in VALIDATOR_METHODS:
                add(sub.func.value)
        elif isinstance(sub, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops):
            add(sub)
    return found


def guard_validated(fn, taint):
    """Names content-validated by a bouncer guard (predicate / membership); presence/None checks don't count.
    Handles the INDIRECT form too, where the predicate result is stored and then checked:
        ok = is_path_allowed(path)   # validates `path`
        if not ok: raise             # test references `ok`, not `path`
    so a value validated before being forwarded into a called function is cleared (the filesystem-server FP)."""
    # map a boolean-ish variable to the tainted names its defining expression validates
    bool_to_validated = {}
    for n in ast.walk(fn):
        tgt = val = None
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            tgt, val = n.targets[0].id, n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            tgt, val = n.target.id, n.value
        if tgt is not None and val is not None:
            names = _validated_in(val, taint)
            if names:
                bool_to_validated[tgt] = names

    validated = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.If) and _body_bounces(n.body):
            validated |= _validated_in(n.test, taint)
            for sub in ast.walk(n.test):  # indirect: a boolean var that holds a prior predicate result
                if isinstance(sub, ast.Name) and sub.id in bool_to_validated:
                    validated |= bool_to_validated[sub.id]

    # Named validator BOUNCERS (`validate_file_path(p)` / `self._require_valid_file_path(p)`) and
    # path-containment bouncers (`resolved.relative_to(base)`) raise on bad input, so a value they
    # check is safe downstream even though it is not reassigned (the code-index-mcp / elevenlabs FP).
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        if BOUNCER_FUNC.search(dotted(n.func).split(".")[-1]):
            for a in n.args:
                for m in ast.walk(a):
                    if isinstance(m, ast.Name) and m.id in taint:
                        validated.add(m.id)
        if isinstance(n.func, ast.Attribute) and n.func.attr in CONTAINMENT_METHODS:
            for m in ast.walk(n.func.value):
                if isinstance(m, ast.Name) and m.id in taint:
                    validated.add(m.id)
    return validated


def propagate(fn, sources):
    """Raw taint reachability, WITHOUT guard-clearing."""
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
    return taint


def taint_of(fn, sources):
    # Guard-aware: a validated name — and anything derived ONLY from validated/clean values — must never
    # (re-)enter taint. Subtracting at the end would miss a derived sink arg (`full = join(base, p)` after
    # `validate(p)`), so we recompute the reachable set with validated names blocked.
    validated = guard_validated(fn, propagate(fn, sources))
    if not validated:
        return propagate(fn, sources)
    taint = {s for s in sources if s not in validated}
    for _ in range(6):
        before = len(taint)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and not is_sanitized(n.value) and refs_taint(n.value, taint):
                for t in n.targets:
                    taint |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name) and x.id not in validated}
            elif isinstance(n, ast.AugAssign) and refs_taint(n.value, taint):
                taint |= {nm for nm in names_in(n.target) if nm not in validated}
        if len(taint) == before:
            break
    return taint


# ---- SSRF-guard awareness (seed: mcp-sanitizer GHSA-4mfg-r38w-w8fg) --------
# A private-network/loopback BLOCKLIST guard is only as good as the forms it rejects; the bypass
# class is IPv6 loopback (::1), IPv4-mapped (::ffff:127.0.0.1), 0.0.0.0, encoded IPs, and failing to
# re-check after a redirect. A guard that names loopback/private but MISSES those is a live SSRF; an
# ALLOWLIST guard (host in {...} / host == "api...") is the correct defense and must stay clean.
SSRF_BLOCKLIST = re.compile(r"localhost|127\.0\.0|0\.0\.0\.0|::1|169\.254|metadata|is_?private|is_?loopback|loopback|block_?private|is_?internal|\bprivate\b|\binternal\b|ssrf|\b10\.0\.0|192\.168|172\.1[6-9]", re.I)
SSRF_ROBUST = re.compile(r"ipaddress|ip_?address|is_?private|netmask|cidr|ip_?range|private_?ip|ssrf_?filter|request_?filtering", re.I)
SSRF_IPV6_LOOPBACK = re.compile(r"::1")
SSRF_ALLZEROS = re.compile(r"0\.0\.0\.0")
SSRF_MAPPED = re.compile(r"::ffff|ipv4[-_]?mapped|\bmapped\b", re.I)


def _guard_tokens(test, idx, depth=0):
    parts = []
    for n in ast.walk(test):
        if isinstance(n, ast.Name):
            parts.append(n.id)
        elif isinstance(n, ast.Attribute):
            parts.append(n.attr)
        elif isinstance(n, ast.Constant):
            parts.append(str(n.value))
    if depth < 1:
        for n in ast.walk(test):
            if isinstance(n, ast.Call):
                r = resolve_call(n.func, idx)
                if r:
                    parts.append(_guard_tokens(r[0], idx, depth + 1))
    return " ".join(parts).lower()


def ssrf_guard_coverage(tokens):
    if SSRF_ROBUST.search(tokens):
        return "complete"
    if not SSRF_BLOCKLIST.search(tokens):
        return "none"
    covers = SSRF_IPV6_LOOPBACK.search(tokens) and SSRF_ALLZEROS.search(tokens) and SSRF_MAPPED.search(tokens)
    return "complete" if covers else "incomplete"


def ssrf_guard_sets(fn, sources, idx):
    """(safe, weak) tainted-name sets, grouping names into derivation components and judging each
    component by its guard: complete ⇒ safe (suppress), incomplete ⇒ weak (still a live bypass)."""
    raw = propagate(fn, sources)
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    def tainted_ids(node):
        return [n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id in raw] if node else []

    for n in raw:
        find(n)
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                for tgt in (x.id for x in ast.walk(t) if isinstance(x, ast.Name) and x.id in raw):
                    for s in tainted_ids(n.value):
                        union(tgt, s)
        elif isinstance(n, ast.AnnAssign) and n.value and isinstance(n.target, ast.Name) and n.target.id in raw:
            for s in tainted_ids(n.value):
                union(n.target.id, s)

    safe_roots, weak_roots = set(), set()
    for n in ast.walk(fn):
        if isinstance(n, ast.If) and _body_bounces(n.body):
            cov = ssrf_guard_coverage(_guard_tokens(n.test, idx))
            if cov == "none":
                continue
            for v in tainted_ids(n.test):
                (safe_roots if cov == "complete" else weak_roots).add(find(v))
    safe, weak = set(), set()
    for n in raw:
        r = find(n)
        if r in safe_roots:
            safe.add(n)
        elif r in weak_roots:
            weak.add(n)
    return safe, weak


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


def is_handler(fn, allow_fastapi=False, allow_autogen=False):
    for d in fn.decorator_list:
        name = dotted(d)
        last = name.split(".")[-1] if name else ""
        if HANDLER_DECO.search(name) or last == "tool":
            return last
        # FastAPI route exposed as an MCP tool (only when the project uses fastapi-mcp)
        if allow_fastapi and isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in FASTAPI_METHODS:
            return "tool"
        # AutoGen function registered for the LLM to call
        if allow_autogen and last in AUTOGEN_DECO:
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


def sql_built_from_taint(fn, taint):
    """Names assigned a SQL string BUILT from tool input (f-string / % / +), then passed to execute(var).
    Excludes a value handed straight through as the raw sql param (by-design arbitrary SQL)."""
    built = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and raw_sql_arg(n.value) and refs_taint(n.value, taint):
            for t in n.targets:
                built |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
    return built


def analyze_fn(fn, seed, file, ctx, depth, visited, via):
    if not fn or id(fn) in visited or depth > MAX_DEPTH:
        return
    visited.add(id(fn))
    taint = taint_of(fn, seed)
    label = ctx["label"] + (f" (via {via})" if via else "")
    where = f"MCP {label}"
    out = ctx["out"]
    idx = ctx["idx"]
    # SSRF-specific taint: drop names a COMPLETE private-net guard protects, re-add names only an
    # INCOMPLETE (bypassable) guard "cleared". Other sinks keep the generic guard-cleared `taint`.
    ssrf_safe, ssrf_weak = ssrf_guard_sets(fn, seed, idx)
    ssrf_taint = (taint - ssrf_safe) | ssrf_weak
    sql_built = sql_built_from_taint(fn, taint)

    def emit(_id, cwe, sev, title, detail, line):
        out.append({"id": _id, "cwe": cwe, "severity": sev, "title": f"{title} in {where}",
                    "detail": detail, "file": file, "line": line, "handler": label})

    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = dotted(n.func)
            last = name.split(".")[-1] if name else ""
            args = list(n.args)

            if CMD.search(name) and (CMD_OBJ.search(name) or last in ("system", "popen", "getoutput", "getstatusoutput", "create_subprocess_shell", "create_subprocess_exec")):
                # SHELL form (shell=True / os.system / os.popen / *_shell): any tainted arg = shell injection.
                shell_form = has_shell_true(n) or last in ("system", "popen", "getoutput", "getstatusoutput", "create_subprocess_shell")
                if shell_form and taint_arg(args, taint):
                    emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command sink",
                         f"Attacker-influenced MCP input flows into `{name}(...)`" + (" with shell=True" if has_shell_true(n) else " (runs via a shell)") + ". Use a fixed argv list and never a shell with tool input.", n.lineno)
                elif not shell_form and args:
                    # ARGV form (list, no shell): shell metachars are inert, so a tainted ARGUMENT is not
                    # injection. Dangerous only if the PROGRAM is attacker-chosen, and we only assert that
                    # when it's visible: an inline list whose FIRST element is tainted. A prebuilt argv in a
                    # variable (`cmd=[ffmpeg,...]; run(cmd)`) has a fixed program -> not flagged (vfx/pandoc FP).
                    prog = args[0]
                    if isinstance(prog, (ast.List, ast.Tuple)) and prog.elts and refs_taint(prog.elts[0], taint):
                        emit("cmd-injection", "CWE-78", "HIGH", "Tool input chooses the program executed",
                             f"Attacker-influenced MCP input is the PROGRAM in `{name}(...)` (argv form) — it runs an arbitrary binary. Pin the program; pass user data only as fixed-position arguments.", n.lineno)

            if last in ("eval", "exec", "compile") and not name.count(".") and taint_arg(args, taint):
                emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
                     f"Attacker-influenced MCP input flows into `{last}(...)` — arbitrary code execution.", n.lineno)

            is_open = last == "open" or name.endswith("aiofiles.open") or last in ("read_text", "write_text", "read_bytes", "write_bytes")
            if is_open and args and not strips_traversal(args[0]) and refs_taint(args[0], taint):
                emit("path-traversal", "CWE-22", "HIGH", "Tool input reaches a filesystem path sink",
                     f"Attacker-influenced MCP input is the path in `{name}(...)` with no traversal guard — a crafted `../` reads/writes arbitrary files. Resolve against a fixed root and reject escapes.", n.lineno)

            if NET.search(name) and NET_OBJ.search(name) and args:
                if refs_taint(args[0], ssrf_taint) and refs_taint(args[0], ssrf_weak):
                    emit("ssrf-guard-bypass", "CWE-918", "HIGH", "Outbound URL passes an incomplete SSRF guard",
                         f"Attacker-influenced MCP input is the URL of `{name}(...)` behind a private-network/loopback guard that misses known bypass forms — IPv6 loopback `[::1]`, IPv4-mapped `::ffff:127.0.0.1`, `0.0.0.0`, and decimal/hex/octal-encoded IPs — and does not re-check the host after redirects (cf. mcp-sanitizer GHSA-4mfg-r38w-w8fg). Allowlist hosts, or normalize to a canonical IP and reject the full private range (a vetted library), re-validating on every redirect.", n.lineno)
                elif refs_taint(args[0], ssrf_taint):
                    emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
                         f"Attacker-influenced MCP input is the URL of `{name}(...)` — SSRF (internal metadata/localhost reachable). Allowlist hosts.", n.lineno)
                elif taint_arg(args[1:], taint) or any(refs_taint(kw.value, taint) for kw in n.keywords):
                    emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
                         f"Attacker-influenced MCP input is in the body/params of `{name}(...)` (data egress, not URL control).", n.lineno)

            sql_interp = args and (raw_sql_arg(args[0]) or (isinstance(args[0], ast.Name) and args[0].id in sql_built))
            if SQL.search(name) and sql_interp and refs_taint(args[0], taint):
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

    def mark_environ(scope):
        for n in ast.walk(scope):
            if isinstance(n, ast.Attribute) and n.attr == "environ" and dotted(n.value) == "os":
                seen.add(id(n))

    class V(ast.NodeVisitor):
        def visit_Subscript(self, node):
            # os.environ['X'] — reading ONE var is fine, not a dump
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ" and dotted(node.value.value) == "os":
                seen.add(id(node.value))
            self.generic_visit(node)

        def visit_Attribute(self, node):
            # os.environ.get("X") / .copy() / .keys() — a member access, not a whole-object dump
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ" and dotted(node.value.value) == "os":
                seen.add(id(node.value))
            self.generic_visit(node)

        def visit_keyword(self, node):
            # `env=os.environ` / `env={**os.environ, ...}` passed to a subprocess is NOT a client leak
            if node.arg == "env":
                mark_environ(node.value)
            self.generic_visit(node)
    V().visit(fn)
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr == "environ" and dotted(n.value) == "os" and id(n) not in seen:
            out.append({"id": "secret-exposure", "cwe": "CWE-200", "severity": "MEDIUM",
                        "title": f"Whole `os.environ` is used (secret exposure risk) in {where}",
                        "detail": f"The {label} uses the entire `os.environ` (not a single `os.environ['X']` / `os.getenv`). If returned, serialized, or sent, every secret leaks to the client.",
                        "file": file, "line": n.lineno, "handler": label})


# ---- unbounded input / resource exhaustion (CWE-770) -----------------------
# Seed: MCP TypeScript SDK GHSA-f897-62hf-6gxq — an HTTP transport read a request body / iterated a
# JSON-RPC batch with no size/length cap before parsing (memory exhaustion). Transport-level, so it
# is scanned structurally over every function in an MCP file, not only inside registered handlers.
SIZE_NAME = re.compile(r"(length|byte|size|bytes|len|total|count|received|read|accumulated)", re.I)
LIMIT_NAME = re.compile(r"(max|limit|cap|bound|threshold|quota)", re.I)
DISPATCH_FN = re.compile(r"(handle|dispatch|process|on_?message|route|execute|serve)", re.I)
RPC_MEMBER = {"method", "jsonrpc", "id", "params"}
GROW_METHOD = {"append", "extend", "concat"}  # NOT "write" — writing OUT drains a stream, not a read
STREAM_ATTR = re.compile(r"(stream|iter_any|iter_content|iter_chunked|iter_chunks|__aiter__)$", re.I)
# the iterated source of a request-body read (vs a file stream / DB cursor, out of scope)
REQ_SOURCE = re.compile(r"(req|request|incoming|socket|body|conn|stream|receive)", re.I)


def _is_size_side(n):
    if isinstance(n, ast.Call):  # len(x)
        return dotted(n.func).split(".")[-1] == "len"
    if isinstance(n, ast.Attribute):
        return bool(SIZE_NAME.search(n.attr))
    if isinstance(n, ast.Name):
        return bool(SIZE_NAME.search(n.id))
    return False


def _is_limit_side(n):
    if isinstance(n, ast.Constant):
        return isinstance(n.value, (int, float)) and n.value > 0
    if isinstance(n, ast.Name):
        return bool(LIMIT_NAME.search(n.id))
    if isinstance(n, ast.Attribute):
        return bool(LIMIT_NAME.search(n.attr))
    return False


def has_size_cap(fn):
    """A comparison of a size/len quantity against a positive numeric/limit value (`len(b) > MAX`,
    `size > 1_000_000`). `i < len(x)` is NOT one — the non-size side is a loop index."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare) and n.ops and isinstance(n.ops[0], (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            left, right = n.left, n.comparators[0]
            if (_is_size_side(left) and _is_limit_side(right)) or (_is_size_side(right) and _is_limit_side(left)):
                return True
    return False


def _grows_buffer(scope):
    for n in ast.walk(scope):
        if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in GROW_METHOD:
            return True
    return False


def _accumulates_body(fn):
    for n in ast.walk(fn):
        if isinstance(n, ast.AsyncFor) and _grows_buffer(n):  # async for chunk in request.stream()
            src = dotted(n.iter.func) if isinstance(n.iter, ast.Call) else dotted(n.iter)
            if REQ_SOURCE.search(src):  # a request stream, not a file/DB async iterable
                return True
        if isinstance(n, ast.For) and _grows_buffer(n):
            it = n.iter
            if isinstance(it, ast.Call) and STREAM_ATTR.search(dotted(it.func)):
                return True
            if isinstance(it, (ast.Attribute, ast.Name)) and STREAM_ATTR.search(dotted(it)):
                return True
    return False


def _looks_like_dispatch(scope):
    nodes = scope if isinstance(scope, list) else [scope]
    for node in nodes:
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and DISPATCH_FN.search(dotted(n.func)):
                return True
            if isinstance(n, ast.Attribute) and n.attr in RPC_MEMBER:
                return True
    return False


def _has_isinstance_list(fn):
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and dotted(n.func) == "isinstance":
            if len(n.args) == 2 and (dotted(n.args[1]) in ("list", "tuple")):
                return True
    return False


def _has_dispatch_iteration(fn):
    for n in ast.walk(fn):
        if isinstance(n, ast.For) and not isinstance(n, ast.AsyncFor) and _looks_like_dispatch(n.body):
            return True
        if isinstance(n, (ast.ListComp, ast.GeneratorExp)) and _looks_like_dispatch(n.elt):
            return True
    return False


# A JSON-RPC batch finding is only meaningful in JSON-RPC transport code; this gate keeps the detector
# off unrelated isinstance(x, list) + dispatch shapes (CLI commands, batch utilities).
RPC_FILE = re.compile(r"jsonrpc|json-rpc|JSONRPCMessage|-32700|-32600|-32603|CallToolRequest|is_initialize_request|StreamableHTTP", re.I)


def scan_unbounded(parsed):
    out = []
    for file, tree, src in parsed:
        if not is_mcp_file(src):
            continue
        is_rpc_file = bool(RPC_FILE.search(src))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if has_size_cap(fn):
                continue
            if _accumulates_body(fn):
                out.append({"id": "unbounded-body", "cwe": "CWE-770", "severity": "HIGH",
                            "title": "Request body is accumulated without a size cap",
                            "detail": "An HTTP transport reads and accumulates a request body (an async stream / chunk loop) with no byte/length limit enforced before it is buffered or parsed. A single large request exhausts server memory (cf. MCP SDK GHSA-f897-62hf-6gxq). Cap the accumulated size and reject once exceeded.",
                            "file": file, "line": fn.lineno, "handler": "(HTTP transport)"})
            elif is_rpc_file and _has_isinstance_list(fn) and _has_dispatch_iteration(fn):
                out.append({"id": "unbounded-batch", "cwe": "CWE-770", "severity": "HIGH",
                            "title": "JSON-RPC batch is iterated without a length cap",
                            "detail": "A JSON-RPC batch (`isinstance(message, list)` → the message list) is dispatched element-by-element with no cap on the list length before processing. A huge batch array exhausts memory/CPU (cf. MCP SDK GHSA-f897-62hf-6gxq). Reject batches longer than a fixed maximum before iterating.",
                            "file": file, "line": fn.lineno, "handler": "(JSON-RPC transport)"})
    return out


# ---- entry -----------------------------------------------------------------

def collect_files(path):
    if os.path.isfile(path):
        return [path] if path.endswith(".py") else []
    out = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py") and not _is_test_file(f):
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
    autogen = any(re.search(r"\b(py)?autogen\b", s) for _, _, s in parsed)
    out = []
    out.extend(scan_unbounded(parsed))  # transport-level unbounded body / JSON-RPC batch (CWE-770)

    def run_handler(node, file, idx, out, kindhint=None):
        kind = kindhint or is_handler(node, allow_fastapi=fastapi_mcp, allow_autogen=autogen)
        if not kind:
            return
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

    for file, tree, src in parsed:
        if not is_mcp_file(src):
            continue
        # CrewAI / LangChain class tools: a BaseTool subclass' _run / _arun method is the handler
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(BASE_TOOL.search(dotted(b)) for b in node.bases):
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in ("_run", "_arun"):
                        run_handler(m, file, idx, out, kindhint="tool")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                run_handler(node, file, idx, out)
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: mcpscan.py <file.py | project-dir>", file=sys.stderr)
        sys.exit(2)
    json.dump(scan_project(sys.argv[1]), sys.stdout)


if __name__ == "__main__":
    main()
