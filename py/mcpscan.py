#!/usr/bin/env python3
"""Static taint analyzer for Python MCP / AI-agent tool servers.

Mirrors the TS scanner: a tool/resource/prompt handler's parameters are attacker-influenced
(the LLM client controls them), so they are taint sources; this flags that input reaching a
dangerous sink. Covers MCP (`mcp`, FastMCP) and LangChain (`@tool`). Parses with `ast` only —
the target file is NEVER imported or executed. Emits a JSON list of findings on stdout.

Usage: python3 mcpscan.py <file.py>
"""
import ast
import json
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


def dotted(node):
    """Dotted name of a Name/Attribute/Call-callee chain, else ''."""
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def is_mcp_file(src):
    return re.search(r"\b(mcp|fastmcp|modelcontextprotocol)\b|langchain|llama_index|llama-index", src, re.I) is not None


def names_in(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def refs_taint(node, taint):
    return bool(node) and bool(names_in(node) & taint)


SANITIZER = re.compile(r"sanitiz|escape|allowlist|whitelist|validate|is_allowed|shlex\.quote|secure_filename", re.I)


def _unwrap_await(node):
    return node.value if isinstance(node, ast.Await) else node


def is_sanitized(node):
    node = _unwrap_await(node)  # `await validate_path(p)` — the guard is often async
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
    """Names CONTENT-validated by a bouncer guard: `if not is_api_uri(u): raise`,
    `if not u.startswith(b): return`, `if '..' in p: raise`, `if host not in ALLOW: raise`.
    Bare presence/None checks don't count (clearing them would miss real injection)."""
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
                    add(sub)  # membership / allowlist check (not `is None`)
    return validated


def taint_of(fn, sources):
    taint = set(sources)
    for _ in range(6):
        before = len(taint)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and not is_sanitized(n.value) and refs_taint(n.value, taint):
                for t in n.targets:
                    taint |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
            elif isinstance(n, (ast.AugAssign,)) and refs_taint(n.value, taint):
                taint |= names_in(n.target)
        if len(taint) == before:
            break
    taint -= guard_validated(fn, taint)  # guard-by-throw clears content-validated names
    return taint


def handler_sources(fn):
    a = fn.args
    params = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    return [p for p in params if p not in SKIP_PARAMS]


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


def is_handler(fn):
    for d in fn.decorator_list:
        name = dotted(d)
        last = name.split(".")[-1] if name else ""
        if HANDLER_DECO.search(name) or last == "tool":
            return name.split(".")[-1]
    return None


CMD = re.compile(r"(?:^|\.)(system|popen|getoutput|getstatusoutput)$|(?:^|\.)(run|call|check_output|check_call|Popen)$")
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
    """f-string / % / + interpolation (not a plain Constant or a parameterized placeholder)."""
    return isinstance(a, ast.JoinedStr) or (isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Mod, ast.Add)))


def scan_handler(fn, kind, file, out):
    label = f'{kind} "{fn.name}"'
    where = f"MCP {label}"
    sources = handler_sources(fn)
    taint = taint_of(fn, sources)

    def emit(_id, cwe, sev, title, detail, line):
        out.append({"id": _id, "cwe": cwe, "severity": sev, "title": f"{title} in {where}",
                    "detail": detail, "file": file, "line": line, "handler": label})

    for s in meta_strings(fn):
        if INVISIBLE.search(s):
            emit("tool-poisoning", "CWE-94", "HIGH", "Hidden (invisible-unicode) text in the tool description",
                 f"The {label} docstring/description contains zero-width / bidi / unicode-tag characters — a hidden channel for model instructions (tool poisoning).", fn.lineno)
            break
        if INJECTION.search(s):
            emit("tool-poisoning", "CWE-94", "HIGH", "Prompt-injection instructions in the tool description",
                 f'The {label} docstring/description contains model-directed instructions ("{s[:60].strip()}…") — a malicious or rug-pulled server steering the client model.', fn.lineno)
            break

    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = dotted(n.func)
            last = name.split(".")[-1] if name else ""
            args = list(n.args)

            # command injection
            if (CMD.search(name) and (CMD_OBJ.search(name) or last in ("system", "popen", "getoutput"))) and (has_shell_true(n) or taint_arg(args, taint)):
                if has_shell_true(n) or taint_arg(args, taint):
                    emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command sink",
                         f"Attacker-influenced MCP input flows into `{name}(...)`" + (" with shell=True" if has_shell_true(n) else "") + ". Use a fixed argv list and never shell=True with tool input.", n.lineno)

            # code execution
            if last in ("eval", "exec", "compile") and not name.count(".") and taint_arg(args, taint):
                emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
                     f"Attacker-influenced MCP input flows into `{last}(...)` — arbitrary code execution.", n.lineno)

            # path traversal: open()/pathlib with tainted path
            is_open = last == "open" or name.endswith("aiofiles.open") or last in ("read_text", "write_text", "read_bytes", "write_bytes")
            if is_open and args and not strips_traversal(args[0]) and refs_taint(args[0], taint):
                emit("path-traversal", "CWE-22", "HIGH", "Tool input reaches a filesystem path sink",
                     f"Attacker-influenced MCP input is the path in `{name}(...)` with no traversal guard — a crafted `../` reads/writes arbitrary files. Resolve against a fixed root and reject escapes.", n.lineno)

            # SSRF
            if NET.search(name) and NET_OBJ.search(name) and args:
                if refs_taint(args[0], taint):
                    emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
                         f"Attacker-influenced MCP input is the URL of `{name}(...)` — SSRF (internal metadata/localhost reachable). Allowlist hosts.", n.lineno)
                elif taint_arg(args[1:], taint) or any(refs_taint(kw.value, taint) for kw in n.keywords):
                    emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
                         f"Attacker-influenced MCP input is in the body/params of `{name}(...)` (data egress, not URL control).", n.lineno)

            # SQL injection: raw interpolation into execute()/text()
            if SQL.search(name) and args and raw_sql_arg(args[0]) and refs_taint(args[0], taint):
                emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
                     f"Attacker-influenced MCP input is f-string/%/+ interpolated into `{name}(...)` instead of bound parameters — SQL injection.", n.lineno)

            # insecure deserialization
            if DESER.search(name) and DESER_OBJ.search(name) and taint_arg(args, taint):
                emit("deserialization", "CWE-502", "HIGH", "Tool input is deserialized with an unsafe loader",
                     f"Attacker-influenced MCP input flows into `{name}(...)` (pickle/dill/marshal) — deserializing untrusted data is arbitrary code execution.", n.lineno)
            # yaml.load without a safe loader is unsafe regardless of taint when fed tool input
            if name.endswith("yaml.load") and taint_arg(args, taint):
                safe = any(kw.arg == "Loader" and dotted(kw.value).endswith(("SafeLoader", "CSafeLoader")) for kw in n.keywords)
                if not safe:
                    emit("deserialization", "CWE-502", "HIGH", "Tool input is parsed with unsafe yaml.load",
                         "Attacker-influenced MCP input goes to `yaml.load(...)` without SafeLoader — can execute arbitrary Python. Use `yaml.safe_load`.", n.lineno)

        # secret exposure: whole os.environ used (not os.environ['X'] / os.getenv('X'))
        if isinstance(n, ast.Attribute) and n.attr == "environ" and dotted(n.value) == "os":
            # n is `os.environ`; skip if it is the value of a Subscript (os.environ['X'])
            pass  # handled below via parent scan
    # whole-environ scan with parent awareness
    _scan_environ(fn, where, label, file, out)


def _scan_environ(fn, where, label, file, out):
    seen = set()
    class V(ast.NodeVisitor):
        def visit_Subscript(self, node):
            # os.environ['X'] — a specific var, fine. Mark the inner environ attribute as safe.
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


def scan_source(src, file):
    if not is_mcp_file(src):
        return []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = is_handler(node)
            if kind:
                k = "resource" if "resource" in kind else ("prompt" if "prompt" in kind else "tool")
                scan_handler(node, k, file, out)
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: mcpscan.py <file.py>", file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
    except OSError as e:
        print(f"[]", end="")
        print(f"read error: {e}", file=sys.stderr)
        sys.exit(0)
    json.dump(scan_source(src, path), sys.stdout)


if __name__ == "__main__":
    main()
