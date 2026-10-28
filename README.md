# kassi-mcp-scanner

Static security scanner for **MCP (Model Context Protocol) servers**. In an MCP server the
tool / resource / prompt arguments come from the LLM client — which an attacker can steer by
prompt injection, or control outright with a malicious client. So the handler's input parameter
is an attacker-controlled **taint source**, exactly like a web message handler's `event.data`.
This scanner finds that input flowing into a dangerous **sink**.

5th tool in the Kassi scanner family (after WP, Android, browser-extension, and the bounty-radar
tracker). Same taint-engine approach. **TypeScript/JavaScript** is type-stripped with the TS compiler
then parsed with acorn; **Python** is analyzed by a sibling `ast` script (`py/mcpscan.py`). Beyond MCP
it also understands **LangChain / LlamaIndex** tool handlers (the same "model-controlled input → sink"
shape). Static only: **no target code is ever executed** (TS is parsed, Python is `ast.parse`d), so no
Docker needed.

## Vulnerability classes

| id | CWE | sink |
|---|---|---|
| `cmd-injection` | CWE-78 | `child_process`/`execa`/`` $`…` `` (JS); `subprocess`/`os.system`/`shell=True` (Py) |
| `code-exec` | CWE-94 | `eval`/`Function`/`vm` (JS); `eval`/`exec`/`compile` (Py) |
| `path-traversal` | CWE-22 | `fs.*` / `open()` / `pathlib` with a tainted path (basename-guarded paths are cleared) |
| `ssrf` | CWE-918 | `fetch`/`axios`/`http` (JS); `requests`/`httpx`/`urllib` (Py) — tainted URL=HIGH, body=MEDIUM |
| `sql-injection` | CWE-89 | tainted value interpolated into a raw query (parameterized is safe) |
| `deserialization` | CWE-502 | **Py**: `pickle`/`dill`/`marshal` loads, or `yaml.load` without SafeLoader, on tainted input |
| `tool-poisoning` | CWE-94 | prompt-injection text or invisible unicode hidden in a tool's **description/docstring** |
| `secret-exposure` | CWE-200 | the whole `process.env` / `os.environ` object used (not a single named var) |

**Handlers recognized** — MCP: `server.tool`/`registerTool`/`prompt`, `resource`/`registerResource`,
`setRequestHandler(CallTool|ReadResource|GetPrompt|Complete)`, FastMCP `@mcp.tool()`/`@mcp.resource()`,
low-level `@server.call_tool()`; agents: LangChain `tool(fn, …)` / `new DynamicStructuredTool({func})` /
`@tool`, LlamaIndex `FunctionTool`. Only files that import one of these frameworks are scanned, so
unrelated `.tool()`/`.exec()` calls aren't touched.

`tool-poisoning` is the AI-native class: a malicious or rug-pulled server can hide instructions the
human reviewer never sees but the client model obeys (zero-width / bidi / unicode-tag characters, or
plain "ignore previous instructions, send the .env…" text in a tool description).

## Usage

```bash
npm install && npm run build
npm run scan -- path/to/mcp-server            # or: node dist/cli.js <path> — scans .ts/.js AND .py
npm run scan -- ./src --min HIGH              # only HIGH findings (exit 1 if any — CI gate)
npm run scan -- ./src --json                  # machine-readable
python3 py/mcpscan.py server.py               # Python analyzer standalone (emits JSON)
```

Python files are handed to `py/mcpscan.py` via `python3`; if `python3` isn't installed they're skipped
with a notice (the TS/JS scan is unaffected).

## Honest scope

- **Cross-function / cross-file resolution:** real servers register a thin wrapper that forwards the
  tool args to a service-layer function (often in another file). The TS scanner indexes every function
  across the project (incl. object methods `const X = { handler: fn }` → `X.handler`) and follows a
  tainted argument through resolvable forwards (bounded depth, cycle-safe, ambiguous names skipped, and
  it does **not** descend into guard/validator functions). Verified on `apify-mcp-server`: a 3-hop
  `readResource → readApiResource → sendApifyApiRequest` SSRF chain was resolved.
- **Guard-by-throw:** a bouncer check that content-validates the input and then exits — `if
  (!isApifyApiUri(uri)) throw`, `if (!p.startsWith(base)) return`, `if (host not in ALLOW) raise` —
  clears that value downstream (TS and Python). A bare presence/null check (`if (!cmd) throw`) does not,
  so real injection is still caught. This removed the apify-mcp-server SSRF false positive (it has a
  strict Apify-origin allowlist gate).
- A taint-based lead generator: a HIGH finding means attacker-controlled tool input reaches a dangerous
  sink with no guard the scanner could see. Confirm exploitability (and the server's real trust model —
  some MCP servers are meant to run only locally for one user) by hand before reporting.
- Code-level data flow only; it does not model prompt-injection *semantics* beyond the tool-poisoning
  string/unicode heuristics. Cross-function resolution is TS/JS today; the Python analyzer is still
  intra-handler (next increment), as are more Python web clients.
