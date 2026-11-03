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
| `ssrf-guard-bypass` | CWE-918 | a tainted URL passes a private-network/loopback **blocklist** guard that misses the known bypass forms — IPv6 `[::1]`, IPv4-mapped `::ffff:127.0.0.1`, `0.0.0.0`, encoded IPs (a *complete* guard or an allowlist is clean) |
| `unbounded-body` | CWE-770 | an HTTP transport accumulates a request body (`.on("data")` / `for await` / async stream) with no size cap before buffering/parsing |
| `unbounded-batch` | CWE-770 | a JSON-RPC batch (`Array.isArray`/`isinstance(...,list)`) is dispatched element-by-element with no length cap |
| `sql-injection` | CWE-89 | tainted value interpolated into a raw query (parameterized is safe) |
| `prototype-pollution` | CWE-1321 | **JS**: tool input into a recursive deep-merge / nested-set (`merge`/`defaultsDeep`/`_.set`) with no `__proto__`/`constructor` key guard |
| `redos` | CWE-1333 | tool input compiled into a regex (`new RegExp`/`re.compile`) or used as the pattern of `match`/`search`/`sub`… = HIGH; tool input matched against a catastrophic-backtracking literal = MEDIUM |
| `deserialization` | CWE-502 | **Py**: `pickle`/`dill`/`marshal` loads, or `yaml.load` without SafeLoader, on tainted input |
| `tool-poisoning` | CWE-94 | prompt-injection text or invisible unicode hidden in a tool's **description/docstring** |
| `secret-exposure` | CWE-200 | the whole `process.env` / `os.environ` object used (not a single named var) |

**Handlers recognized** — MCP: `server.tool`/`registerTool`/`prompt`, `resource`/`registerResource`,
`setRequestHandler(CallTool|ReadResource|GetPrompt|Complete)`, FastMCP `@mcp.tool()`/`@mcp.resource()`,
low-level `@server.call_tool()`, and FastAPI routes exposed via `fastapi-mcp`. Agent frameworks: LangChain
`tool(fn, …)` / `new DynamicStructuredTool({func})` / `@tool`, LlamaIndex `FunctionTool`, Vercel AI SDK
`tool({ execute })`, CrewAI `BaseTool._run`/`_arun`, AutoGen `@register_for_execution`/`register_function`.
Only files that import one of these frameworks are scanned, so unrelated `.tool()`/`.exec()` calls aren't
touched.

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

- **Cross-function / cross-file resolution (TS/JS *and* Python):** real servers register a thin wrapper
  that forwards the tool args to a service-layer function, often in another file. Both analyzers index
  every function across the project (TS: object methods `const X = { handler: fn }` → `X.handler`;
  Python: module functions + `Class.method`) and follow a tainted argument through resolvable forwards
  (bounded depth, cycle-safe, ambiguous names skipped, method `self`/`cls` offset handled, and they do
  **not** descend into guard/validator functions). The Python analyzer takes a project directory and
  walks it for the index.
- **Guard-by-throw:** a bouncer check that content-validates the input and then exits — `if
  (!isApifyApiUri(uri)) throw`, `if (!p.startsWith(base)) return`, `if (host not in ALLOW) raise` —
  clears that value downstream (TS and Python). A bare presence/null check (`if (!cmd) throw`) does not,
  so real injection is still caught. This removed the apify-mcp-server SSRF false positive (it has a
  strict Apify-origin allowlist gate).
- A taint-based lead generator: a HIGH finding means attacker-controlled tool input reaches a dangerous
  sink with no guard the scanner could see. Confirm exploitability (and the server's real trust model —
  some MCP servers are meant to run only locally for one user) by hand before reporting.
- Code-level data flow only; it does not model prompt-injection *semantics* beyond the tool-poisoning
  string/unicode heuristics. Resolution is unique-name based (ambiguous names are skipped, so a very
  generic method name shared by many classes won't be followed).
