# kassi-mcp-scanner

Static security scanner for **MCP (Model Context Protocol) servers**. In an MCP server the
tool / resource / prompt arguments come from the LLM client — which an attacker can steer by
prompt injection, or control outright with a malicious client. So the handler's input parameter
is an attacker-controlled **taint source**, exactly like a web message handler's `event.data`.
This scanner finds that input flowing into a dangerous **sink**.

4th tool in the Kassi scanner family (after WP, Android, browser-extension). Same taint-engine
approach, acorn AST. TypeScript source is type-stripped with the TS compiler, then parsed — so it
eats `.ts` and `.js` MCP servers alike. Static only: **no code is executed**, so no Docker needed.

## Vulnerability classes (v0.1.0, TS/JS servers)

| id | CWE | sink |
|---|---|---|
| `cmd-injection` | CWE-78 | `child_process.exec/spawn/...`, `execa`, `$\`…\`` shell templates |
| `code-exec` | CWE-94 | `eval`, `Function`, `vm.runInNewContext`, `new vm.Script` |
| `path-traversal` | CWE-22 | `fs.*` read/write with a tainted path (basename-guarded paths are cleared) |
| `ssrf` | CWE-918 | `fetch` / `axios` / `http(s)` with a tainted URL (HIGH) or body (MEDIUM) |
| `sql-injection` | CWE-89 | tainted value interpolated into a raw `db.query`/`execute` (parameterized is safe) |

Handlers recognized: `server.tool` / `registerTool` / `prompt`, `server.resource` / `registerResource`,
and `setRequestHandler(CallTool|ReadResource|GetPrompt|Complete RequestSchema, …)`. Only files that
import `@modelcontextprotocol/sdk` are scanned, so unrelated `.tool()`/`.exec()` calls aren't touched.

## Usage

```bash
npm install && npm run build
npm run scan -- path/to/mcp-server            # or: node dist/cli.js <path>
npm run scan -- ./src --min HIGH              # only HIGH findings (exit 1 if any — CI gate)
npm run scan -- ./src --json                  # machine-readable
```

## Honest scope

- v1 is TypeScript/JavaScript servers. Python MCP servers (the `mcp` package) need a Python AST — later.
- It's a taint-based lead generator: a HIGH finding means attacker input reaches a dangerous sink with
  no guard it could see. Confirm exploitability (and the server's real trust model) by hand before
  reporting. It does not model prompt-injection semantics, only the code-level data flow.
