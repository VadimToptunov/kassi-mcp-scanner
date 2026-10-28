import assert from "node:assert/strict";
import { test } from "node:test";
import { type Finding, scanSource } from "../src/detect.js";

// every snippet is a real MCP file (imports the SDK) so the file-gate passes
const mcp = (body: string) =>
  scanSource(`import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n${body}`, "server.ts");
const ids = (f: Finding[]) => f.map((x) => x.id).sort();

test("command injection: tool arg -> child_process.exec", () => {
  const f = mcp(`
    import cp from "node:child_process";
    server.tool("sh", async (args) => { cp.exec("ls " + args.dir); });`);
  assert.deepEqual(ids(f), ["cmd-injection"]);
  assert.equal(f[0].severity, "HIGH");
});

test("command injection via execa template ($) with tainted value", () => {
  const f = mcp(`server.tool("sh", async (args) => { await $\`git clone \${args.repo}\`; });`);
  assert.ok(f.some((x) => x.id === "cmd-injection"));
});

test("code execution: request input -> eval", () => {
  const f = mcp(`
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      return eval(request.params.arguments.expr);
    });`);
  assert.deepEqual(ids(f), ["code-exec"]);
});

test("path traversal: tool arg -> fs.readFile (and basename() clears it)", () => {
  const vuln = mcp(`
    import fs from "node:fs/promises";
    server.tool("read", async (args) => fs.readFile(args.path, "utf8"));`);
  assert.deepEqual(ids(vuln), ["path-traversal"]);
  const safe = mcp(`
    import fs from "node:fs/promises";
    import path from "node:path";
    server.tool("read", async (args) => fs.readFile(path.basename(args.path), "utf8"));`);
  assert.deepEqual(ids(safe), [], "basename() strips traversal");
});

test("SSRF: tainted URL = HIGH; tainted body only = MEDIUM", () => {
  const url = mcp(`server.tool("f", async (args) => { await fetch(args.url); });`);
  assert.equal(url.find((x) => x.id === "ssrf")?.severity, "HIGH");
  const body = mcp(`server.tool("f", async (args) => { await fetch("https://fixed.example", { body: args.data }); });`);
  assert.equal(body.find((x) => x.id === "ssrf")?.severity, "MEDIUM");
});

test("SQL injection: template-interpolated tainted query (but parameterized is safe)", () => {
  const vuln = mcp(`server.tool("q", async (args) => { await db.query(\`SELECT * FROM t WHERE id='\${args.id}'\`); });`);
  assert.deepEqual(ids(vuln), ["sql-injection"]);
  const safe = mcp(`server.tool("q", async (args) => { await db.query("SELECT * FROM t WHERE id=?", [args.id]); });`);
  assert.deepEqual(ids(safe), [], "parameterized query is not flagged");
});

test("taint flows through aliasing and string ops", () => {
  const f = mcp(`
    import cp from "node:child_process";
    server.tool("sh", async (args) => {
      const d = args.dir;
      const cmd = "ls " + d.trim();
      cp.execSync(cmd);
    });`);
  assert.deepEqual(ids(f), ["cmd-injection"]);
});

test("sanitized / validated input is not flagged", () => {
  const f = mcp(`
    import cp from "node:child_process";
    server.tool("sh", async (args) => { cp.exec(sanitizeShellArg(args.dir)); });`);
  assert.deepEqual(ids(f), []);
});

test("static / non-tainted sinks are NOT flagged (low FP)", () => {
  assert.deepEqual(mcp(`
    import cp from "node:child_process";
    server.tool("t", async (args) => { cp.exec("git status"); });`), [], "constant command");
  assert.deepEqual(mcp(`
    import fs from "node:fs";
    server.tool("t", async (args) => { fs.readFile("./config.json", cb); });`), [], "constant path");
});

test("a regex .exec() is not a command-injection sink", () => {
  const f = mcp(`server.tool("t", async (args) => { const m = /x/.exec(args.q); return m; });`);
  assert.deepEqual(ids(f), [], "RegExp.exec is not child_process.exec");
});

test("non-MCP file is skipped entirely", () => {
  assert.deepEqual(scanSource(`import cp from "child_process"; app.get("/", (req) => cp.exec(req.query.x));`, "app.ts"), []);
});
