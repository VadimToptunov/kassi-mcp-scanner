import assert from "node:assert/strict";
import { test } from "node:test";
import { parse } from "../src/analyze.js";
import { findHandlers, isMcpFile } from "../src/mcp.js";

test("isMcpFile gates on the SDK import", () => {
  assert.ok(isMcpFile(`import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";`));
  assert.ok(isMcpFile(`server.setRequestHandler(CallToolRequestSchema, h)`));
  assert.ok(!isMcpFile(`import express from "express"; app.get("/", h)`));
});

test("high-level server.tool handler: param[0] is the tainted source", () => {
  const ast = parse(`
    server.tool("run", { cmd: z.string() }, async (args, extra) => { doThing(args.cmd); });
  `, "s.ts");
  const hs = findHandlers(ast);
  assert.equal(hs.length, 1);
  assert.equal(hs[0].kind, "tool");
  assert.equal(hs[0].label, "run");
  assert.deepEqual(hs[0].sources, ["args"]);
});

test("setRequestHandler(CallToolRequestSchema) taints the request param; ListTools is ignored", () => {
  const ast = parse(`
    server.setRequestHandler(CallToolRequestSchema, async (request) => { run(request.params.arguments.cmd); });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  `, "s.ts");
  const hs = findHandlers(ast);
  assert.equal(hs.length, 1, "only the input-bearing schema is a handler");
  assert.equal(hs[0].kind, "request");
  assert.deepEqual(hs[0].sources, ["request"]);
});

test("destructured + renamed params are tracked", () => {
  const ast = parse(`server.tool("t", async ({ arguments: a }) => use(a));`, "s.ts");
  assert.deepEqual(findHandlers(ast)[0].sources, ["a"]);
});

test("resource handler taints both uri and template vars", () => {
  const ast = parse(`server.resource("r", tmpl, async (uri, vars) => read(uri));`, "s.ts");
  const h = findHandlers(ast)[0];
  assert.equal(h.kind, "resource");
  assert.deepEqual(h.sources, ["uri", "vars"]);
});

test("TypeScript syntax is parsed (type annotations stripped)", () => {
  const ast = parse(`
    import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
    const server: McpServer = new McpServer({ name: "x", version: "1" });
    server.tool("t", async (args: { p: string }): Promise<void> => { sink(args.p); });
  `, "s.ts");
  assert.ok(ast, "TS parsed");
  assert.equal(findHandlers(ast).length, 1);
});
