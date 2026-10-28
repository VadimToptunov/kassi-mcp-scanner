// Identify AI tool/resource/prompt handlers and the parameter(s) that carry ATTACKER-INFLUENCED
// input. Covers MCP servers (@modelcontextprotocol/sdk) and, more broadly, agent frameworks whose
// tool arguments are model/client-controlled (LangChain, LlamaIndex). The handler's input parameter
// is the taint SOURCE — an attacker steers it via prompt injection or a malicious client.
// We only scan files that import one of those frameworks, so a stray `.tool(...)` elsewhere is safe.

import { type Node, lastFnArg, memberName } from "./analyze.js";
import * as walk from "acorn-walk";

export type HandlerKind = "tool" | "resource" | "prompt" | "request";

export interface Handler {
  kind: HandlerKind;
  fn: Node; // the handler function
  sources: string[]; // local identifier names bound to attacker-controlled input
  label: string; // tool/resource name (if a string literal) for the finding
  metaStrings: string[]; // string literals in the registration (name/description/schema docs) — for tool-poisoning
  line?: number;
}

/** Only scan AI tool servers: the file must pull in a known framework. */
export function isMcpFile(source: string): boolean {
  return /@modelcontextprotocol\/sdk|\bMcpServer\b|\bCallToolRequestSchema\b|\bReadResourceRequestSchema\b|@langchain\/|\bDynamic(Structured)?Tool\b|from\s+["']llamaindex["']|\bFunctionTool\b|\bfastmcp\b/i.test(source);
}

// request schemas whose handler receives attacker input worth tainting
const INPUT_SCHEMA = /^(CallTool|ReadResource|GetPrompt|Complete)RequestSchema$/;

/** Local names bound by a handler parameter (Identifier, or destructured ObjectPattern w/ rename). */
export function paramNames(param: Node | undefined): string[] {
  if (!param) return [];
  if (param.type === "AssignmentPattern") return paramNames(param.left); // default value
  if (param.type === "Identifier") return [param.name];
  if (param.type === "ObjectPattern") {
    const out: string[] = [];
    for (const p of param.properties ?? []) {
      const v = p.value ?? p.argument; // RestElement uses .argument
      if (v?.type === "Identifier") out.push(v.name);
      else out.push(...paramNames(v));
    }
    return out;
  }
  if (param.type === "RestElement") return paramNames(param.argument);
  return [];
}

function labelOf(args: Node[]): string {
  const a = args[0];
  return a?.type === "Literal" && typeof a.value === "string" ? a.value : "(dynamic)";
}

/** All string literals inside the given nodes (registration metadata: name, description, schema docs). */
function stringsIn(nodes: Node[]): string[] {
  const out: string[] = [];
  for (const n of nodes) {
    if (!n) continue;
    walk.simple(n as any, {
      Literal(x: any) { if (typeof x.value === "string" && x.value.length > 1) out.push(x.value); },
      TemplateLiteral(x: any) { for (const q of x.quasis ?? []) { const v = q.value?.cooked ?? q.value?.raw; if (v) out.push(v); } },
    });
  }
  return out;
}

/** Find every handler and the tainted source names + registration metadata strings in it. */
export function findHandlers(ast: Node): Handler[] {
  const out: Handler[] = [];
  const nonFnArgs = (args: Node[], fn: Node | undefined) => args.filter((a) => a !== fn);

  walk.simple(ast as any, {
    CallExpression(n: any) {
      const callee = n.callee;
      const args: Node[] = n.arguments ?? [];
      const fn = lastFnArg(args);

      // LangChain JS: tool(func, { name, description, schema }) — func is the FIRST arg.
      if (callee?.type === "Identifier" && callee.name === "tool") {
        const f = args.find((a) => a?.type === "ArrowFunctionExpression" || a?.type === "FunctionExpression");
        if (f) out.push({ kind: "tool", fn: f, sources: paramNames(f.params?.[0]), label: labelOf(args), metaStrings: stringsIn(nonFnArgs(args, f)), line: n.loc?.start.line });
        return;
      }

      if (callee?.type !== "MemberExpression" || callee.computed) return;
      const prop = callee.property?.name ?? "";

      if (/^(tool|registerTool|prompt|registerPrompt)$/.test(prop)) {
        if (!fn) return;
        out.push({ kind: prop.includes("rompt") ? "prompt" : "tool", fn, sources: paramNames(fn.params?.[0]), label: labelOf(args), metaStrings: stringsIn(nonFnArgs(args, fn)), line: n.loc?.start.line });
        return;
      }
      if (/^(resource|registerResource)$/.test(prop)) {
        if (!fn) return;
        const sources = [...paramNames(fn.params?.[0]), ...paramNames(fn.params?.[1])];
        out.push({ kind: "resource", fn, sources, label: labelOf(args), metaStrings: stringsIn(nonFnArgs(args, fn)), line: n.loc?.start.line });
        return;
      }
      if (prop === "setRequestHandler") {
        const schema = memberName(args[0]) || (args[0]?.type === "Identifier" ? args[0].name : "");
        if (!INPUT_SCHEMA.test(schema.replace(/^.*\./, ""))) return;
        if (!fn) return;
        out.push({ kind: "request", fn, sources: paramNames(fn.params?.[0]), label: schema, metaStrings: [], line: n.loc?.start.line });
      }
    },
    // LangChain/LlamaIndex class tools: new DynamicStructuredTool({ func, name, description, schema })
    NewExpression(n: any) {
      const name = n.callee?.type === "Identifier" ? n.callee.name : memberName(n.callee);
      if (!/(^|\.)(DynamicStructuredTool|DynamicTool|FunctionTool)$/.test(name)) return;
      const cfg = (n.arguments ?? []).find((a: Node) => a?.type === "ObjectExpression");
      if (!cfg) return;
      let fn: Node | undefined;
      for (const p of cfg.properties ?? []) {
        const k = p.key?.name ?? p.key?.value;
        if ((k === "func" || k === "function" || k === "fn") && (p.value?.type === "ArrowFunctionExpression" || p.value?.type === "FunctionExpression")) fn = p.value;
      }
      if (!fn) return;
      out.push({ kind: "tool", fn, sources: paramNames(fn.params?.[0]), label: "(DynamicTool)", metaStrings: stringsIn([cfg]), line: n.loc?.start.line });
    },
  });
  return out;
}
