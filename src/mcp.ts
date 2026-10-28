// Identify MCP request handlers and the parameter(s) that carry ATTACKER-INFLUENCED input.
//
// In an MCP server the tool/resource/prompt arguments come from the LLM client — which an
// attacker can steer via prompt injection, or control outright with a malicious/compromised
// client. So the handler's input parameter is the taint SOURCE, exactly like a web message
// handler's `event.data`. We only treat a file as an MCP server if it imports the SDK, so a
// stray `.tool(...)` in an unrelated project is not scanned.

import { type Node, lastFnArg, memberName } from "./analyze.js";
import * as walk from "acorn-walk";

export type HandlerKind = "tool" | "resource" | "prompt" | "request";

export interface Handler {
  kind: HandlerKind;
  fn: Node; // the handler function
  sources: string[]; // local identifier names bound to attacker-controlled input
  label: string; // tool/resource name (if a string literal) for the finding
  line?: number;
}

/** Only scan real MCP servers: the file must pull in the MCP SDK. */
export function isMcpFile(source: string): boolean {
  return /@modelcontextprotocol\/sdk|\bMcpServer\b|\bCallToolRequestSchema\b|\bReadResourceRequestSchema\b/.test(source);
}

// request schemas whose handler receives attacker input worth tainting
const INPUT_SCHEMA = /^(CallTool|ReadResource|GetPrompt|Complete)RequestSchema$/;

/** Local names bound by a handler parameter (Identifier, or destructured ObjectPattern w/ rename). */
function paramNames(param: Node | undefined): string[] {
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

/** Find every MCP handler and the tainted source names in it. */
export function findHandlers(ast: Node): Handler[] {
  const out: Handler[] = [];
  walk.simple(ast as any, {
    CallExpression(n: any) {
      const callee = n.callee;
      if (callee?.type !== "MemberExpression" || callee.computed) return;
      const prop = callee.property?.name ?? "";
      const args: Node[] = n.arguments ?? [];
      const fn = lastFnArg(args);

      if (/^(tool|registerTool|prompt|registerPrompt)$/.test(prop)) {
        if (!fn) return;
        out.push({ kind: prop.includes("rompt") ? "prompt" : "tool", fn, sources: paramNames(fn.params?.[0]), label: labelOf(args), line: n.loc?.start.line });
        return;
      }
      if (/^(resource|registerResource)$/.test(prop)) {
        if (!fn) return;
        // resource(name, template, (uri, vars) => …): both the URI and the template vars are tainted
        const sources = [...paramNames(fn.params?.[0]), ...paramNames(fn.params?.[1])];
        out.push({ kind: "resource", fn, sources, label: labelOf(args), line: n.loc?.start.line });
        return;
      }
      if (prop === "setRequestHandler") {
        const schema = memberName(args[0]) || (args[0]?.type === "Identifier" ? args[0].name : "");
        if (!INPUT_SCHEMA.test(schema.replace(/^.*\./, ""))) return; // ListTools/etc. carry no input
        if (!fn) return;
        out.push({ kind: "request", fn, sources: paramNames(fn.params?.[0]), label: schema, line: n.loc?.start.line });
      }
    },
  });
  return out;
}
