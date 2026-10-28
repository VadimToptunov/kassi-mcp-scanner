// Parsing layer. MCP servers ship as TypeScript source, which acorn can't parse, so we
// transpile TS -> JS with the TypeScript compiler (type-strip only, no type-check — fast and
// tolerant of missing deps) and then parse the emitted JS with acorn. Plain .js parses directly.
// Reusing acorn + acorn-walk keeps the taint engine identical to the other Kassi scanners.

import * as acorn from "acorn";
import ts from "typescript";

// Minimal structural node type (acorn nodes are untyped at runtime).
export type Node = any;

/** Parse one source file into an acorn AST (with locations). Returns null if it can't be parsed. */
export function parse(source: string, filename = "input.ts"): Node | null {
  const isTs = /\.(ts|tsx|mts|cts)$/.test(filename) || /:\s*\w+\s*[=)]|interface\s|\bimport\s+type\b|\bas\s+const\b/.test(source);
  let js = source;
  if (isTs) {
    try {
      js = ts.transpileModule(source, {
        fileName: filename,
        compilerOptions: {
          target: ts.ScriptTarget.ES2022,
          module: ts.ModuleKind.ESNext,
          jsx: /\.tsx$/.test(filename) ? ts.JsxEmit.Preserve : ts.JsxEmit.None,
          isolatedModules: true,
          verbatimModuleSyntax: false,
        },
        reportDiagnostics: false,
      }).outputText;
    } catch {
      js = source; // fall back to raw (may still parse if it's really JS)
    }
  }
  for (const opts of [{ ecmaVersion: "latest" as const, sourceType: "module" as const, locations: true },
                      { ecmaVersion: "latest" as const, sourceType: "script" as const, locations: true }]) {
    try {
      return acorn.parse(js, opts) as unknown as Node;
    } catch { /* try next */ }
  }
  return null;
}

/** Dotted name of a (possibly nested, non-computed) MemberExpression: `a.b.c`. "" if dynamic. */
export function memberName(n: Node | undefined): string {
  if (!n) return "";
  if (n.type === "Identifier") return n.name;
  if (n.type === "ThisExpression") return "this";
  if (n.type === "MemberExpression" && !n.computed) {
    const obj = memberName(n.object);
    const prop = n.property?.name ?? "";
    return obj && prop ? `${obj}.${prop}` : prop;
  }
  return "";
}

/** The last argument that is a function (arrow or function expression) — i.e. a handler callback. */
export function lastFnArg(args: Node[]): Node | undefined {
  for (let i = args.length - 1; i >= 0; i--) {
    const a = args[i];
    if (a && (a.type === "ArrowFunctionExpression" || a.type === "FunctionExpression")) return a;
  }
  return undefined;
}
