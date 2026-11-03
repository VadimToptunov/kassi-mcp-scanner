// Parsing layer. MCP servers ship as TypeScript source, which acorn can't parse, so we
// transpile TS -> JS with the TypeScript compiler (type-strip only, no type-check — fast and
// tolerant of missing deps) and then parse the emitted JS with acorn. Plain .js parses directly.
// Reusing acorn + acorn-walk keeps the taint engine identical to the other Kassi scanners.

import * as acorn from "acorn";
import * as walk from "acorn-walk";
import ts from "typescript";

// Minimal structural node type (acorn nodes are untyped at runtime).
export type Node = any;

// ---- TS -> source line mapping ---------------------------------------------
// We transpile TS to JS (type-strip) before acorn, which DELETES type-only lines (interfaces, type
// aliases, `import type`) and so shifts every line below them. A finding's `loc` then points at a
// transpiled line, not the source the user reads. We emit a source map with the transpile and remap
// each node's loc line back to the original, so every detector reports the real source line for free.

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/** Decode one base64-VLQ-encoded source-map segment into its signed integer fields. */
function decodeVlq(seg: string): number[] {
  const out: number[] = [];
  let shift = 0, value = 0;
  for (const ch of seg) {
    const digit = B64.indexOf(ch);
    if (digit === -1) continue;
    value += (digit & 31) << shift;
    if (digit & 32) { shift += 5; continue; }
    const n = value >> 1;
    out.push(value & 1 ? -n : n);
    value = 0; shift = 0;
  }
  return out;
}

interface Seg { col: number; srcLine: number } // one mapping on a generated line (generated col -> source line)

/** Build a (genLine, genCol) -> original source line (1-based) mapper from a source map's `mappings`.
 *  Column-aware: for a position it uses the segment with the greatest generated column <= genCol (the
 *  mapping that opens the construct at that position), which is exact enough for line reporting even
 *  when one generated line carries several source constructs. Generated lines with no mapping, and
 *  positions before the first segment, carry the nearest preceding mapped line. */
function buildLineMapper(mappingsText: string): (genLine: number, genCol: number) => number {
  const lines = mappingsText.split(";");
  const perLine: Seg[][] = new Array(lines.length);
  let srcLine = 0; // source line/col/index fields are cumulative across the WHOLE map, not per line
  let genCol = 0;
  for (let gi = 0; gi < lines.length; gi++) {
    genCol = 0; // generated column resets at each generated line
    const segs: Seg[] = [];
    for (const seg of lines[gi].split(",")) {
      if (!seg) continue;
      const f = decodeVlq(seg);
      genCol += f[0] ?? 0;
      if (f.length >= 4) { // [genColDelta, srcIdxDelta, srcLineDelta, srcColDelta, (nameIdxDelta)]
        srcLine += f[2];
        segs.push({ col: genCol, srcLine });
      }
    }
    perLine[gi] = segs;
  }
  const lastLineAtOrBefore = (gi: number): number | undefined => {
    for (let i = gi; i >= 0; i--) { const s = perLine[i]; if (s && s.length) return s[s.length - 1].srcLine; }
    return undefined;
  };
  return (genLine: number, genCol: number): number => {
    const gi = genLine - 1;
    if (gi < 0 || gi >= perLine.length) return genLine;
    const segs = perLine[gi];
    if (segs && segs.length) {
      let pick = segs[0].col <= genCol ? segs[0].srcLine : undefined;
      for (const s of segs) { if (s.col <= genCol) pick = s.srcLine; else break; }
      if (pick !== undefined) return pick + 1;
    }
    const carried = lastLineAtOrBefore(gi - 1); // position precedes this line's first mapping
    return carried !== undefined ? carried + 1 : genLine;
  };
}

/** Rewrite every node's loc line (start/end) through `map`, in place, using each endpoint's column.
 *  Columns themselves are left untouched — the scanner reports lines only. */
function remapLocLines(ast: Node, map: (line: number, col: number) => number): void {
  walk.full(ast as any, (node: any) => {
    if (!node.loc) return;
    if (node.loc.start) node.loc.start.line = map(node.loc.start.line, node.loc.start.column ?? 0);
    if (node.loc.end) node.loc.end.line = map(node.loc.end.line, node.loc.end.column ?? 0);
  });
}

/** Parse one source file into an acorn AST (with locations). Returns null if it can't be parsed. */
export function parse(source: string, filename = "input.ts"): Node | null {
  const isTs = /\.(ts|tsx|mts|cts)$/.test(filename) || /:\s*\w+\s*[=)]|interface\s|\bimport\s+type\b|\bas\s+const\b/.test(source);
  let js = source;
  let lineMap: ((line: number, col: number) => number) | null = null;
  if (isTs) {
    try {
      const res = ts.transpileModule(source, {
        fileName: filename,
        compilerOptions: {
          target: ts.ScriptTarget.ES2022,
          module: ts.ModuleKind.ESNext,
          jsx: /\.tsx$/.test(filename) ? ts.JsxEmit.Preserve : ts.JsxEmit.None,
          isolatedModules: true,
          verbatimModuleSyntax: false,
          sourceMap: true, // so we can map transpiled lines back to the source the user reads
        },
        reportDiagnostics: false,
      });
      js = res.outputText; // carries a trailing //# sourceMappingURL comment — harmless to acorn
      if (res.sourceMapText) {
        try { lineMap = buildLineMapper(JSON.parse(res.sourceMapText).mappings ?? ""); } catch { lineMap = null; }
      }
    } catch {
      js = source; // fall back to raw (may still parse if it's really JS)
      lineMap = null;
    }
  }
  for (const opts of [{ ecmaVersion: "latest" as const, sourceType: "module" as const, locations: true },
                      { ecmaVersion: "latest" as const, sourceType: "script" as const, locations: true }]) {
    try {
      const ast = acorn.parse(js, opts) as unknown as Node;
      if (lineMap) remapLocLines(ast, lineMap);
      return ast;
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
