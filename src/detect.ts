// Taint the MCP/AI handler's input parameter(s) through the handler body and flag dangerous sinks.
// Source = attacker-influenced tool/resource/prompt input (see mcp.ts). Static (AST) only.
//
// Cross-function resolution: real servers register a thin wrapper that FORWARDS the tool args to a
// service-layer function (often in another file), e.g.
//     server.registerTool(name, schema, (params) => getFigmaDataTool.handler(params, svc, …))
// so the sink is one call away from the taint source. We index every function across the project
// (incl. object methods `const X = { handler: fn }` -> "X.handler"), and when a tainted argument is
// forwarded into a resolvable function we recurse into it, mapping the forwarded args to its params
// (bounded depth, visited-set for cycles). Without this the scanner reports false-clean on most servers.

import * as walk from "acorn-walk";
import { type Node, memberName, parse } from "./analyze.js";
import { type Handler, findHandlers, isMcpFile, paramNames } from "./mcp.js";

export type Severity = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  id: string;
  cwe: string;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  line?: number;
  handler: string;
}

const SANITIZER = /sanitiz|escape|allowlist|whitelist|validate|isAllowed|assert|zod|schema\.parse/i;
const INJECTION = /ignore\s+(?:all\s+|the\s+)?(?:previous|above|prior)\s+(?:instructions|context|messages)|disregard\s+(?:the\s+)?(?:previous|above|prior)|do\s+not\s+(?:tell|inform|mention|notify|reveal).{0,20}\buser\b|without\s+(?:telling|informing|notifying|alerting).{0,20}\buser\b|exfiltrat|<important>|<secret>|\bsystem\s+prompt\b|you\s+must\s+(?:always|secretly|silently)|send\s+(?:the\s+|all\s+|any\s+)?(?:data|files?|contents?|credentials?|secrets?|keys?|\.env)\b|read\s+(?:the\s+)?(?:~\/\.ssh|\.env|id_rsa|credentials)/i;
const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿]|[\u{e0000}-\u{e007f}]/u;

const MAX_DEPTH = 4; // handler -> service -> … forward chain

// ---- taint -----------------------------------------------------------------

function refsTaint(node: Node | undefined, taint: Set<string>): boolean {
  if (!node) return false;
  let found = false;
  walk.simple(node as any, { Identifier(x: any) { if (taint.has(x.name)) found = true; } });
  return found;
}

function unwrapAwait(node: Node | undefined): Node | undefined {
  return node?.type === "AwaitExpression" ? node.argument : node;
}

function isSanitized(node: Node | undefined): boolean {
  const n = unwrapAwait(node);
  if (!n || n.type !== "CallExpression") return false;
  const name = memberName(n.callee) || (n.callee?.type === "Identifier" ? n.callee.name : "");
  return SANITIZER.test(name);
}

function stripsTraversal(node: Node | undefined): boolean {
  const n = unwrapAwait(node);
  if (!n || n.type !== "CallExpression") return false;
  return /(^|\.)basename$/.test(memberName(n.callee));
}

/** Does this statement guarantee the path exits (throw / return / process.exit)? */
function bounces(node: Node | undefined): boolean {
  if (!node) return false;
  if (node.type === "ThrowStatement" || node.type === "ReturnStatement") return true;
  if (node.type === "BlockStatement") return (node.body ?? []).some(bounces);
  if (node.type === "ExpressionStatement") return /(^|\.)exit$/.test(memberName(node.expression?.callee));
  return false;
}

/** Names CONTENT-validated by a bouncer guard: `if (!isApifyApiUri(uri)) throw`, `if (!x.startsWith(B))
 *  return`, `if (RE.test(x)) throw`, `if (!allow.has(host)) throw`. A bare presence/null check does NOT
 *  count (clearing it would miss real injection). Flow-insensitive, like the sanitizer-wrapper handling. */
const VALIDATOR_METHOD = /^(startsWith|endsWith|includes|match|test|has|search|indexOf|every|some)$/;
function guardValidatedNames(fn: Node, taint: Set<string>): Set<string> {
  const validated = new Set<string>();
  const addNames = (node: Node | undefined) => {
    if (!node) return;
    walk.simple(node as any, { Identifier(x: any) { if (taint.has(x.name)) validated.add(x.name); } });
  };
  walk.simple(fn as any, {
    IfStatement(n: any) {
      if (!bounces(n.consequent)) return;
      walk.simple(n.test as any, {
        CallExpression(c: any) {
          for (const a of c.arguments ?? []) addNames(a); // predicate(x) / allow.has(x) / RE.test(x)
          if (c.callee?.type === "MemberExpression" && VALIDATOR_METHOD.test(c.callee.property?.name ?? "")) addNames(c.callee.object); // x.startsWith(B)
        },
      });
    },
  });
  return validated;
}

function taintOf(fn: Node, sources: string[]): Set<string> {
  const taint = new Set<string>(sources);
  for (let pass = 0; pass < 6; pass++) {
    const before = taint.size;
    walk.simple(fn as any, {
      VariableDeclarator(n: any) {
        if (n.id?.type === "Identifier" && !isSanitized(n.init) && refsTaint(n.init, taint)) taint.add(n.id.name);
      },
      AssignmentExpression(n: any) {
        if (n.left?.type === "Identifier" && !isSanitized(n.right) && refsTaint(n.right, taint)) taint.add(n.left.name);
      },
    });
    if (taint.size === before) break;
  }
  // a bouncer guard that content-validates a tainted value clears it downstream (guard-by-throw)
  for (const v of guardValidatedNames(fn, taint)) taint.delete(v);
  return taint;
}

// ---- project function index (for cross-function resolution) ----------------

interface IndexedFn { fn: Node; file: string; }

/** name / "Obj.method" -> function node(s). Ambiguous names (>1) are left unresolved to avoid FPs. */
function buildIndex(parsed: Array<{ file: string; ast: Node }>): Map<string, IndexedFn[]> {
  const idx = new Map<string, IndexedFn[]>();
  const add = (key: string, fn: Node, file: string) => {
    if (!key || !fn) return;
    const list = idx.get(key) ?? [];
    list.push({ fn, file });
    idx.set(key, list);
  };
  const isFn = (n: Node | undefined) => n && (n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression");
  for (const { file, ast } of parsed) {
    walk.simple(ast as any, {
      FunctionDeclaration(n: any) { if (n.id?.name) add(n.id.name, n, file); },
      VariableDeclarator(n: any) {
        if (n.id?.type !== "Identifier" || !n.init) return;
        if (isFn(n.init)) add(n.id.name, n.init, file);
        else if (n.init.type === "ObjectExpression") {
          for (const p of n.init.properties ?? []) {
            const k = p.key?.name ?? p.key?.value;
            if (typeof k === "string" && isFn(p.value)) add(`${n.id.name}.${k}`, p.value, file);
          }
        }
      },
      MethodDefinition(n: any) { // class methods: X.method via the enclosing class name is hard; index bare method name
        if (n.key?.name && isFn(n.value)) add(n.key.name, n.value, file);
      },
    });
  }
  return idx;
}

/** Resolve a call's callee to a unique indexed function (dotted name > property name > identifier). */
function resolveCall(callee: Node, idx: Map<string, IndexedFn[]>): IndexedFn | null {
  const keys: string[] = [];
  const dotted = memberName(callee);
  if (dotted) keys.push(dotted);
  if (callee?.type === "MemberExpression" && !callee.computed && callee.property?.name) keys.push(callee.property.name);
  if (callee?.type === "Identifier") keys.push(callee.name);
  for (const k of keys) {
    const hit = idx.get(k);
    if (hit && hit.length === 1) return hit[0]; // unique only — ambiguous names skipped
  }
  return null;
}

// ---- sinks -----------------------------------------------------------------

const CP_METHOD = /^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/;
const CP_BARE = /^(exec|execSync|execFile|execFileSync|spawn|spawnSync|execa|execaSync|execaCommand|execaCommandSync|\$)$/;
const CP_OBJ = /(^|\.)(cp|childProcess|child_process|execa|shell|shelljs|sh|zx)$/i;
const FS_METHOD = /^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|open|openSync|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|stat|statSync|realpath|readlink|copyFile|copyFileSync)$/;
const FS_OBJ = /(^|\.)(fs|fsp|fsPromises|promises)$/i;
const NET_OBJ = /(^|\.)(axios|got|http|https|needle|superagent|undici|ky)$/i;
const NET_METHOD = /^(get|post|put|patch|delete|request|fetch|head)$/;
const SQL_METHOD = /^(query|execute|unsafe|raw)$/;
const SQL_OBJ = /(^|\.)(db|database|conn|connection|pool|client|sequelize|knex|sql|prisma|pg|mysql|sqlite|cursor)$/i;

function isConcatOrTemplate(n: Node | undefined): boolean {
  return !!n && (n.type === "TemplateLiteral" || (n.type === "BinaryExpression" && n.operator === "+"));
}

interface Ctx {
  idx: Map<string, IndexedFn[]>;
  out: Finding[];
  label: string; // handler label for attribution
}

/** Analyze one function with a taint seed; emit sinks and recurse into forwarded functions. */
function analyzeFn(fn: Node, seed: string[], file: string, ctx: Ctx, depth: number, visited: Set<Node>, via: string): void {
  if (!fn || visited.has(fn) || depth > MAX_DEPTH) return;
  visited.add(fn);
  const taint = taintOf(fn, seed);
  const where = ctx.label + (via ? ` (via ${via})` : "");
  const tainted = (node: Node | undefined) => node && !isSanitized(node) && refsTaint(node, taint);

  const emit = (id: string, cwe: string, severity: Severity, title: string, detail: string, line?: number) =>
    ctx.out.push({ id, cwe, severity, title: `${title} in MCP ${where}`, detail, file, line, handler: where });

  walk.simple(fn as any, {
    CallExpression(n: any) {
      const callee = n.callee;
      const args: Node[] = n.arguments ?? [];
      const bare = callee?.type === "Identifier" ? callee.name : "";
      const full = memberName(callee);
      const prop = callee?.type === "MemberExpression" ? (callee.property?.name ?? "") : "";
      const obj = callee?.type === "MemberExpression" ? memberName(callee.object) : "";

      const isCp = CP_BARE.test(bare) || (CP_METHOD.test(prop) && CP_OBJ.test(obj));
      if (isCp && args.some((a) => tainted(a)))
        emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command execution sink",
          `Attacker-influenced MCP input flows into \`${full || bare}(...)\`. A malicious tool call can inject OS commands. Use execFile with a fixed binary + array args, never a shell string.`, n.loc?.start.line);

      if ((bare === "eval" || bare === "Function" || /(^|\.)(runInNewContext|runInContext|compileFunction)$/.test(full)) && args.some((a) => tainted(a)))
        emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
          `Attacker-influenced MCP input flows into \`${full || bare}(...)\` — arbitrary code execution in the server process.`, n.loc?.start.line);

      const isFs = FS_METHOD.test(prop) && FS_OBJ.test(obj);
      if (isFs && args[0] && !stripsTraversal(args[0]) && tainted(args[0]))
        emit("path-traversal", "CWE-22", "HIGH", "Tool input reaches a filesystem path sink",
          `Attacker-influenced MCP input is used as the path in \`${full}(...)\` with no traversal guard — a crafted \`../\` reads/writes arbitrary files. Resolve against a fixed root and reject paths that escape it.`, n.loc?.start.line);

      const isNet = bare === "fetch" || bare === "axios" || (NET_METHOD.test(prop) && NET_OBJ.test(obj)) || /(^|\.)fetch$/.test(full);
      if (isNet && args[0]) {
        if (tainted(args[0])) emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
          `Attacker-influenced MCP input is the URL of \`${full || bare}(...)\` — SSRF: the attacker picks the destination (internal metadata endpoints, localhost services). Allowlist hosts.`, n.loc?.start.line);
        else if (args.slice(1).some((a) => tainted(a))) emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
          `Attacker-influenced MCP input is in the body/options of \`${full || bare}(...)\` (data egress, not URL control). Confirm the destination is trusted.`, n.loc?.start.line);
      }

      if (SQL_METHOD.test(prop) && SQL_OBJ.test(obj) && isConcatOrTemplate(args[0]) && tainted(args[0]))
        emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
          `Attacker-influenced MCP input is concatenated/templated into \`${full}(...)\` instead of a parameterized query — SQL injection. Use bound parameters.`, n.loc?.start.line);

      // cross-function forward: a tainted arg handed to a resolvable function -> follow it.
      // but NOT into a guard/validator (validatePath/sanitize/…): its internals legitimately
      // handle the raw path (realpath/readdir) — following in would re-flag the guard itself.
      const resolved = isSanitized(n) ? null : resolveCall(callee, ctx.idx);
      if (resolved && !visited.has(resolved.fn)) {
        const params: Node[] = resolved.fn.params ?? [];
        const nextSeed = new Set<string>();
        args.forEach((a, i) => {
          if (!tainted(a)) return;
          const p = params[i] ?? params.find((pp) => pp?.type === "RestElement");
          for (const nm of paramNames(p)) nextSeed.add(nm);
        });
        if (nextSeed.size) analyzeFn(resolved.fn, [...nextSeed], resolved.file, ctx, depth + 1, visited, via ? `${via} -> ${full || bare}` : (full || bare));
      }
    },
    TaggedTemplateExpression(n: any) {
      const tag = n.tag?.type === "Identifier" ? n.tag.name : memberName(n.tag);
      if ((/^\$$/.test(tag) || /(^|\.)(execa|zx|sh|\$)$/.test(tag)) && (n.quasi?.expressions ?? []).some((e: Node) => refsTaint(e, taint)))
        emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command execution sink",
          `Attacker-influenced MCP input is interpolated into a shell template \`${tag}\`...\`\` — a malicious tool call can inject OS commands.`, n.loc?.start.line);
    },
    NewExpression(n: any) {
      if (/(^|\.)Script$/.test(memberName(n.callee)) && (n.arguments ?? []).some((a: Node) => a && refsTaint(a, taint)))
        emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
          `Attacker-influenced MCP input flows into \`new vm.Script(...)\` — arbitrary code execution.`, n.loc?.start.line);
    },
  });

  // secret exposure: the WHOLE process.env object (not a single process.env.X read)
  walk.ancestor(fn as any, {
    MemberExpression(node: any, _s: unknown, ancestors: any[]) {
      if (node.computed || node.object?.type !== "Identifier" || node.object.name !== "process" || node.property?.name !== "env") return;
      const parent = ancestors[ancestors.length - 2];
      if (parent && parent.type === "MemberExpression" && parent.object === node && !parent.computed) return;
      emit("secret-exposure", "CWE-200", "MEDIUM", "Whole `process.env` is used (secret exposure risk)",
        `The ${where} uses the entire \`process.env\` object (not a single named var). If it is returned, serialized, or sent, every environment secret leaks to the client. Return only the specific values you mean to.`, node.loc?.start.line);
    },
  });
}

// ---- entry points ----------------------------------------------------------

/** Scan a whole project: parse all files for the cross-function index, then analyze MCP handlers. */
export function scanProject(files: Array<{ file: string; source: string }>): Finding[] {
  const parsed: Array<{ file: string; source: string; ast: Node }> = [];
  for (const f of files) {
    const ast = parse(f.source, f.file);
    if (ast) parsed.push({ file: f.file, source: f.source, ast });
  }
  const idx = buildIndex(parsed);
  const out: Finding[] = [];
  for (const { file, source, ast } of parsed) {
    if (!isMcpFile(source)) continue;
    for (const h of findHandlers(ast)) {
      const ctx: Ctx = { idx, out, label: `${h.kind} "${h.label}"` };
      // tool-poisoning: injection text / invisible unicode in the registration metadata
      for (const s of h.metaStrings) {
        if (INVISIBLE.test(s)) { out.push(poison(file, h, `contains zero-width / bidi / unicode-tag characters — a channel for instructions the human reviewer can't see but the model reads (tool poisoning / rug-pull).`)); break; }
        if (INJECTION.test(s)) { out.push(poison(file, h, `contains model-directed instructions (e.g. "${s.slice(0, 60).replace(/\s+/g, " ")}…") — a malicious or rug-pulled server covertly steering the client model.`)); break; }
      }
      analyzeFn(h.fn, h.sources, file, ctx, 0, new Set<Node>(), "");
    }
  }
  return out;
}

function poison(file: string, h: Handler, why: string): Finding {
  return { id: "tool-poisoning", cwe: "CWE-94", severity: "HIGH",
    title: `Prompt-injection / hidden text in the tool description in MCP ${h.kind} "${h.label}"`,
    detail: `The ${h.kind} "${h.label}" description/schema ${why}`, file, line: h.line, handler: `${h.kind} "${h.label}"` };
}

/** Scan one source file (cross-function resolution limited to that file). */
export function scanSource(source: string, file = "input.ts"): Finding[] {
  if (!isMcpFile(source)) return [];
  return scanProject([{ file, source }]);
}
