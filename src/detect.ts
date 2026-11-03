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

// ---- unsafe-autonomy design smell (tool DESCRIPTION, not taint) -------------
// Seeded by a field report of a personal agent with a bank card + browser + phone
// (habr.com/ru/articles/1097430): the agent's failures were irreversible real-world actions taken
// with no human gate — a recurring purchase with no stop condition and a blind re-charge on retry.
// At the MCP layer the analogue is a tool whose OWN description steers the client model to take a
// high-stakes action autonomously. We flag two text patterns (never an absence — that would FP):
//   1) a high-stakes/irreversible tool whose description removes the confirmation step; and
//   2) a money-moving tool whose description invites unattended repeats (auto-retry / recurring /
//      scheduled) — the double-charge risk — UNLESS it mentions an idempotency affordance (which
//      only MUTES the flag; its absence alone never raises one). Only `tool` handlers take actions.

/** An irreversible / money-moving / outward side-effecting action, by the tool's name or description. */
const HIGH_STAKES = /\b(purchas|buy|checkout|pay|payment|charge|billing|\bbill\b|refund|transfer|wire|withdraw|deposit|trade|place[_ -]?order|\border\b|book(?:ing|[_ -]?(?:flight|hotel|table|room|ticket))?|reserve|subscrib|delete|destroy|wipe|terminat|deploy|publish|send[_ -]?(?:email|sms|message|money|funds|payment)|cancel)\b/i;
/** The tighter money-movement subset, for the retry / double-charge sub-rule. */
const MONEY_ACTION = /\b(purchas|buy|checkout|\bpay\b|payment|charge|billing|refund|transfer|wire|withdraw|deposit|trade|place[_ -]?order|send[_ -]?(?:money|funds|payment))\b/i;
/** Description language that tells the model to act WITHOUT a user-confirmation gate. */
const NO_CONFIRM = /\bwithout\s+(?:asking|confirm(?:ing|ation)?|user\s+(?:confirmation|approval|consent)|prompting|approval|permission)\b|\bdo(?:\s+not|n'?t)\s+ask\b|\bno\s+confirmation(?:\s+(?:needed|required|necessary))?\b|\bno\s+need\s+to\s+(?:ask|confirm)\b|\bskip(?:\s+the)?\s+confirmation\b|\bwithout\s+(?:further\s+)?(?:human|user)\s+(?:input|intervention|interaction|review)\b|\balways\s+(?:proceed|comply|execute)\b|\bimmediately\s+(?:execute|proceed|run|charge|pay|purchase|send|order|place)\b/i;
/** Description language that invites unattended, repeated invocation (→ double-execution). */
const AUTO_REPEAT = /\bautomatic(?:ally)?\b|\bauto-?retr(?:y|ies)\b|\bretr(?:y|ies|ying)\b|\bre-?try\b|\brecurring\b|\bon\s+a\s+schedule\b|\bscheduled?\b|\bevery\s+\d|\bperiodic|\bpoll(?:ing)?\b|\bin\s+a\s+loop\b|\brepeatedly\b|\bin\s+the\s+background\b|\bunattended\b/i;
/** A mention of an idempotency / dedup affordance — the author is aware; MUTES the retry sub-rule. */
const IDEMPOTENCY = /\bidempoten|idempotency[_ -]?key|\bnonce\b|dedup|deduplicat|request[_ -]?id|transaction[_ -]?id|\btxn[_ -]?id|reference[_ -]?id|client[_ -]?token|\bdry[_ -]?run\b|confirm(?:ation)?[_ -]?(?:token|required|flag)\b/i;

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

/** Names assigned from a template/concat that interpolates tainted data — i.e. a SQL string BUILT from
 *  tool input and stored in a variable before `query(sql)`. This catches the variable case (the inline
 *  `query(`…${x}`)` is caught directly) and, crucially, does NOT include a value passed straight through
 *  as a param (`query(sql, params)` where sql is the user's own raw SQL) — that is by-design arbitrary SQL. */
function strBuiltFromTaint(fn: Node, taint: Set<string>): Set<string> {
  const built = new Set<string>();
  const check = (name: string | undefined, init: Node | undefined) => {
    if (name && isConcatOrTemplate(init) && refsTaint(init, taint)) built.add(name);
  };
  walk.simple(fn as any, {
    VariableDeclarator(n: any) { if (n.id?.type === "Identifier") check(n.id.name, n.init); },
    AssignmentExpression(n: any) { if (n.left?.type === "Identifier") check(n.left.name, n.right); },
  });
  return built;
}

/** Ordered parts of a URL expression: a template literal or a `+`-concat chain. null if neither. */
function urlParts(node: Node | undefined): Array<{ text?: string; expr?: Node }> | null {
  if (!node) return null;
  if (node.type === "TemplateLiteral") {
    const parts: Array<{ text?: string; expr?: Node }> = [];
    const quasis = node.quasis ?? [], exprs = node.expressions ?? [];
    for (let i = 0; i < quasis.length; i++) {
      parts.push({ text: quasis[i]?.value?.cooked ?? quasis[i]?.value?.raw ?? "" });
      if (i < exprs.length) parts.push({ expr: exprs[i] });
    }
    return parts;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const flat: Node[] = [];
    const flatten = (n: Node) => { if (n?.type === "BinaryExpression" && n.operator === "+") { flatten(n.left); flatten(n.right); } else flat.push(n); };
    flatten(node);
    return flat.map((n) => (n.type === "Literal" && typeof n.value === "string") ? { text: n.value } : { expr: n });
  }
  return null;
}

/** Where attacker taint lands in a URL expression: "host" (controls scheme/authority → real SSRF) vs
 *  "path" (only a path/query suffix on a host fixed by a preceding literal or base-URL variable → not
 *  host control). null = not a URL expression / no taint in it. A fixed `scheme://host/` prefix, or ANY
 *  non-tainted expression before the first taint (a base-URL variable), closes the authority → "path". */
function classifyUrlTaint(node: Node | undefined, taint: Set<string>): "host" | "path" | null {
  const parts = urlParts(node);
  if (!parts) return null;
  let prefixText = "";
  let sawPrecedingExpr = false;
  for (const p of parts) {
    if (p.expr && refsTaint(p.expr, taint)) {
      if (sawPrecedingExpr) return "path";
      if (/:\/\/[^/]+\//.test(prefixText)) return "path";
      return "host";
    }
    if (p.text !== undefined) prefixText += p.text;
    else if (p.expr) sawPrecedingExpr = true;
  }
  return null;
}

/** Names assigned from a URL expression built on a FIXED host with taint only in the path (→ not SSRF
 *  host control). Lets `const u = `${base}${arg}`; fetch(u)` be classified at the sink. */
function urlPathOnlyNames(fn: Node, taint: Set<string>): Set<string> {
  const out = new Set<string>();
  const check = (name: string | undefined, init: Node | undefined) => {
    if (name && classifyUrlTaint(init, taint) === "path") out.add(name);
  };
  walk.simple(fn as any, {
    VariableDeclarator(n: any) { if (n.id?.type === "Identifier") check(n.id.name, n.init); },
    AssignmentExpression(n: any) { if (n.left?.type === "Identifier") check(n.left.name, n.right); },
  });
  return out;
}

interface Ctx {
  idx: Map<string, IndexedFn[]>;
  out: Finding[];
  label: string; // handler label for attribution
}

/** Analyze one function with a taint seed; emit sinks and recurse into forwarded functions.
 *  `seedPathOnly` names seed params whose taint is only a path suffix on a fixed host (forwarded from
 *  a caller that built the URL) — so a downstream `fetch(param)` is path manipulation, not host SSRF. */
function analyzeFn(fn: Node, seed: string[], file: string, ctx: Ctx, depth: number, visited: Set<Node>, via: string, seedPathOnly: string[] = []): void {
  if (!fn || visited.has(fn) || depth > MAX_DEPTH) return;
  visited.add(fn);
  const taint = taintOf(fn, seed);
  const sqlBuilt = strBuiltFromTaint(fn, taint);
  const pathOnly = new Set<string>(seedPathOnly);
  for (const n of urlPathOnlyNames(fn, taint)) pathOnly.add(n);
  const where = ctx.label + (via ? ` (via ${via})` : "");
  const tainted = (node: Node | undefined) => node && !isSanitized(node) && refsTaint(node, taint);
  // classify a URL argument's taint position: "host" (real SSRF) | "path" (fixed host) | null
  const urlClass = (a: Node | undefined): "host" | "path" | null => {
    const direct = classifyUrlTaint(a, taint);
    if (direct) return direct;
    if (a?.type === "Identifier" && pathOnly.has(a.name)) return "path";
    return tainted(a) ? "host" : null;
  };
  // a SQL arg is injectable if it's an inline template/concat of taint, or a var built that way
  const sqlInterp = (a: Node | undefined) => isConcatOrTemplate(a) || (a?.type === "Identifier" && sqlBuilt.has(a.name));

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
        const cls = urlClass(args[0]);
        if (cls === "host") emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
          `Attacker-influenced MCP input is the URL of \`${full || bare}(...)\` — SSRF: the attacker picks the destination (internal metadata endpoints, localhost services). Allowlist hosts.`, n.loc?.start.line);
        else if (cls === "path") emit("ssrf", "CWE-918", "MEDIUM", "Tool input is a path/query on a fixed-host URL",
          `Attacker-influenced MCP input is interpolated into the PATH/query of \`${full || bare}(...)\`, but the host is fixed (a literal or base-URL prefix precedes it) — not host-controlled SSRF. Still worth a path-traversal/parameter-tampering check; confirm the base host and that \`../\` can't redirect it.`, n.loc?.start.line);
        else if (args.slice(1).some((a) => tainted(a))) emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
          `Attacker-influenced MCP input is in the body/options of \`${full || bare}(...)\` (data egress, not URL control). Confirm the destination is trusted.`, n.loc?.start.line);
      }

      if (SQL_METHOD.test(prop) && SQL_OBJ.test(obj) && sqlInterp(args[0]) && tainted(args[0]))
        emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
          `Attacker-influenced MCP input is concatenated/templated into \`${full}(...)\` instead of a parameterized query — SQL injection. Use bound parameters.`, n.loc?.start.line);

      // cross-function forward: a tainted arg handed to a resolvable function -> follow it.
      // but NOT into a guard/validator (validatePath/sanitize/…): its internals legitimately
      // handle the raw path (realpath/readdir) — following in would re-flag the guard itself.
      const resolved = isSanitized(n) ? null : resolveCall(callee, ctx.idx);
      if (resolved && !visited.has(resolved.fn)) {
        const params: Node[] = resolved.fn.params ?? [];
        const nextSeed = new Set<string>();
        const nextPathOnly = new Set<string>();
        args.forEach((a, i) => {
          if (!tainted(a)) return;
          const p = params[i] ?? params.find((pp) => pp?.type === "RestElement");
          const isPath = (a?.type === "Identifier" && pathOnly.has(a.name)) || classifyUrlTaint(a, taint) === "path";
          for (const nm of paramNames(p)) { nextSeed.add(nm); if (isPath) nextPathOnly.add(nm); }
        });
        if (nextSeed.size) analyzeFn(resolved.fn, [...nextSeed], resolved.file, ctx, depth + 1, visited, via ? `${via} -> ${full || bare}` : (full || bare), [...nextPathOnly]);
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
      // unsafe-autonomy: the tool's description steers the model to act on a high-stakes action with
      // no human gate (distilled from habr.com/ru/articles/1097430's agent-autonomy failures).
      out.push(...scanToolDesign(file, h));
      analyzeFn(h.fn, h.sources, file, ctx, 0, new Set<Node>(), "");
    }
  }
  return out;
}

/** Flag a tool whose DESCRIPTION steers the client model to take a high-stakes action autonomously.
 *  Text-only and FP-averse: both rules trigger on positive language, never on a missing field. */
function scanToolDesign(file: string, h: Handler): Finding[] {
  if (h.kind !== "tool") return []; // only tools take actions
  const hay = [h.label, ...h.metaStrings].join("  ").toLowerCase();
  if (!HIGH_STAKES.test(hay)) return [];
  const out: Finding[] = [];
  const where = `tool "${h.label}"`;
  if (NO_CONFIRM.test(hay)) {
    out.push({
      id: "unsafe-autonomy", cwe: "CWE-841", severity: "MEDIUM",
      title: `High-stakes tool description removes the confirmation step in MCP ${where}`,
      detail: `The ${where} performs an irreversible / money-moving action yet its own description tells the model to proceed without user confirmation ("do not ask", "automatically", "no confirmation needed", …). A tool must not instruct the agent to skip the human gate on a consequential action — leave the confirm-before-acting decision to the client/policy, and gate the action behind an explicit approval argument.`,
      file, line: h.line, handler: where,
    });
  }
  if (MONEY_ACTION.test(hay) && AUTO_REPEAT.test(hay) && !IDEMPOTENCY.test(hay)) {
    out.push({
      id: "unsafe-autonomy", cwe: "CWE-841", severity: "LOW",
      title: `Money-moving tool invites unattended retries with no idempotency affordance in MCP ${where}`,
      detail: `The ${where} moves money and its description invites unattended / automatic / recurring invocation, but declares no idempotency affordance (idempotency key, request/transaction id, nonce, dry-run). A retried or rescheduled call can then charge twice — the classic agent double-charge. Accept and honor a caller-supplied idempotency key, and document it in the tool schema.`,
      file, line: h.line, handler: where,
    });
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
