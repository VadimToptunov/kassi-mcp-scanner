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
import { scanUnbounded } from "./unbounded.js";

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

const SANITIZER = /sanitiz|escape|allowlist|whitelist|validate|isAllowed|assert|zod|schema\.parse|resolveSafe|safeResolve|ensureInside|ensureWithin|normalize\w*(relative|path)/i;
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

/** Taint FLOW for an assigned value: a `cond ? a : b` evaluates to a branch, never the condition, so
 *  taint must not flow from the TEST. Without this, `where = (userDays===null) ? "" : "WHERE …"` is
 *  marked tainted because the condition refs a tainted value, though every branch is a constant — the
 *  SQL false positive from the sweep (ghostwright/phantom). Non-ternary values use the plain walk. */
function flowRefsTaint(node: Node | undefined, taint: Set<string>): boolean {
  if (node?.type === "ConditionalExpression")
    return flowRefsTaint(node.consequent, taint) || flowRefsTaint(node.alternate, taint);
  return refsTaint(node, taint);
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

/** Taint propagation WITHOUT guard-clearing — the raw reachable set. */
function propagate(fn: Node, sources: string[]): Set<string> {
  const taint = new Set<string>(sources);
  for (let pass = 0; pass < 6; pass++) {
    const before = taint.size;
    walk.simple(fn as any, {
      VariableDeclarator(n: any) {
        if (n.id?.type === "Identifier" && !isSanitized(n.init) && flowRefsTaint(n.init, taint)) taint.add(n.id.name);
      },
      AssignmentExpression(n: any) {
        if (n.left?.type === "Identifier" && !isSanitized(n.right) && flowRefsTaint(n.right, taint)) taint.add(n.left.name);
      },
    });
    if (taint.size === before) break;
  }
  return taint;
}

function taintOf(fn: Node, sources: string[]): Set<string> {
  const taint = propagate(fn, sources);
  // a bouncer guard that content-validates a tainted value clears it downstream (guard-by-throw)
  for (const v of guardValidatedNames(fn, taint)) taint.delete(v);
  return taint;
}

// ---- SSRF-guard awareness (seed: mcp-sanitizer GHSA-4mfg-r38w-w8fg) --------
// A private-network/loopback BLOCKLIST guard is the common SSRF defense, but it is only as good as
// the forms it rejects. The mcp-sanitizer bug allowed loopback via bracketed IPv6 ([::1]) and an
// explicit port; the whole bypass class is IPv6 loopback (::1), IPv4-mapped (::ffff:127.0.0.1),
// 0.0.0.0, and decimal/hex/octal-encoded IPs — plus NOT re-checking the host after a redirect.
// So: a guard that names loopback/private forms but MISSES those is still a live SSRF (guard-bypass);
// an ALLOWLIST guard (startsWith(base) / isApiHost / host === "api.github.com") is the correct
// defense and must stay clean — it never names the blocklist forms, so it is not mistaken for one.

/** A guard whose intent is to REJECT loopback/private destinations (blocklist-style). */
const SSRF_BLOCKLIST = /localhost|127\.0\.0|0\.0\.0\.0|::1|169\.254|metadata|isprivate|isloopback|loopback|blockprivate|is[-_]?internal|\bprivate\b|\binternal\b|ssrf|\b10\.0\.0|192\.168|172\.1[6-9]/i;
/** Delegation to a library/primitive that handles the full private-IP space is treated as complete. */
const SSRF_ROBUST = /ipaddr|is[-_]?ip\b|netmask|cidr|ip[-_]?range[-_]?check|private[-_]?ip|net\.isip|ssrf[-_]?(req[-_]?)?filter|request[-_]?filtering|blockedcidr/i;
const SSRF_IPV6_LOOPBACK = /::1/;
const SSRF_ALLZEROS = /0\.0\.0\.0/;
const SSRF_MAPPED = /::ffff|ipv4[-_]?mapped|\bmapped\b/i;

/** Lowercased bag of identifiers + string/regex/numeric literal text under a node (and, one hop deep,
 *  the bodies of resolvable predicate functions it calls) — enough to judge what a guard covers. */
function guardTokens(node: Node | undefined, idx: Map<string, IndexedFn[]>, depth = 0): string {
  if (!node) return "";
  const parts: string[] = [];
  walk.simple(node as any, {
    Identifier(x: any) { parts.push(x.name); },
    Literal(x: any) { if (x.regex) parts.push(x.regex.pattern); else if (x.value != null) parts.push(String(x.value)); },
    TemplateLiteral(x: any) { for (const q of x.quasis ?? []) parts.push(q.value?.cooked ?? q.value?.raw ?? ""); },
  });
  if (depth < 1) {
    walk.simple(node as any, {
      CallExpression(c: any) {
        const r = resolveCall(c.callee, idx);
        if (r) parts.push(guardTokens(r.fn.body, idx, depth + 1));
      },
    });
  }
  return parts.join(" ").toLowerCase();
}

/** Classify a guard's SSRF coverage from its tokens: not an SSRF blocklist guard, a complete one, or
 *  an incomplete one (names loopback/private but misses the IPv6/mapped/0.0.0.0 bypass forms). */
function ssrfGuardCoverage(tokens: string): "none" | "complete" | "incomplete" {
  if (SSRF_ROBUST.test(tokens)) return "complete"; // delegates to a full private-IP library — correct
  if (!SSRF_BLOCKLIST.test(tokens)) return "none"; // allowlist / unrelated guard — correct defense, leave clean
  const covers = SSRF_IPV6_LOOPBACK.test(tokens) && SSRF_ALLZEROS.test(tokens) && SSRF_MAPPED.test(tokens);
  return covers ? "complete" : "incomplete";
}

/** SSRF guards usually validate a value DERIVED from the URL (`new URL(url).hostname`) while the
 *  original `url` is what gets fetched, so a per-name check misses the link. We group tainted names
 *  into derivation components (a var is unioned with the tainted names in its initializer) and judge
 *  a guard against the whole component: a COMPLETE guard makes the component `safe` (suppress SSRF —
 *  the hardened-server negative control), an INCOMPLETE one makes it `weak` (still a live bypass).
 *  Coarse at the param level (two distinct user URLs in one handler share the param root), which is a
 *  rare, deliberate false-NEGATIVE in line with this scanner's FP-aversion — never a false alarm. */
function ssrfGuardSets(fn: Node, sources: string[], idx: Map<string, IndexedFn[]>): { safe: Set<string>; weak: Set<string> } {
  const raw = propagate(fn, sources);
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r)!;
    parent.set(x, r);
    return r;
  };
  const union = (a: string, b: string) => { parent.set(find(a), find(b)); };
  const taintedIdsIn = (node: Node | undefined): string[] => {
    const out: string[] = [];
    if (node) walk.simple(node as any, { Identifier(x: any) { if (raw.has(x.name)) out.push(x.name); } });
    return out;
  };
  for (const n of raw) find(n);
  walk.simple(fn as any, {
    VariableDeclarator(n: any) { if (n.id?.type === "Identifier" && raw.has(n.id.name)) for (const s of taintedIdsIn(n.init)) union(n.id.name, s); },
    AssignmentExpression(n: any) { if (n.left?.type === "Identifier" && raw.has(n.left.name)) for (const s of taintedIdsIn(n.right)) union(n.left.name, s); },
  });
  const safeRoots = new Set<string>(), weakRoots = new Set<string>();
  walk.simple(fn as any, {
    IfStatement(n: any) {
      if (!bounces(n.consequent)) return;
      const cov = ssrfGuardCoverage(guardTokens(n.test, idx));
      if (cov === "none") return;
      for (const v of taintedIdsIn(n.test)) (cov === "complete" ? safeRoots : weakRoots).add(find(v));
    },
  });
  const safe = new Set<string>(), weak = new Set<string>();
  for (const n of raw) {
    const r = find(n);
    if (safeRoots.has(r)) safe.add(n);
    else if (weakRoots.has(r)) weak.add(n);
  }
  return { safe, weak };
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

// prototype pollution (CWE-1321): a RECURSIVE deep-merge / nested-set fed attacker data walks the input's
// keys into the target, so a `__proto__` key reaches Object.prototype. Scoped to the genuinely-recursive
// helpers (not shallow Object.assign / Map.set / res.set, which would be noise).
const MERGE_SINK = /^(merge|mergeWith|deepMerge|deepmerge|defaultsDeep|mergeDeep|setWith)$/;
// ReDoS (CWE-1333): string methods whose first arg is the regex/pattern.
const REDOS_PAT_METHOD = /^(match|matchAll|search|replace|replaceAll|split)$/;
// A regex literal with catastrophic backtracking: a quantified group that itself contains a quantifier,
// or an alternation of the same atom under a quantifier — `(a+)+`, `(a*)*`, `(.*)*`, `(a|a)*`.
const EVIL_REGEX = /\([^()]*[+*][^()]*\)[+*?]|\(([^()|]+)\|\1\)[+*]/;

/** True when a regex LITERAL argument has an evil (catastrophic-backtracking) shape. */
function isEvilRegexLiteral(n: Node | undefined): boolean {
  return !!n && n.type === "Literal" && !!n.regex && EVIL_REGEX.test(n.regex.pattern ?? "");
}
/** A function that defends against prototype pollution anywhere (so merge/set sinks in it are suppressed):
 *  a `__proto__`/`constructor`/`prototype` key check, a null-prototype object, a Map, or hasOwnProperty. */
function hasProtoGuard(fn: Node): boolean {
  let g = false;
  walk.simple(fn as any, {
    Literal(x: any) { if (typeof x.value === "string" && /^(__proto__|constructor|prototype)$/.test(x.value)) g = true; },
    Identifier(x: any) { if (/^(hasOwnProperty|getOwnPropertyNames|freeze)$/.test(x.name)) g = true; },
    NewExpression(x: any) { if ((x.callee?.name ?? memberName(x.callee)) === "Map") g = true; },
    CallExpression(x: any) { if (memberName(x.callee) === "Object.create" && x.arguments?.[0]?.type === "Literal" && x.arguments[0].value === null) g = true; },
  });
  return g;
}

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
  // SSRF-specific taint: drop names a COMPLETE private-net guard protects, re-add names only an
  // INCOMPLETE (bypassable) guard "cleared". Other sinks keep using `taint` (generic guard-clearing).
  const { safe: ssrfSafe, weak: ssrfWeak } = ssrfGuardSets(fn, seed, ctx.idx);
  const ssrfTaint = new Set<string>([...taint].filter((n) => !ssrfSafe.has(n)));
  for (const w of ssrfWeak) ssrfTaint.add(w);
  const sqlBuilt = strBuiltFromTaint(fn, taint);
  const protoGuarded = hasProtoGuard(fn); // a __proto__/constructor key guard anywhere suppresses merge sinks
  const pathOnly = new Set<string>(seedPathOnly);
  for (const n of urlPathOnlyNames(fn, taint)) pathOnly.add(n);
  const where = ctx.label + (via ? ` (via ${via})` : "");
  const tainted = (node: Node | undefined) => node && !isSanitized(node) && refsTaint(node, taint);
  const ssrfTainted = (node: Node | undefined) => node && !isSanitized(node) && refsTaint(node, ssrfTaint);
  const refsSet = (node: Node | undefined, set: Set<string>) => {
    if (!node) return false;
    let hit = false;
    walk.simple(node as any, { Identifier(x: any) { if (set.has(x.name)) hit = true; } });
    return hit;
  };
  // classify a URL argument's taint position: "host" (real SSRF) | "path" (fixed host) | null.
  // Uses ssrfTaint so a complete-guard'd URL reads as untainted and a weak-guard'd one stays tainted.
  const urlClass = (a: Node | undefined): "host" | "path" | null => {
    const direct = classifyUrlTaint(a, ssrfTaint);
    if (direct) return direct;
    if (a?.type === "Identifier" && pathOnly.has(a.name)) return "path";
    return ssrfTainted(a) ? "host" : null;
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

      // Shell-form vs argv-form (matches py/mcpscan.py). A shell-form sink runs a COMMAND STRING
      // (arg0) through a shell, so taint in arg0 injects. An argv-form sink (execFile*/spawn*/fork/
      // execa(file,args)) passes a fixed program + a separate args array with NO shell, so a tainted
      // ARGUMENT is inert — only a tainted PROGRAM (arg0) or an explicit `shell:true`/`shell:"<sh>"`
      // option injects. This kills the sweep's dominant cmd-inj FP (execFile/spawn with a resolved
      // binary + user data in the args array). The `sh -c <tainted>` pattern is a deliberate,
      // FP-averse false-negative, exactly as in the Python engine.
      const cpName = CP_BARE.test(bare) ? bare : ((CP_METHOD.test(prop) && CP_OBJ.test(obj)) ? prop : "");
      if (cpName) {
        const shellOpt = args.some((a) => a?.type === "ObjectExpression" &&
          (a.properties ?? []).some((p: Node) => (p.key?.name ?? p.key?.value) === "shell" &&
            !(p.value?.type === "Literal" && p.value.value === false)));
        const hit = shellOpt ? args.some((a) => tainted(a)) : tainted(args[0]);
        if (hit)
          emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command execution sink",
            `Attacker-influenced MCP input flows into \`${full || bare}(...)\`. A malicious tool call can inject OS commands. Use execFile with a fixed binary + array args, never a shell string.`, n.loc?.start.line);
      }

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
        // a URL reachable only because an INCOMPLETE private-network guard "cleared" it = live bypass
        if (cls === "host" && refsSet(args[0], ssrfWeak)) emit("ssrf-guard-bypass", "CWE-918", "HIGH", "Outbound URL passes an incomplete SSRF guard",
          `Attacker-influenced MCP input is the URL of \`${full || bare}(...)\` behind a private-network/loopback guard that misses known bypass forms — IPv6 loopback \`[::1]\`, IPv4-mapped \`::ffff:127.0.0.1\`, \`0.0.0.0\`, and decimal/hex/octal-encoded IPs — and does not re-check the host after redirects (cf. mcp-sanitizer GHSA-4mfg-r38w-w8fg). Allowlist hosts, or normalize to a canonical IP and reject the full private range (use a vetted library), re-validating on every redirect.`, n.loc?.start.line);
        else if (cls === "host") emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
          `Attacker-influenced MCP input is the URL of \`${full || bare}(...)\` — SSRF: the attacker picks the destination (internal metadata endpoints, localhost services). Allowlist hosts.`, n.loc?.start.line);
        else if (cls === "path") emit("ssrf", "CWE-918", "MEDIUM", "Tool input is a path/query on a fixed-host URL",
          `Attacker-influenced MCP input is interpolated into the PATH/query of \`${full || bare}(...)\`, but the host is fixed (a literal or base-URL prefix precedes it) — not host-controlled SSRF. Still worth a path-traversal/parameter-tampering check; confirm the base host and that \`../\` can't redirect it.`, n.loc?.start.line);
        else if (args.slice(1).some((a) => tainted(a))) emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
          `Attacker-influenced MCP input is in the body/options of \`${full || bare}(...)\` (data egress, not URL control). Confirm the destination is trusted.`, n.loc?.start.line);
      }

      if (SQL_METHOD.test(prop) && SQL_OBJ.test(obj) && sqlInterp(args[0]) && tainted(args[0]))
        emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
          `Attacker-influenced MCP input is concatenated/templated into \`${full}(...)\` instead of a parameterized query — SQL injection. Use bound parameters.`, n.loc?.start.line);

      // prototype pollution (CWE-1321): attacker data into a recursive deep-merge / nested-set.
      if ((MERGE_SINK.test(prop) || MERGE_SINK.test(bare) || (/^set$/.test(prop) && /(^|\.)(_|lodash)$/.test(obj)))
          && !protoGuarded && args.some((a) => tainted(a)))
        emit("prototype-pollution", "CWE-1321", "HIGH", "Tool input flows into a recursive merge/set",
          `Attacker-influenced MCP input is a source/path for \`${full || bare}(...)\` (recursive deep-merge / nested set). A payload with a \`__proto__\`/\`constructor\` key pollutes Object.prototype. Reject those keys, or use a null-prototype object / Map.`, n.loc?.start.line);

      // ReDoS (CWE-1333): attacker controls the regex PATTERN (arg0 of a pattern method / RegExp()).
      if ((bare === "RegExp" || /(^|\.)RegExp$/.test(full)) && tainted(args[0]))
        emit("redos", "CWE-1333", "HIGH", "Tool input is compiled into a regular expression",
          `Attacker-influenced MCP input is the pattern of \`${full || bare}(...)\` — a crafted pattern (catastrophic backtracking or a huge pattern) hangs the event loop (ReDoS). Validate/bound the pattern, or don't build regexes from tool input.`, n.loc?.start.line);
      else if (REDOS_PAT_METHOD.test(prop) && tainted(args[0]))
        emit("redos", "CWE-1333", "HIGH", "Tool input is used as a regular-expression pattern",
          `Attacker-influenced MCP input is the pattern passed to \`${full}(...)\` — a crafted regex causes catastrophic backtracking (ReDoS). Treat tool input as a literal (escape it) rather than a pattern.`, n.loc?.start.line);
      // ReDoS (MEDIUM): tainted INPUT tested against a statically catastrophic regex literal.
      else if (REDOS_PAT_METHOD.test(prop) && refsTaint(callee?.object, taint) && isEvilRegexLiteral(args[0]))
        emit("redos", "CWE-1333", "MEDIUM", "Tool input is matched against a catastrophic regex",
          `Attacker-influenced MCP input is matched by \`${full}(...)\` against a regex with nested quantifiers (catastrophic backtracking) — a crafted input hangs the event loop (ReDoS). Rewrite the regex to avoid nested quantifiers, or cap input length.`, n.loc?.start.line);

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
      // ReDoS: new RegExp(taintedPattern) — attacker controls the compiled regex.
      if (/(^|\.)RegExp$/.test(memberName(n.callee)) && tainted((n.arguments ?? [])[0]))
        emit("redos", "CWE-1333", "HIGH", "Tool input is compiled into a regular expression",
          `Attacker-influenced MCP input is the pattern of \`new RegExp(...)\` — a crafted pattern (catastrophic backtracking) hangs the event loop (ReDoS). Validate/bound the pattern, or don't build regexes from tool input.`, n.loc?.start.line);
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
  const mcpParsed = parsed.filter((p) => isMcpFile(p.source));
  out.push(...scanUnbounded(mcpParsed)); // transport-level unbounded body / JSON-RPC batch (CWE-770)
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
