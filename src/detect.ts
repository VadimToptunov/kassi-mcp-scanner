// Taint the MCP handler's input parameter(s) through the handler body and flag dangerous sinks.
// Source = attacker-influenced tool/resource/prompt input (see mcp.ts). Static (AST) only.

import * as walk from "acorn-walk";
import { type Node, memberName, parse } from "./analyze.js";
import { type Handler, findHandlers, isMcpFile } from "./mcp.js";

export type Severity = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  id: string; // cmd-injection | code-exec | path-traversal | ssrf | sql-injection
  cwe: string;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  line?: number;
  handler: string; // e.g. tool "run_shell"
}

const SANITIZER = /sanitiz|escape|allowlist|whitelist|validate|isAllowed|assert|zod|schema\.parse/i;

// ---- taint -----------------------------------------------------------------

function refsTaint(node: Node | undefined, taint: Set<string>): boolean {
  if (!node) return false;
  let found = false;
  walk.simple(node as any, { Identifier(x: any) { if (taint.has(x.name)) found = true; } });
  return found;
}

function isSanitized(node: Node | undefined): boolean {
  if (!node || node.type !== "CallExpression") return false;
  const name = memberName(node.callee) || (node.callee?.type === "Identifier" ? node.callee.name : "");
  return SANITIZER.test(name);
}

/** path.basename(x) / path.parse(x).base strip directory traversal — treat as neutralized. */
function stripsTraversal(node: Node | undefined): boolean {
  if (!node || node.type !== "CallExpression") return false;
  return /(^|\.)basename$/.test(memberName(node.callee));
}

/** Build the set of tainted local names inside one handler (fixpoint over aliasing). */
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
  return taint;
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

/** Scan one handler body for tainted sinks. */
function scanHandler(h: Handler, file: string, out: Finding[]): void {
  const taint = taintOf(h.fn, h.sources);
  const where = `${h.kind} "${h.label}"`;
  const tainted = (node: Node | undefined) => node && !isSanitized(node) && refsTaint(node, taint);

  const emit = (id: string, cwe: string, severity: Severity, title: string, detail: string, line?: number) =>
    out.push({ id, cwe, severity, title: `${title} in MCP ${where}`, detail, file, line, handler: where });

  walk.simple(h.fn as any, {
    CallExpression(n: any) {
      const callee = n.callee;
      const args: Node[] = n.arguments ?? [];
      const bare = callee?.type === "Identifier" ? callee.name : "";
      const full = memberName(callee);
      const prop = callee?.type === "MemberExpression" ? (callee.property?.name ?? "") : "";
      const obj = callee?.type === "MemberExpression" ? memberName(callee.object) : "";

      // command injection: child_process / execa / shell
      const isCp = CP_BARE.test(bare) || (CP_METHOD.test(prop) && CP_OBJ.test(obj));
      if (isCp && args.some((a) => tainted(a))) {
        emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command execution sink",
          `Attacker-influenced MCP input flows into \`${full || bare}(...)\`. A malicious tool call can inject OS commands. Use execFile with a fixed binary + array args, never a shell string.`, n.loc?.start.line);
      }

      // code execution
      if ((bare === "eval" || bare === "Function" || /(^|\.)(runInNewContext|runInContext|compileFunction)$/.test(full)) && args.some((a) => tainted(a))) {
        emit("code-exec", "CWE-94", "HIGH", "Tool input reaches a code-execution sink",
          `Attacker-influenced MCP input flows into \`${full || bare}(...)\` — arbitrary code execution in the server process.`, n.loc?.start.line);
      }

      // path traversal: fs read/write with a tainted path (unless basename-stripped)
      const isFs = FS_METHOD.test(prop) && FS_OBJ.test(obj);
      if (isFs && args[0] && !stripsTraversal(args[0]) && tainted(args[0])) {
        emit("path-traversal", "CWE-22", "HIGH", "Tool input reaches a filesystem path sink",
          `Attacker-influenced MCP input is used as the path in \`${full}(...)\` with no traversal guard — a crafted \`../\` reads/writes arbitrary files. Resolve against a fixed root and reject paths that escape it.`, n.loc?.start.line);
      }

      // SSRF: tainted URL into an HTTP client
      const isNet = bare === "fetch" || (bare === "axios") || (NET_METHOD.test(prop) && NET_OBJ.test(obj)) || /(^|\.)fetch$/.test(full);
      if (isNet && args[0]) {
        if (tainted(args[0])) emit("ssrf", "CWE-918", "HIGH", "Tool input controls an outbound request URL",
          `Attacker-influenced MCP input is the URL of \`${full || bare}(...)\` — SSRF: the attacker picks the destination (internal metadata endpoints, localhost services). Allowlist hosts.`, n.loc?.start.line);
        else if (args.slice(1).some((a) => tainted(a))) emit("ssrf", "CWE-918", "MEDIUM", "Tool input is sent in an outbound request body",
          `Attacker-influenced MCP input is in the body/options of \`${full || bare}(...)\` (data egress, not URL control). Confirm the destination is trusted.`, n.loc?.start.line);
      }

      // SQL injection: tainted value interpolated into a raw query string (not a param placeholder)
      if (SQL_METHOD.test(prop) && SQL_OBJ.test(obj) && isConcatOrTemplate(args[0]) && tainted(args[0])) {
        emit("sql-injection", "CWE-89", "HIGH", "Tool input is interpolated into a raw SQL query",
          `Attacker-influenced MCP input is concatenated/templated into \`${full}(...)\` instead of a parameterized query — SQL injection. Use bound parameters.`, n.loc?.start.line);
      }
    },
    TaggedTemplateExpression(n: any) {
      // execa / zx shell tags: $`cmd ${taint}`, sh`…`, execa`…`
      const tag = n.tag?.type === "Identifier" ? n.tag.name : memberName(n.tag);
      if (/^\$$/.test(tag) || /(^|\.)(execa|zx|sh|\$)$/.test(tag)) {
        if ((n.quasi?.expressions ?? []).some((e: Node) => refsTaint(e, taint))) {
          emit("cmd-injection", "CWE-78", "HIGH", "Tool input reaches a shell/command execution sink",
            `Attacker-influenced MCP input is interpolated into a shell template \`${tag}\`...\`\` — a malicious tool call can inject OS commands.`, n.loc?.start.line);
        }
      }
    },
    NewExpression(n: any) {
      if (/(^|\.)Script$/.test(memberName(n.callee)) && (n.arguments ?? []).some((a: Node) => a && refsTaint(a, taint))) {
        out.push({ id: "code-exec", cwe: "CWE-94", severity: "HIGH", title: `Tool input reaches a code-execution sink in MCP ${where}`,
          detail: `Attacker-influenced MCP input flows into \`new vm.Script(...)\` — arbitrary code execution.`, file, line: n.loc?.start.line, handler: where });
      }
    },
  });
}

/** Scan one source file. Returns [] for non-MCP files. */
export function scanSource(source: string, file = "input.ts"): Finding[] {
  if (!isMcpFile(source)) return [];
  const ast = parse(source, file);
  if (!ast) return [];
  const out: Finding[] = [];
  for (const h of findHandlers(ast)) scanHandler(h, file, out);
  return out;
}
