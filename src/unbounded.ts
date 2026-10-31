// Unbounded-input / resource-exhaustion detector (CWE-770).
// Seed: @modelcontextprotocol/typescript-sdk GHSA-f897-62hf-6gxq (PR#2698 + PR#2926) — an HTTP
// transport read a request body, and iterated a JSON-RPC batch array, with NO size/length cap
// before parsing, so a single large request exhausts memory. This is a TRANSPORT-level flaw, not a
// tool-argument taint flow, so it is scanned structurally over every function in an MCP file rather
// than only inside registered handlers.
//
// Two shapes, each with a NEGATIVE control (a cap present ⇒ no finding):
//   1. body accumulation — a `.on("data", …)` or `for await (… of req)` loop that GROWS a buffer
//      (`body += chunk` / `chunks.push(chunk)`) with no length/size comparison against a limit.
//   2. JSON-RPC batch — `Array.isArray(x)` then iterating x to DISPATCH messages (`.map`/`for…of`
//      over handlers) with no `x.length` cap.

import * as walk from "acorn-walk";
import { type Node, memberName } from "./analyze.js";
import type { Finding } from "./detect.js";

// a value we treat as a "size/length" quantity on one side of a comparison
const SIZE_NAME = /(length|byteLength|size|bytes|len|total|count|received|read|accumulated)$/i;
// a value we treat as a "limit" on the other side
const LIMIT_NAME = /(max|limit|cap|bound|threshold|quota)/i;

/** Does the number literal / identifier look like a meaningful cap (not 0, not a loop index)? */
function isLimitSide(n: Node | undefined): boolean {
  if (!n) return false;
  if (n.type === "Literal" && typeof n.value === "number") return n.value > 0;
  if (n.type === "Identifier") return LIMIT_NAME.test(n.name);
  if (n.type === "MemberExpression") return LIMIT_NAME.test(memberName(n));
  return false;
}

function isSizeSide(n: Node | undefined): boolean {
  if (!n) return false;
  if (n.type === "MemberExpression") return SIZE_NAME.test(n.property?.name ?? "") || SIZE_NAME.test(memberName(n));
  if (n.type === "Identifier") return SIZE_NAME.test(n.name);
  return false;
}

/** A comparison of a size/length quantity against a positive numeric/limit value — the cap that an
 *  unbounded read is missing. `i < arr.length` is NOT one (the non-length side is a loop index). */
function hasSizeCap(fn: Node): boolean {
  let found = false;
  walk.simple(fn as any, {
    BinaryExpression(n: any) {
      if (!/^(>|>=|<|<=)$/.test(n.operator)) return;
      if ((isSizeSide(n.left) && isLimitSide(n.right)) || (isSizeSide(n.right) && isLimitSide(n.left))) found = true;
    },
  });
  return found;
}

// `.push`/`.concat`/`.append` GROW a buffer; `.write` is the opposite (draining a stream OUT), so it
// is deliberately excluded — a `for await (chunk of response.body) res.write(chunk)` relay is not a read.
const GROW_METHOD = /^(push|concat|append)$/;
// the iterated source of a request-body read (vs a file stream / DB cursor, which is out of scope)
const REQ_SOURCE = /(^|\.)(req|request|incoming|socket|body|conn|stream|rawbody|raw)$/i;

/** A statement/scope that GROWS an accumulator: `body += chunk`, `chunks.push(c)`, `buf.concat(c)`. */
function growsBuffer(scope: Node): boolean {
  let grows = false;
  walk.simple(scope as any, {
    AssignmentExpression(n: any) { if (n.operator === "+=") grows = true; },
    CallExpression(n: any) { if (n.callee?.type === "MemberExpression" && GROW_METHOD.test(n.callee.property?.name ?? "")) grows = true; },
  });
  return grows;
}

/** `emitter.on("data", cb)` / `.addListener("data", cb)` whose callback accumulates. */
function dataListenerGrows(fn: Node): boolean {
  let hit = false;
  walk.simple(fn as any, {
    CallExpression(n: any) {
      const c = n.callee;
      if (c?.type !== "MemberExpression" || !/^(on|addListener)$/.test(c.property?.name ?? "")) return;
      const ev = n.arguments?.[0];
      if (ev?.type !== "Literal" || ev.value !== "data") return;
      const cb = n.arguments?.[1];
      if (cb && (cb.type === "ArrowFunctionExpression" || cb.type === "FunctionExpression") && growsBuffer(cb.body)) hit = true;
    },
  });
  return hit;
}

/** `for await (const chunk of req) { body += chunk }` — streaming read of a REQUEST that accumulates.
 *  The source must look like a request stream; a file stream / DB cursor is a different threat model. */
function forAwaitGrows(fn: Node): boolean {
  let hit = false;
  walk.simple(fn as any, {
    ForOfStatement(n: any) {
      if (!n.await || !growsBuffer(n.body)) return;
      const src = n.right?.type === "Identifier" ? n.right.name : memberName(n.right);
      if (REQ_SOURCE.test(src)) hit = true;
    },
  });
  return hit;
}

// JSON-RPC-batch dispatch: an element handed to a message handler, or a member read that marks it as
// a JSON-RPC message (.method / .jsonrpc / .id / .params).
const DISPATCH_FN = /(handle|dispatch|process|onmessage|handlemessage|route|execute|_onrequest|onrequest)/i;
const RPC_MEMBER = /^(method|jsonrpc|id|params)$/;

function looksLikeDispatch(scope: Node): boolean {
  let hit = false;
  walk.simple(scope as any, {
    CallExpression(n: any) {
      const name = (n.callee?.type === "Identifier" ? n.callee.name : memberName(n.callee)) || "";
      if (DISPATCH_FN.test(name)) hit = true;
    },
    MemberExpression(n: any) { if (!n.computed && RPC_MEMBER.test(n.property?.name ?? "")) hit = true; },
  });
  return hit;
}

/** Iteration over an array that dispatches each element (`x.map(handle)`, `for (const m of x) …`). */
function hasDispatchIteration(fn: Node): boolean {
  let hit = false;
  walk.simple(fn as any, {
    CallExpression(n: any) {
      const c = n.callee;
      if (c?.type === "MemberExpression" && /^(map|forEach)$/.test(c.property?.name ?? "")) {
        const cb = n.arguments?.[0];
        if (cb && (cb.type === "ArrowFunctionExpression" || cb.type === "FunctionExpression") && looksLikeDispatch(cb.body)) hit = true;
        // `.map(handleMessage)` — a bare function reference
        if (cb?.type === "Identifier" && DISPATCH_FN.test(cb.name)) hit = true;
      }
    },
    ForOfStatement(n: any) { if (!n.await && looksLikeDispatch(n.body)) hit = true; },
  });
  return hit;
}

function hasArrayIsArray(fn: Node): boolean {
  let hit = false;
  walk.simple(fn as any, { CallExpression(n: any) { if (memberName(n.callee) === "Array.isArray") hit = true; } });
  return hit;
}

// A function that opens a FILE stream is reading the local filesystem, not a remote request body —
// a different (path-validated) trust model, so its `.on("data")` accumulation is out of scope here.
const FILE_STREAM = /(^|\.)(createReadStream|createWriteStream|openAsBlob)$/;
function readsFileStream(fn: Node): boolean {
  let hit = false;
  walk.simple(fn as any, {
    CallExpression(n: any) {
      const name = (n.callee?.type === "Identifier" ? n.callee.name : memberName(n.callee)) || "";
      if (FILE_STREAM.test(name)) hit = true;
    },
  });
  return hit;
}

/** All function nodes in a tree (declarations, expressions, arrows, methods). */
function allFns(ast: Node): Node[] {
  const out: Node[] = [];
  walk.simple(ast as any, {
    FunctionDeclaration(n: any) { out.push(n); },
    FunctionExpression(n: any) { out.push(n); },
    ArrowFunctionExpression(n: any) { out.push(n); },
  });
  return out;
}

// A JSON-RPC batch finding is only meaningful in JSON-RPC transport code; this gate keeps the
// detector off unrelated `Array.isArray(x) ? x : [x]` + `.map(process)` shapes (CLI commands, admin
// batch utilities) that are not request-controlled message batches.
const RPC_FILE = /jsonrpc|json-rpc|JSONRPCMessage|-32700|-32600|-32603|CallToolRequest|isInitializeRequest|StreamableHTTP/i;

/** Scan already-parsed MCP files for unbounded body / batch reads. */
export function scanUnbounded(parsed: Array<{ file: string; ast: Node; source?: string }>): Finding[] {
  const out: Finding[] = [];
  for (const { file, ast, source } of parsed) {
    const isRpcFile = !source || RPC_FILE.test(source);
    for (const fn of allFns(ast)) {
      if (hasSizeCap(fn)) continue; // a cap is present somewhere in this function → bounded
      const line = fn.loc?.start.line;
      if ((dataListenerGrows(fn) || forAwaitGrows(fn)) && !readsFileStream(fn)) {
        out.push({ id: "unbounded-body", cwe: "CWE-770", severity: "HIGH",
          title: "Request body is accumulated without a size cap",
          detail: "An HTTP transport reads and accumulates a request body (`.on(\"data\", …)` / `for await (… of req)`) with no byte/length limit enforced before it is buffered or parsed. A single large request exhausts server memory (cf. MCP TypeScript SDK GHSA-f897-62hf-6gxq). Cap the accumulated size and reject once it is exceeded (e.g. `raw-body`/`getRawBody` with a `limit`, or a running byte count checked against a maximum).",
          file, line, handler: "(HTTP transport)" });
        continue;
      }
      if (isRpcFile && hasArrayIsArray(fn) && hasDispatchIteration(fn)) {
        out.push({ id: "unbounded-batch", cwe: "CWE-770", severity: "HIGH",
          title: "JSON-RPC batch is iterated without a length cap",
          detail: "A JSON-RPC batch (`Array.isArray(message)` → the message array) is dispatched element-by-element with no cap on the array length before processing. A single request carrying a huge batch array exhausts memory/CPU (cf. MCP TypeScript SDK GHSA-f897-62hf-6gxq, PR#2698/#2926). Reject batches whose length exceeds a fixed maximum before iterating.",
          file, line, handler: "(JSON-RPC transport)" });
      }
    }
  }
  return out;
}
