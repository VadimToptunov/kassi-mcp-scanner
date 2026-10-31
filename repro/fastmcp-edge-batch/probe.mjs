// Benign, bounded dynamic probe for the unbounded JSON-RPC batch dispatch in
// punkpeye/fastmcp's EDGE transport (src/edge/index.ts #handleMcpRequest).
//
// It stands up a REAL EdgeFastMCP server with one trivial counting tool and
// POSTs JSON-RPC batches of increasing length to its Web-fetch handler,
// measuring how many messages the server dispatches. A vulnerable build
// dispatches the whole batch (no upper length cap); a fixed build rejects an
// oversized batch before dispatch.
//
// Benign: payloads are `tools/call` to a no-op tool that only increments a
// counter — nothing is written, deleted, or exfiltrated. Bounded: batch size
// is capped by MAX_N below. Authorized: runs only against the local in-process
// server this script creates.

const MAX_N = Number(process.env.MAX_N ?? 50000);
const SIZES = [1, 100, 1000, 10000, MAX_N].filter((n, i, a) => a.indexOf(n) === i && n <= MAX_N);

// Resolve the edge entry across plausible layouts of the built package.
let EdgeFastMCP;
for (const spec of ["fastmcp/edge", "fastmcp", "./dist/edge/index.js", "./dist/esm/edge/index.js"]) {
  try { ({ EdgeFastMCP } = await import(spec)); if (EdgeFastMCP) { console.error(`imported EdgeFastMCP from ${spec}`); break; } } catch { /* try next */ }
}
if (!EdgeFastMCP) { console.error("Could not import EdgeFastMCP — check the installed fastmcp version's edge export path."); process.exit(2); }

let dispatched = 0;
const server = new EdgeFastMCP({ name: "repro", version: "0.0.0" });
server.addTool({
  name: "noop",
  description: "counts dispatches",
  parameters: { type: "object", properties: {} },
  execute: async () => { dispatched++; return "ok"; },
});

const batch = (n) => Array.from({ length: n }, (_, i) => ({
  jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "noop", arguments: {} },
}));

async function post(n) {
  dispatched = 0;
  const req = new Request("http://local/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify(batch(n)),
  });
  const t0 = process.hrtime.bigint();
  let status, rejected = false;
  try {
    const res = await server.fetch(req);
    status = res.status;
    rejected = status >= 400;
  } catch (e) { rejected = true; status = `threw: ${e.message}`; }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { dispatched, status, rejected, ms };
}

console.log("batch size | status | dispatched | ms      | verdict");
console.log("-----------+--------+------------+---------+-------------------------");
for (const n of SIZES) {
  const r = await post(n);
  const verdict = r.dispatched >= n ? "ALL dispatched (unbounded)" : (r.rejected ? "rejected (bounded)" : "partial");
  console.log(`${String(n).padStart(10)} | ${String(r.status).padStart(6)} | ${String(r.dispatched).padStart(10)} | ${r.ms.toFixed(1).padStart(7)} | ${verdict}`);
}
console.log("\nUnbounded if the server dispatches the whole batch at every size with no 4xx rejection.");
