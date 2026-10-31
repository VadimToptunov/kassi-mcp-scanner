// Benign, bounded demonstration of the unbounded JSON-RPC batch dispatch in
// punkpeye/fastmcp's edge transport (src/edge/index.ts #handleMcpRequest).
// This is OUR harness: it replicates the transport's batch-handling structure
// (verbatim shape) around a trivial counting handler — it does NOT run the
// upstream package. It shows the vulnerable loop processes the whole client
// batch with only a `length === 0` MIN check and no MAX cap, vs a one-line fix.

function makeBatch(n) {           // a client-controlled JSON-RPC batch of n pings
  return Array.from({ length: n }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "ping" }));
}

// --- VULNERABLE: the shape from edge/index.ts (lines ~285-312) -------------
async function handleVulnerable(body, handleMessage) {
  const isBatch = Array.isArray(body);
  const messages = Array.isArray(body) ? body : [body];
  if (isBatch && messages.length === 0) throw new Error("Batch must contain at least one message"); // MIN only
  const responses = [];
  for (const message of messages) {        // <-- no upper bound on messages.length
    const response = await handleMessage(message);
    if (response) responses.push(response);
  }
  return responses;
}

// --- FIXED: reject an oversized batch before dispatch ----------------------
const MAX_BATCH = 100;
async function handleFixed(body, handleMessage) {
  const isBatch = Array.isArray(body);
  const messages = Array.isArray(body) ? body : [body];
  if (isBatch && messages.length === 0) throw new Error("Batch must contain at least one message");
  if (isBatch && messages.length > MAX_BATCH) throw new Error(`Batch too large: ${messages.length} > ${MAX_BATCH}`);
  const responses = [];
  for (const message of messages) { const r = await handleMessage(message); if (r) responses.push(r); }
  return responses;
}

async function measure(fn, n) {
  let dispatched = 0;
  const handleMessage = async (m) => { dispatched++; return { jsonrpc: "2.0", id: m.id, result: {} }; };
  const t0 = process.hrtime.bigint();
  let rejected = false, msg = "";
  try { await fn(makeBatch(n), handleMessage); } catch (e) { rejected = true; msg = e.message; }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { dispatched, rejected, msg, ms };
}

console.log("batch size |   VULNERABLE (edge/index.ts)      |   FIXED (length>MAX reject)");
console.log("-----------+-----------------------------------+-----------------------------");
for (const n of [1, 100, 1000, 10000, 100000]) {
  const v = await measure(handleVulnerable, n);
  const f = await measure(handleFixed, n);
  const vs = v.rejected ? `REJECTED (${v.msg})` : `dispatched ${v.dispatched} msgs in ${v.ms.toFixed(1)}ms`;
  const fs = f.rejected ? `REJECTED after 0 dispatch` : `dispatched ${f.dispatched}`;
  console.log(`${String(n).padStart(10)} | ${vs.padEnd(33)} | ${fs}`);
}
