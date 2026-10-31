# Repro — unbounded JSON-RPC batch dispatch (fastmcp edge transport)

**Lead (candidate, not auto-disclosed):** `punkpeye/fastmcp` edge transport
`src/edge/index.ts` → `EdgeFastMCP.#handleMcpRequest` (audited at commit `febd9b4`).

The hand-rolled edge Streamable-HTTP transport parses the request body and, for a
JSON-RPC **batch** (a top-level array), dispatches every element with no cap on the
array length — only a `length === 0` *minimum* check:

```js
const isBatch = Array.isArray(body);
const messages = Array.isArray(body) ? body : [body];
if (isBatch && messages.length === 0) { /* 400 */ }   // minimum only — no maximum
for (const message of messages) {
  const response = await this.#handleMessage(message); // dispatched unbounded
  if (response) responses.push(response);
}
```

A single POST carrying a huge batch array makes the server allocate and dispatch
one unit of work per element — a memory/CPU resource-exhaustion DoS. This is the
same class as the official MCP TypeScript SDK's **GHSA-f897-62hf-6gxq** (fixed in
PR #2698 / #2926). The fastmcp **Node** path uses the patched official SDK
transport; the **edge** path reimplemented the transport and did not carry the cap.

> Base rate: this is a *candidate for human review and coordinated disclosure*, not
> a confirmed CVE. A maintainer should confirm exploitability against the edge
> runtime's own body-size limits (Cloudflare Workers / Vercel Edge cap request
> bytes, which bounds the batch indirectly) before deciding severity.

## 1. Offline mechanism demo (no install, no network)

Runs our own replica of the dispatch loop (the exact shape above) beside a capped
variant, so you can see the behavior without building the package:

```bash
node batch-dispatch-mechanism.mjs
```

Expected: the vulnerable shape dispatches the whole batch at every size (linear,
unbounded); the capped variant rejects before dispatching anything.

## 2. Real-server Docker repro (benign, bounded)

Drives a real in-process `EdgeFastMCP` with a trivial no-op tool and POSTs
JSON-RPC batches of increasing length to its `fetch()` handler:

```bash
docker build -t fastmcp-edge-batch .
docker run --rm --memory=512m fastmcp-edge-batch          # MAX_N=50000 default
docker run --rm --memory=256m -e MAX_N=200000 fastmcp-edge-batch   # tighter cap, bigger batch
```

**Vulnerable** → the server dispatches all N messages at every size with no 4xx,
and under a low `--memory` limit a large enough batch trends toward OOM.
**Fixed** (a `messages.length > MAX` guard added before the loop) → the oversized
batch returns a 4xx with zero dispatches.

## Safety / authorization

- Runs only against the local in-process server the script creates — no external
  target, no network at run time.
- Payloads are `tools/call` to a no-op tool that only increments a counter.
  Nothing is written, deleted, or exfiltrated; batch size is bounded by `MAX_N`.
- This is a lead for a human to verify and disclose responsibly. Do **not**
  point `probe.mjs` at a server you are not authorized to test.
