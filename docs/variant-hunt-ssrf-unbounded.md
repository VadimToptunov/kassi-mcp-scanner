# Variant hunt — MCP SSRF guard-bypass (CWE-918) + unbounded input (CWE-770)

**Date:** 2026-10-31 · **Branch:** `feat/ssrf-unbounded-variant-hunt` · **Scope:** public OSS only,
benign, leads-for-a-human (no auto-submit).

Take two recently-patched, CVE-validated MCP-ecosystem bug *shapes*, teach the scanner to recognize
each shape (including the guard/cap that makes it safe), then hunt the same shape in other public MCP
servers and SDKs. The detectors are the durable product win; they ship whether or not any specific
target turns out vulnerable.

## Seeds

| seed | CWE | shape taught to the scanner |
|---|---|---|
| mcp-sanitizer **GHSA-4mfg-r38w-w8fg** | 918 | a URL from tool input reaches an http client behind a private-network/loopback **blocklist** guard that misses the bypass forms: IPv6 `[::1]`, IPv4-mapped `::ffff:127.0.0.1`, `0.0.0.0`, decimal/hex/octal IPs, and no re-check after redirects |
| MCP TS SDK **GHSA-f897-62hf-6gxq** (PR #2698/#2926) | 770 | an HTTP transport reads a request body, or iterates a JSON-RPC batch array, with no size/length cap before parsing → memory exhaustion |

## Detectors added (the product win)

Both scanners (TypeScript `src/detect.ts` + `src/unbounded.ts`, Python `py/mcpscan.py`), with positive
and **negative controls** (a correct guard / a present cap must NOT fire). Test suite: **83 pass**
(was 62).

- **`ssrf-guard-bypass`** — a tainted URL reaching `fetch`/`axios`/`requests`/… is grouped with its
  derivation family (so a guard on `new URL(url).hostname` is linked to the `fetch(url)` that follows),
  and the guard is classified:
  - **complete** (covers `::1` + `0.0.0.0` + `::ffff` mapped, or delegates to a vetted private-IP
    library such as `ipaddr.js`) → suppressed — the *hardened-server* negative control;
  - **incomplete** (names loopback/private but misses those forms) → **flagged** as a live bypass;
  - **allowlist / unrelated** guard (`startsWith(base)`, `host === "api.github.com"`, `isApiUri`) →
    left clean — allowlisting is the correct defense and must never raise a false alarm.
  - Previously a *weak* blocklist guard that threw silently cleared the URL taint → a false-negative;
    this detector closes that gap.
- **`unbounded-body`** — a request-body accumulation loop (`.on("data")` / `for await (… of req)` /
  async stream) that grows a buffer with no running size cap. A request-ish source is required (a
  local file stream is out of scope), and `.write()` (draining out) is not accumulation.
- **`unbounded-batch`** — a JSON-RPC batch (`Array.isArray` / `isinstance(…, list)`) dispatched
  element-by-element with no length cap, gated to JSON-RPC transport files (not CLI/util array code).

A size/length comparison against a positive limit (`received > maxBytes`, `batch.length > MAX`)
suppresses both unbounded detectors — the *cap-present* negative control.

## Corpus (16 public repos)

Official SDKs + servers and widely-used community MCP servers. **The scanner analyzes JavaScript/
TypeScript and Python only** — the Go repos below are effectively unanalyzed and must not be read as
"clean".

| repo | lang | variant findings | note |
|---|---|---|---|
| modelcontextprotocol/typescript-sdk | TS | 17 (all test/example or capped) | the *patched* seed repo — see triage |
| modelcontextprotocol/python-sdk | Py | 0 | |
| modelcontextprotocol/servers | TS/Py | 0 production | 1 filesystem FP (fixed) |
| jlowin/fastmcp | Py | 0 | |
| punkpeye/fastmcp | TS | 1 production (+ test noise) | **lead** — edge transport |
| tadata-org/fastapi_mcp | Py | 0 | |
| supabase-community/supabase-mcp | TS | 1 production | preprocessing, SDK-delegated |
| upstash/context7 | TS | 2 production | preprocessing, SDK-delegated |
| cloudflare/mcp-server-cloudflare | TS | 0 (8 plain `ssrf`, not in scope) | |
| apify/apify-mcp-server | TS | 0 production | |
| awslabs/mcp | Py | 0 | |
| elastic/mcp-server-elasticsearch | TS | 0 | |
| sooperset/mcp-atlassian | Py | 0 | |
| pydantic/pydantic-ai | Py | 0 | |
| github/github-mcp-server | Go | — | **not analyzed (Go)** |
| grafana/mcp-grafana | Go | — | **not analyzed (Go)** |

Raw per-file findings are reproducible with `node dist/src/cli.js <repo> --json`.

## Triage — verified vs hardened

Test/example files (toy servers that legitimately stand up uncapped readers) are excluded from
ranking: 34 such hits across the corpus, all expected noise. Of the production hits:

| candidate | verdict | why |
|---|---|---|
| **punkpeye/fastmcp** `src/edge/index.ts` `#handleMcpRequest` | **LEAD — unbounded batch** | hand-rolled edge Streamable-HTTP dispatches the whole client batch (`for (const message of messages) await #handleMessage(message)`) with only a `length === 0` *minimum* check — no maximum. The Node path uses the patched official SDK; the edge path reimplemented it and missed the cap. Same class as the seed. |
| modelcontextprotocol/typescript-sdk `toNodeHandler` / `toWebRequest` | hardened | the real body reader caps `received > maxRequestBodySize` (413) with `DEFAULT_MAX_REQUEST_BODY_SIZE`; the detector FP was a `res.write(chunk)` response **drain** → precision fix landed |
| supabase-mcp `local-http-entry.ts` `describeRequest` | low impact | iterates the batch only to build a **log line**; real dispatch is delegated to the patched `@modelcontextprotocol` handler (batch-capped) |
| upstash/context7 `filterBatchSelfCancellations` (mcp + admin-mcp) | low impact | iterates the batch to **strip self-cancellation pairs** before handing it to the patched SDK; bounded by the body-size limit |
| typescript-sdk `client/streamableHttp.ts` | out of scope | client-side parsing of **server** responses, not a server-side DoS |
| punkpeye/fastmcp `FastMCP.ts` (Node) | hardened / FP | server-controlled result normalization + tool dedup; Node HTTP path delegates to the patched SDK |

**SSRF guard-bypass: zero production findings across the corpus.** The servers that fetch
tool-controlled URLs either allowlist, delegate to a full private-IP check, or (Cloudflare) fetch
with a tainted URL and no guard at all (plain `ssrf`, the pre-existing class — outside this hunt's
guard-bypass variant, and those servers are credentialed admin tools where that is by design). This
matches the base-rate expectation that major/official servers are hardened against the seed. The
detector still ships as hardening for the ecosystem and for our own `kassi-mcp-probe`.

## Dynamic verification — the fastmcp edge lead

`repro/fastmcp-edge-batch/` holds a benign, bounded repro:

- **Offline mechanism demo** (`batch-dispatch-mechanism.mjs`, no install) — replicates the exact
  dispatch loop beside a capped variant. Observed: the vulnerable shape dispatches the whole batch at
  every size (1 → 100k, linear), while the one-line `length > MAX` guard rejects before any dispatch.

  ```
  batch size |   VULNERABLE (edge/index.ts)      |   FIXED (length>MAX reject)
         100 | dispatched 100 msgs               | dispatched 100
      100000 | dispatched 100000 msgs in 22.3ms  | REJECTED after 0 dispatch
  ```

- **Docker repro** (`Dockerfile` + `probe.mjs`) — stands up a **real** `EdgeFastMCP` at the audited
  commit `febd9b4` and POSTs JSON-RPC batches to its `fetch()` handler, confirming all N messages are
  dispatched with no 4xx (and trending toward OOM under a low `--memory` limit). Left for a human to
  run and disclose responsibly.

Note: the edge runtime's own request-byte limit (Cloudflare Workers / Vercel Edge) bounds the batch
indirectly, so a maintainer should confirm severity against that before disclosure.

## Limitations / honesty

- Static, AST-level; TS line numbers refer to transpiled JS, so use the function name + file, not the
  reported line, when reading source.
- The batch SSRF-guard family grouping is coarse at the handler-parameter level (a deliberate rare
  false-*negative*, never a false alarm).
- Go MCP servers are not analyzed. Several high-value targets (github-mcp-server, grafana) are Go.
- A clean scan is not proof of safety; a reported lead is a candidate for human review, not a CVE.
