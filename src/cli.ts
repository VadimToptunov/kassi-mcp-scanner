#!/usr/bin/env node
// mcp-scan — static security scan for MCP (Model Context Protocol) servers.
//
//   mcp-scan <path> [--json] [--min HIGH|MEDIUM|LOW]
//
// Walks a file or directory (skipping node_modules/dist/.git), scans every TS/JS file that
// imports the MCP SDK, and reports tool/resource/prompt input flowing into dangerous sinks.

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { type Finding, type Severity, scanProject } from "./detect.js";

const SRC_RE = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs|py)$/;
const SKIP = new Set(["node_modules", "dist", ".git", "build", "coverage", "out", "venv", ".venv", "__pycache__",
  // test / spec trees: their fixtures and seams are not a running server's attack surface, and they
  // dominated the sweep's false-positive funnel (deliberately-unsafe fixtures, "not reachable" seams).
  "test", "tests", "__tests__", "spec", "specs", "e2e", "__mocks__",
  // example / demo / docs / fixture / scripts trees: shipped for humans to read or run by hand, never
  // a running server's handler surface — the rest of the sweep's FP funnel came from here. `scripts`
  // was initially kept for recall, but a 10-repo triage showed it was pure non-handler tooling
  // (stdio↔HTTP bridges, config tests); loose build scripts outside it are still caught by TOOL_FILE.
  "example", "examples", "demo", "demos", "sample", "samples", "docs", "doc",
  "fixture", "fixtures", "benchmark", "benchmarks", "bench", "script", "scripts"]);
// Suffixed test/spec dirs the exact-match SKIP set misses: e2e_tests, integration-tests, unit_tests…
const TEST_DIR = /[-_](tests?|specs?|e2e)$/i;
// Test/spec FILES anywhere (foo.test.ts, foo.spec.js, test_foo.py, foo_test.py, conftest.py).
const TEST_FILE = /(\.(test|spec)\.[cm]?[jt]sx?$)|((^|[\/])(test_.*|conftest)\.py$)|(_test\.py$)/i;
// Build / config / codegen tooling files: a repo's verify-examples.mjs, *.config.ts, a bundler config.
// Shipped tooling, not a request-handler surface — these leaked through the sweep as non-handler FPs.
const TOOL_FILE = /(^|[\/])verify-[^\/]*\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]sx?$|(^|[\/])(rollup|webpack|esbuild|vite|vitest|jest|babel|gulpfile|gruntfile)\.[^\/]*$/i;
const isScannable = (p: string) => SRC_RE.test(p) && !TEST_FILE.test(p) && !TOOL_FILE.test(p);
const RANK: Record<Severity, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

// Python MCP/AI servers are analyzed by the sibling ast-based script (py/mcpscan.py); the target
// file is only parsed there, never executed. The script lives at the repo root's `py/`, but this
// module runs from either `src/` (tsx) or `dist/src/` (compiled — tsc nests under dist/ because
// rootDir is "."), so `../py` is right for one and `../../py` for the other. Probe both and fall
// back to the first existing one, so the compiled build does not SILENTLY skip all Python files.
const PY_SCRIPT = ((): string => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.resolve(here, "../py/mcpscan.py"), path.resolve(here, "../../py/mcpscan.py")];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[0];
})();
const PY_GATE = /\b(mcp|fastmcp|modelcontextprotocol)\b|langchain|llama_index|llama-index/i;
let pyMissing = false;

// Python is analyzed as a whole project in one pass (the ast script walks the tree and builds the
// cross-function index itself), so a tainted arg forwarded into a service function in another .py is followed.
function scanPythonProject(target: string): Finding[] {
  if (pyMissing) return [];
  try {
    const out = execFileSync("python3", ["-I", PY_SCRIPT, target], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    return JSON.parse(out) as Finding[];
  } catch (e: any) {
    if (e?.code === "ENOENT") { pyMissing = true; console.error("! python3 not found — skipping Python MCP files"); }
    return [];
  }
}

function walkFiles(root: string, acc: string[] = []): string[] {
  let st: fs.Stats;
  try { st = fs.statSync(root); } catch { return acc; }
  if (st.isFile()) { if (isScannable(root)) acc.push(root); return acc; } // explicit file arg: still skip test files
  if (!st.isDirectory()) return acc;
  for (const e of fs.readdirSync(root, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP.has(e.name) && !TEST_DIR.test(e.name)) walkFiles(path.join(root, e.name), acc); }
    else if (isScannable(e.name)) acc.push(path.join(root, e.name));
  }
  return acc;
}

function main(): void {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const minIdx = args.indexOf("--min");
  const min = (minIdx >= 0 ? args[minIdx + 1] : "LOW") as Severity;
  const target = args.find((a) => !a.startsWith("--") && a !== min);
  if (!target) { console.error("usage: mcp-scan <path> [--json] [--min HIGH|MEDIUM|LOW]"); process.exit(2); }

  const files = walkFiles(path.resolve(target));
  const findings: Finding[] = [];
  // TS/JS: one project pass so cross-function resolution spans the whole repo (not per file).
  const jsFiles: Array<{ file: string; source: string }> = [];
  let hasMcpPy = false;
  for (const f of files) {
    let src: string;
    try { src = fs.readFileSync(f, "utf8"); } catch { continue; }
    if (f.endsWith(".py")) { if (PY_GATE.test(src)) hasMcpPy = true; }
    else jsFiles.push({ file: f, source: src });
  }
  findings.push(...scanProject(jsFiles));
  if (hasMcpPy) findings.push(...scanPythonProject(path.resolve(target))); // one project pass over the Python tree
  // De-duplicate: the same sink can be reached by more than one taint path and get emitted twice. A
  // finding is identified by where it fires and what it says (file:line:id:title:detail) — identical
  // tuples are the same bug reported twice, so keep the first and drop the rest.
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    // One physical sink of one class = one finding. The same location is often reached by several
    // taint paths / handler entry points, each emitting a copy that differs only in its handler label;
    // to a reader those are the same bug, so key on file:line:id and keep the first.
    const key = `${f.file}\u0000${f.line ?? ""}\u0000${f.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const scanned = new Set(deduped.map((x) => x.file)).size;
  const kept = deduped.filter((x) => RANK[x.severity] >= RANK[min]).sort((a, b) => RANK[b.severity] - RANK[a.severity]);

  if (json) { console.log(JSON.stringify(kept, null, 2)); return; }
  console.log(`scanned ${files.length} source file(s); ${scanned} MCP file(s) with findings.`);
  if (!kept.length) { console.log("no findings at or above " + min + "."); return; }
  console.log(`\n${kept.length} finding(s):`);
  for (const f of kept) {
    const rel = path.relative(process.cwd(), f.file);
    console.log(`\n  [${f.severity}] ${f.id} (${f.cwe}) — ${f.title}`);
    console.log(`        ${rel}${f.line ? ":" + f.line : ""}`);
    console.log(`        ${f.detail}`);
  }
  const high = kept.filter((f) => f.severity === "HIGH").length;
  if (high) process.exitCode = 1; // non-zero when HIGH findings exist (CI gate)
}

main();
