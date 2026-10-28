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
const SKIP = new Set(["node_modules", "dist", ".git", "build", "coverage", "out", "venv", ".venv", "__pycache__"]);
const RANK: Record<Severity, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

// Python MCP/AI servers are analyzed by the sibling ast-based script (py/mcpscan.py); the target
// file is only parsed there, never executed. Resolve the script next to this module (src/ or dist/).
const PY_SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../py/mcpscan.py");
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
  if (st.isFile()) { if (SRC_RE.test(root)) acc.push(root); return acc; }
  if (!st.isDirectory()) return acc;
  for (const e of fs.readdirSync(root, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP.has(e.name)) walkFiles(path.join(root, e.name), acc); }
    else if (SRC_RE.test(e.name)) acc.push(path.join(root, e.name));
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
  const scanned = new Set(findings.map((x) => x.file)).size;
  const kept = findings.filter((x) => RANK[x.severity] >= RANK[min]).sort((a, b) => RANK[b.severity] - RANK[a.severity]);

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
