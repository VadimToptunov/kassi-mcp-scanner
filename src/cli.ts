#!/usr/bin/env node
// mcp-scan — static security scan for MCP (Model Context Protocol) servers.
//
//   mcp-scan <path> [--json] [--min HIGH|MEDIUM|LOW]
//
// Walks a file or directory (skipping node_modules/dist/.git), scans every TS/JS file that
// imports the MCP SDK, and reports tool/resource/prompt input flowing into dangerous sinks.

import * as fs from "node:fs";
import * as path from "node:path";
import { type Finding, type Severity, scanSource } from "./detect.js";

const SRC_RE = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;
const SKIP = new Set(["node_modules", "dist", ".git", "build", "coverage", "out"]);
const RANK: Record<Severity, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

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
  let scanned = 0;
  for (const f of files) {
    let src: string;
    try { src = fs.readFileSync(f, "utf8"); } catch { continue; }
    const fs_findings = scanSource(src, f);
    if (fs_findings.length) scanned++;
    findings.push(...fs_findings);
  }
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
