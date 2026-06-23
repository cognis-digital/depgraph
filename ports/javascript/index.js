#!/usr/bin/env node
// JavaScript port of the depgraph core surface — offline, zero deps.
//
// Mirrors the Python reference: parse a pip requirements.txt, run a
// Levenshtein typosquat check against popular package names, and match each
// pinned version against a small embedded OSV-style advisory set. Same JSON
// output shape ({tool, version, dependencies[], project_score, project_grade}).
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

export const POPULAR = [
  "requests", "urllib3", "numpy", "pandas", "flask", "django", "pillow",
  "lxml", "cryptography", "colorama", "python-dateutil", "setuptools",
];

export const ADVISORIES = [
  { id: "GHSA-j8r2-6x86-q33q", alias: "CVE-2023-32681", pkg: "requests", sev: "MEDIUM", introduced: "2.3.0", fixed: "2.31.0" },
  { id: "GHSA-9wx4-h78v-vm56", alias: "CVE-2021-33503", pkg: "urllib3", sev: "HIGH", introduced: "0", fixed: "1.26.5" },
  { id: "GHSA-h5c8-rqwp-cp95", alias: "CVE-2022-22817", pkg: "pillow", sev: "CRITICAL", introduced: "0", fixed: "9.0.0" },
  { id: "GHSA-8q59-q68h-6hv4", alias: "CVE-2022-2309", pkg: "lxml", sev: "MEDIUM", introduced: "0", fixed: "4.9.1" },
];

const SEV_PENALTY = { LOW: 1.0, MEDIUM: 2.5, HIGH: 4.0, CRITICAL: 6.5 };

export function parseVersion(v) {
  if (v == null) return [0];
  const m = String(v).replace(/^[vV=]+/, "").split(/[+\s-]/)[0].match(/\d+/g);
  return m ? m.slice(0, 4).map(Number) : [0];
}

export function versionCompare(a, b) {
  const ta = parseVersion(a), tb = parseVersion(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i] || 0, y = tb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function inRange(version, adv) {
  if (versionCompare(version, adv.introduced || "0") < 0) return false;
  if (adv.fixed && versionCompare(version, adv.fixed) >= 0) return false;
  return true;
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[b.length];
}

export function typosquatMatch(name) {
  const ln = name.toLowerCase();
  if (POPULAR.includes(ln)) return null;
  let best = null, bestD = 99;
  for (const cand of POPULAR) {
    if (Math.abs(cand.length - ln.length) > 2) continue;
    const d = levenshtein(ln, cand);
    if (d < bestD) { bestD = d; best = cand; }
  }
  return bestD === 1 ? [best, 1] : null;
}

export function parseRequirements(text) {
  const deps = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("#")[0].trim();
    if (!line || /^[-./]|^git\+|^http/.test(line)) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|~=|>=|<=|>|<|!=)?\s*([A-Za-z0-9][\w.*+!-]*)?/);
    if (!m) continue;
    const op = m[2], ver = m[3];
    deps.push({ name: m[1], version: (op === "==" || op === "~=") && ver ? ver : null });
  }
  return deps;
}

export function scoreDependency(dep) {
  const findings = [];
  for (const adv of ADVISORIES) {
    if (adv.pkg !== dep.name.toLowerCase()) continue;
    if (dep.version && inRange(dep.version, adv)) {
      findings.push({ kind: "vuln", severity: adv.sev, advisory_id: adv.id,
        message: `${adv.id} (${adv.alias}) affects ${dep.name} ${dep.version}` });
    }
  }
  const ts = typosquatMatch(dep.name);
  if (ts) findings.push({ kind: "typosquat", severity: "CRITICAL",
    message: `'${dep.name}' is 1 edit from popular '${ts[0]}'` });
  if (dep.version == null) findings.push({ kind: "unpinned", severity: "MEDIUM",
    message: `'${dep.name}' is not pinned` });
  let penalty = 0;
  for (const f of findings) penalty += f.kind === "typosquat" ? 5.0 : (f.kind === "unpinned" ? 1.5 : (SEV_PENALTY[f.severity] || 2.0));
  const score = Math.max(0, Math.round((10 - penalty) * 100) / 100);
  return { ...dep, score, grade: scoreToGrade(score), findings };
}

export function scoreToGrade(s) {
  if (s >= 9) return "A"; if (s >= 7.5) return "B"; if (s >= 6) return "C";
  if (s >= 4) return "D"; return "F";
}

export function audit(text) {
  const deps = parseRequirements(text).map(scoreDependency);
  const proj = deps.length ? deps.reduce((a, d) => a + d.score, 0) / deps.length : 10;
  const score = Math.round(proj * 100) / 100;
  const vuln_count = deps.reduce((a, d) => a + d.findings.filter(f => f.kind === "vuln").length, 0);
  return { tool: "depgraph", version: "2.1.0", dependency_count: deps.length,
    vuln_count, project_score: score, project_grade: scoreToGrade(score), dependencies: deps };
}

const _isMain = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (_isMain) {
  const path = process.argv[2];
  if (path) {
    console.log(JSON.stringify(audit(readFileSync(path, "utf8")), null, 2));
  } else {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (buf += c));
    process.stdin.on("end", () =>
      console.log(JSON.stringify(audit(buf), null, 2)));
  }
}
