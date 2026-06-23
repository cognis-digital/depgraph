// Smoke test for the JS port — run with: node test.js  (Node >= 18, zero deps)
import assert from "assert";
import {
  parseVersion, versionCompare, inRange, levenshtein, typosquatMatch,
  parseRequirements, scoreDependency, scoreToGrade, audit, ADVISORIES,
} from "./index.js";

let passed = 0;
function check(name, fn) { fn(); passed++; }

check("parseVersion", () => {
  assert.deepStrictEqual(parseVersion("2.31.0"), [2, 31, 0]);
  assert.deepStrictEqual(parseVersion("v1.2.3-beta"), [1, 2, 3]);
  assert.deepStrictEqual(parseVersion("0"), [0]);
});

check("versionCompare", () => {
  assert.strictEqual(versionCompare("1.2.3", "1.2.10"), -1);
  assert.strictEqual(versionCompare("2.0", "2.0.0"), 0);
  assert.strictEqual(versionCompare("9.0.0", "8.4.0"), 1);
});

check("levenshtein", () => {
  assert.strictEqual(levenshtein("colorama", "colourama"), 1);
  assert.strictEqual(levenshtein("same", "same"), 0);
});

check("typosquat", () => {
  assert.deepStrictEqual(typosquatMatch("reqests"), ["requests", 1]);
  assert.strictEqual(typosquatMatch("requests"), null);
});

check("inRange", () => {
  const a = ADVISORIES.find(x => x.pkg === "requests");
  assert.ok(inRange("2.28.0", a));
  assert.ok(!inRange("2.31.0", a));
});

check("parseRequirements", () => {
  const deps = parseRequirements("requests==2.28.0\nnumpy\nflask>=2.0\n");
  const by = Object.fromEntries(deps.map(d => [d.name, d]));
  assert.strictEqual(by.requests.version, "2.28.0");
  assert.strictEqual(by.numpy.version, null);
  assert.strictEqual(by.flask.version, null); // >= not a pin
});

check("scoreDependency vuln", () => {
  const d = scoreDependency({ name: "pillow", version: "8.4.0" });
  assert.strictEqual(d.grade, "F");
  assert.ok(d.findings.some(f => f.kind === "vuln" && f.severity === "CRITICAL"));
});

check("scoreDependency clean", () => {
  const d = scoreDependency({ name: "cryptography", version: "42.0.0" });
  assert.strictEqual(d.score, 10);
  assert.strictEqual(d.grade, "A");
});

check("scoreToGrade", () => {
  assert.strictEqual(scoreToGrade(10), "A");
  assert.strictEqual(scoreToGrade(6), "C");
  assert.strictEqual(scoreToGrade(0), "F");
});

check("audit shape", () => {
  const r = audit("requests==2.28.0\nnumpy\n");
  assert.strictEqual(r.tool, "depgraph");
  assert.strictEqual(r.vuln_count, 1);
  assert.ok(["A", "B", "C", "D", "F"].includes(r.project_grade));
});

console.log(`ok - ${passed} JS port test groups passed`);
