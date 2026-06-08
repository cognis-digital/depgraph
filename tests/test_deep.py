"""Deep-feature tests for DEPGRAPH. Standard library only, no network."""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from depgraph import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    audit_text,
    levenshtein,
    list_advisories,
    parse_manifest,
    parse_version,
    score_to_grade,
    typosquat_match,
    version_compare,
)
from depgraph.cli import main  # noqa: E402

DEMO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos", "02-deep"
)

PIP_SAMPLE = (
    "requests==2.28.0\n"
    "urllib3==1.25.0\n"
    "pillow==8.4.0\n"
    "colourama==0.4.6\n"
    "python3-dateutil==2.8.2\n"
    "nose==1.3.7\n"
    "numpy\n"
    "cryptography==42.0.0\n"
)

NPM_SAMPLE = json.dumps(
    {
        "dependencies": {
            "lodash": "4.17.20",
            "axios": "0.19.0",
            "lodahs": "1.0.0",
            "react": "^18.2.0",
        },
        "devDependencies": {"minimist": "1.2.0"},
    }
)


class TestVersions(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(parse_version("2.31.0"), (2, 31, 0))
        self.assertEqual(parse_version("v1.2.3-beta+build"), (1, 2, 3))
        self.assertEqual(parse_version("0"), (0,))

    def test_version_compare(self):
        self.assertEqual(version_compare("1.2.3", "1.2.10"), -1)
        self.assertEqual(version_compare("2.0", "2.0.0"), 0)
        self.assertEqual(version_compare("9.0.0", "8.4.0"), 1)


class TestTyposquat(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(levenshtein("colorama", "colourama"), 1)
        self.assertEqual(levenshtein("same", "same"), 0)

    def test_typosquat_flags_lookalike(self):
        m = typosquat_match("colourama", "pypi")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "colorama")
        self.assertEqual(m[1], 1)

    def test_typosquat_npm(self):
        m = typosquat_match("lodahs", "npm")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "lodash")

    def test_popular_name_not_flagged(self):
        self.assertIsNone(typosquat_match("requests", "pypi"))
        self.assertIsNone(typosquat_match("lodash", "npm"))


class TestManifestParsing(unittest.TestCase):
    def test_pip_parse_pin_vs_unpinned(self):
        deps = parse_manifest("requests==2.28.0\nnumpy\nflask>=2.0", "requirements.txt")
        by = {d.name: d for d in deps}
        self.assertEqual(by["requests"].version, "2.28.0")
        self.assertIsNone(by["numpy"].version)
        self.assertIsNone(by["flask"].version)  # >= is not a concrete pin

    def test_package_json_parse_scopes(self):
        deps = parse_manifest(NPM_SAMPLE, "package.json")
        by = {d.name: d for d in deps}
        self.assertEqual(by["lodash"].version, "4.17.20")
        self.assertEqual(by["react"].version, "18.2.0")  # caret stripped
        self.assertEqual(by["minimist"].scope, "dev")
        self.assertEqual(by["lodash"].ecosystem, "npm")

    def test_pipfile_parse(self):
        text = '[packages]\nrequests = "==2.28.0"\nflask = "*"\n'
        deps = parse_manifest(text, "Pipfile")
        by = {d.name: d for d in deps}
        self.assertEqual(by["requests"].version, "2.28.0")
        self.assertIsNone(by["flask"].version)


class TestAdvisoryMatching(unittest.TestCase):
    def test_vulnerable_version_matches(self):
        res = audit_text("requests==2.28.0", "requirements.txt")
        dep = res.dependencies[0]
        vulns = [f for f in dep.findings if f.kind == "vuln"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].advisory_id, "GHSA-j8r2-6x86-q33q")
        self.assertEqual(vulns[0].severity, "MEDIUM")

    def test_fixed_version_not_matched(self):
        res = audit_text("requests==2.31.0", "requirements.txt")
        dep = res.dependencies[0]
        vulns = [f for f in dep.findings if f.kind == "vuln"]
        self.assertEqual(vulns, [])

    def test_critical_pillow(self):
        res = audit_text("pillow==8.4.0", "requirements.txt")
        dep = res.dependencies[0]
        self.assertEqual(dep.max_severity, "CRITICAL")
        self.assertEqual(dep.grade, "F")

    def test_multi_range_advisory(self):
        # flask advisory has two ranges: < 2.2.5 and [2.3.0, 2.3.2)
        vuln_old = audit_text("flask==2.2.0", "r.txt").dependencies[0]
        vuln_mid = audit_text("flask==2.3.1", "r.txt").dependencies[0]
        safe = audit_text("flask==2.3.3", "r.txt").dependencies[0]
        self.assertTrue(any(f.kind == "vuln" for f in vuln_old.findings))
        self.assertTrue(any(f.kind == "vuln" for f in vuln_mid.findings))
        self.assertFalse(any(f.kind == "vuln" for f in safe.findings))

    def test_npm_advisory(self):
        res = audit_text(NPM_SAMPLE, "package.json")
        by = {d.name: d for d in res.dependencies}
        self.assertTrue(any(f.advisory_id == "GHSA-35jh-r3h4-6jhm"
                            for f in by["lodash"].findings))


class TestHeuristics(unittest.TestCase):
    def test_unpinned_flag(self):
        res = audit_text("numpy", "requirements.txt")
        dep = res.dependencies[0]
        self.assertTrue(any(f.kind == "unpinned" for f in dep.findings))

    def test_deprecated_flag(self):
        res = audit_text("nose==1.3.7", "requirements.txt")
        dep = res.dependencies[0]
        self.assertTrue(any(f.kind == "deprecated" for f in dep.findings))

    def test_typosquat_finding_in_audit(self):
        res = audit_text("python3-dateutil==2.8.2", "requirements.txt")
        dep = res.dependencies[0]
        self.assertTrue(any(f.kind == "typosquat" for f in dep.findings))


class TestScoringAndGrades(unittest.TestCase):
    def test_score_to_grade(self):
        self.assertEqual(score_to_grade(10.0), "A")
        self.assertEqual(score_to_grade(7.6), "B")
        self.assertEqual(score_to_grade(6.0), "C")
        self.assertEqual(score_to_grade(4.0), "D")
        self.assertEqual(score_to_grade(0.0), "F")

    def test_clean_package_grades_A(self):
        res = audit_text("cryptography==42.0.0", "requirements.txt")
        dep = res.dependencies[0]
        self.assertEqual(dep.findings, [])
        self.assertEqual(dep.score, 10.0)
        self.assertEqual(dep.grade, "A")

    def test_project_rollup(self):
        res = audit_text(PIP_SAMPLE, "requirements.txt")
        self.assertGreater(res.vuln_count, 0)
        self.assertGreater(res.finding_count, res.vuln_count)
        self.assertIn(res.project_grade, ("A", "B", "C", "D", "F"))
        self.assertLessEqual(res.project_score, 10.0)

    def test_as_dict_shape(self):
        d = audit_text("requests==2.28.0", "r.txt").as_dict()
        self.assertEqual(
            set(d),
            {
                "source", "dependency_count", "finding_count", "vuln_count",
                "project_score", "project_grade", "dependencies",
            },
        )
        self.assertIn("grade", d["dependencies"][0])


class TestAdvisoryDB(unittest.TestCase):
    def test_list_all(self):
        self.assertGreaterEqual(len(list_advisories()), 10)

    def test_filter_ecosystem(self):
        npm = list_advisories("npm")
        self.assertTrue(all(a["ecosystem"] == "npm" for a in npm))
        self.assertTrue(npm)


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = main(argv)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "depgraph")
        self.assertTrue(TOOL_VERSION)

    def test_audit_demo_requirements_nonzero(self):
        path = os.path.join(DEMO_DIR, "requirements.txt")
        self.assertTrue(os.path.exists(path), "demo manifest must exist")
        rc, out = self._run(["audit", "--format", "json", path])
        self.assertEqual(rc, 1)  # findings -> non-zero
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "depgraph")
        self.assertGreater(payload["vuln_count"], 0)
        names = {d["name"] for d in payload["dependencies"]}
        self.assertIn("pillow", names)
        self.assertIn("colourama", names)

    def test_audit_demo_package_json(self):
        path = os.path.join(DEMO_DIR, "package.json")
        self.assertTrue(os.path.exists(path))
        rc, out = self._run(["audit", "--format", "json", path])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertTrue(any(d["ecosystem"] == "npm" for d in payload["dependencies"]))

    def test_min_severity_gate(self):
        # A lone unpinned (MEDIUM) package should NOT fail a HIGH gate.
        path = os.path.join(DEMO_DIR, "requirements.txt")
        rc_high, _ = self._run(["audit", "--min-severity", "CRITICAL", path])
        # demo has a CRITICAL (pillow) + typosquat -> should fail
        self.assertEqual(rc_high, 1)

    def test_clean_manifest_zero_exit(self):
        tmp = os.path.join(os.path.dirname(__file__), "_tmp_clean_reqs.txt")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("cryptography==42.0.0\n")
        try:
            rc, _ = self._run(["audit", "--format", "json", tmp])
            self.assertEqual(rc, 0)
        finally:
            os.remove(tmp)

    def test_advisories_command(self):
        rc, out = self._run(["advisories", "--format", "json"])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertGreater(payload["count"], 0)

    def test_table_format_runs(self):
        path = os.path.join(DEMO_DIR, "requirements.txt")
        rc, out = self._run(["audit", path])
        self.assertEqual(rc, 1)
        self.assertIn("project:", out)
        self.assertIn("GRADE", out)

    def test_missing_file_returns_2(self):
        old = sys.stderr
        sys.stderr = StringIO()
        try:
            rc = main(["audit", "no_such_manifest_98765.txt"])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
