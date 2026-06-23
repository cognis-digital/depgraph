"""Smoke tests for DEPGRAPH — no network, stdlib only.

Exercises the current public API (audit_text / audit_file / CLI `audit`).
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from depgraph import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Dependency,
    Finding,
    audit_dependency,
    audit_text,
    levenshtein,
    parse_manifest,
    parse_version,
    score_to_grade,
    typosquat_match,
    version_compare,
)
from depgraph.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "02-deep",
                    "requirements.txt")


class TestMeta(unittest.TestCase):
    def test_exports(self):
        self.assertEqual(TOOL_NAME, "depgraph")
        self.assertTrue(TOOL_VERSION)


class TestVersionLogic(unittest.TestCase):
    def test_below(self):
        self.assertEqual(version_compare("1.26.5", "1.26.18"), -1)
        self.assertEqual(version_compare("2.31.0", "2.31.0"), 0)
        self.assertEqual(version_compare("3.0.0", "2.31.0"), 1)
        self.assertEqual(version_compare("5.3.1", "5.4"), -1)

    def test_parse(self):
        self.assertEqual(parse_version("2.31.0"), (2, 31, 0))
        self.assertEqual(parse_version("0"), (0,))


class TestEditDistance(unittest.TestCase):
    def test_distance(self):
        self.assertEqual(levenshtein("reqests", "requests"), 1)
        self.assertEqual(levenshtein("abc", "abc"), 0)


class TestTyposquat(unittest.TestCase):
    def test_detects_squat(self):
        m = typosquat_match("reqests", "pypi")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "requests")

    def test_ignores_legit(self):
        self.assertIsNone(typosquat_match("requests", "pypi"))
        self.assertIsNone(typosquat_match("my-unique-internal-lib", "pypi"))


class TestScoring(unittest.TestCase):
    def test_vulnerable_dep_scored(self):
        dep = audit_dependency(Dependency("pyyaml", "5.3.1", "pypi"))
        self.assertIn(dep.grade, "ABCDF")

    def test_clean_dep(self):
        dep = audit_dependency(Dependency("numpy", "1.26.4", "pypi"))
        self.assertEqual(dep.score, 10.0)
        self.assertEqual(dep.grade, "A")

    def test_typosquat_dep(self):
        dep = audit_dependency(Dependency("reqests", "2.31.0", "pypi"))
        self.assertTrue(any(f.kind == "typosquat" for f in dep.findings))

    def test_score_to_grade(self):
        self.assertEqual(score_to_grade(10.0), "A")
        self.assertEqual(score_to_grade(0.0), "F")


class TestManifest(unittest.TestCase):
    def test_parse(self):
        with open(DEMO, encoding="utf-8") as fh:
            deps = parse_manifest(fh.read(), DEMO)
        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("colourama", names)

    def test_analyze(self):
        with open(DEMO, encoding="utf-8") as fh:
            res = audit_text(fh.read(), DEMO)
        self.assertGreater(len(res.dependencies), 0)
        self.assertGreaterEqual(res.vuln_count, 1)


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        from io import StringIO
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = main(argv)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_json_output(self):
        rc, out = self._run(["audit", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)  # findings present
        data = json.loads(out)
        self.assertIn("project_grade", data)
        self.assertIn("dependencies", data)

    def test_missing_file_nonzero(self):
        old = sys.stderr
        sys.stderr = __import__("io").StringIO()
        try:
            rc = main(["audit", "does-not-exist.txt"])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
