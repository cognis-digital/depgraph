"""Smoke tests for DEPGRAPH — no network, stdlib only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from depgraph import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Dependency,
    analyze_dependencies,
    analyze_manifest,
    parse_manifest,
    score_dependency,
)
from depgraph.cli import main  # noqa: E402
from depgraph.core import _edit_distance, _is_below, _typosquat_match  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic",
                    "requirements.txt")


class TestMeta(unittest.TestCase):
    def test_exports(self):
        self.assertEqual(TOOL_NAME, "depgraph")
        self.assertTrue(TOOL_VERSION)


class TestVersionLogic(unittest.TestCase):
    def test_is_below(self):
        self.assertTrue(_is_below("1.26.5", "1.26.18"))
        self.assertFalse(_is_below("2.31.0", "2.31.0"))
        self.assertFalse(_is_below("3.0.0", "2.31.0"))
        self.assertTrue(_is_below("5.3.1", "5.4"))

    def test_edit_distance(self):
        self.assertEqual(_edit_distance("reqests", "requests"), 1)
        self.assertEqual(_edit_distance("abc", "abc"), 0)


class TestTyposquat(unittest.TestCase):
    def test_detects_squat(self):
        self.assertEqual(_typosquat_match("reqests"), "requests")

    def test_ignores_legit(self):
        self.assertIsNone(_typosquat_match("requests"))
        self.assertIsNone(_typosquat_match("my-unique-internal-lib"))


class TestScoring(unittest.TestCase):
    def test_vulnerable_dep_scored(self):
        rep = score_dependency(Dependency("pyyaml", "5.3.1", "==5.3.1"))
        cats = {f.category for f in rep.findings}
        self.assertIn("vuln", cats)
        self.assertGreater(rep.risk_score, 0)
        self.assertIn(rep.grade, "ABCDF")

    def test_clean_dep(self):
        rep = score_dependency(Dependency("numpy", "1.26.4", "==1.26.4"))
        self.assertEqual(rep.risk_score, 0)
        self.assertEqual(rep.grade, "A")

    def test_typosquat_dep_high(self):
        rep = score_dependency(Dependency("reqests", "2.31.0", "==2.31.0"))
        self.assertTrue(any(f.category == "typosquat" for f in rep.findings))


class TestManifest(unittest.TestCase):
    def test_parse(self):
        deps = parse_manifest(DEMO)
        names = {d.name for d in deps}
        self.assertIn("requests", names)
        self.assertIn("reqests", names)
        flask = next(d for d in deps if d.name == "flask")
        self.assertIsNone(flask.version)  # unpinned

    def test_analyze(self):
        report = analyze_manifest(DEMO)
        self.assertGreater(report["summary"]["total_dependencies"], 0)
        self.assertGreaterEqual(report["summary"]["vulnerable"], 2)
        self.assertGreaterEqual(report["summary"]["typosquats"], 1)
        # sorted descending by risk
        scores = [d["risk_score"] for d in report["dependencies"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_analyze_dependencies_direct(self):
        out = analyze_dependencies([Dependency("numpy", "1.26.4")])
        self.assertEqual(out["summary"]["total_dependencies"], 1)


class TestCLI(unittest.TestCase):
    def test_json_output(self):
        from io import StringIO
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = main(["scan", DEMO, "--format", "json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("summary", data)
        self.assertIn("dependencies", data)

    def test_missing_file_nonzero(self):
        rc = main(["scan", "does-not-exist.txt"])
        self.assertEqual(rc, 2)

    def test_fail_on_threshold(self):
        rc = main(["scan", DEMO, "--format", "json", "--fail-on", "30"])
        self.assertEqual(rc, 1)

    def test_no_command_returns_one(self):
        self.assertEqual(main([]), 1)


if __name__ == "__main__":
    unittest.main()
