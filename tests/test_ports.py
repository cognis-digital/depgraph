"""Cross-language port parity tests.

Runs the JS and shell ports (skipped if the toolchain is absent) against the
same manifest the Python reference scores, and asserts they agree on the key
verdicts (vuln count, project grade, typosquat detection). Offline, stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from depgraph.core import audit_text  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = "pillow==8.4.0\nreqests==2.31.0\nrequests==2.28.0\nnumpy\ncryptography==42.0.0\n"


class TestPythonReferenceBaseline(unittest.TestCase):
    def setUp(self):
        self.res = audit_text(MANIFEST, "requirements.txt")

    def test_vuln_count(self):
        # pillow 8.4.0 (CRITICAL) + requests 2.28.0 (MEDIUM) = 2 curated vulns
        self.assertEqual(self.res.vuln_count, 2)

    def test_project_grade(self):
        # mixed manifest averages to a C (one A, two B, one D, one F)
        self.assertEqual(self.res.project_grade, "C")

    def test_typosquat_detected(self):
        by = {d.name: d for d in self.res.dependencies}
        self.assertTrue(any(f.kind == "typosquat" for f in by["reqests"].findings))


class TestJSPortParity(unittest.TestCase):
    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("node not installed")
        self.script = os.path.join(ROOT, "ports", "javascript", "index.js")

    def _run(self):
        p = subprocess.run(
            ["node", self.script],
            input=MANIFEST, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_tool_field(self):
        self.assertEqual(self._run()["tool"], "depgraph")

    def test_vuln_count_matches_python(self):
        py = audit_text(MANIFEST, "r.txt")
        self.assertEqual(self._run()["vuln_count"], py.vuln_count)

    def test_project_grade_matches_python(self):
        py = audit_text(MANIFEST, "r.txt")
        self.assertEqual(self._run()["project_grade"], py.project_grade)

    def test_dependency_count(self):
        self.assertEqual(self._run()["dependency_count"], 5)


class TestShellPortParity(unittest.TestCase):
    def setUp(self):
        if not shutil.which("sh") and not shutil.which("bash"):
            self.skipTest("sh not available")
        self.script = os.path.join(ROOT, "ports", "shell", "depgraph.sh")
        if not os.path.exists(self.script):
            self.skipTest("shell port missing")

    def _run(self):
        sh = shutil.which("sh") or shutil.which("bash")
        p = subprocess.run(
            [sh, self.script],
            input=MANIFEST, capture_output=True, text=True, timeout=30,
        )
        return p.stdout

    def test_flags_critical_pillow(self):
        out = self._run()
        self.assertRegex(out, r"F\s+pillow")

    def test_flags_typosquat(self):
        self.assertIn("typosquat: reqests", self._run())

    def test_project_rollup_present(self):
        self.assertRegex(self._run(), r"project:\s+[A-F]\s+score=")

    def test_clean_pkg_grades_a(self):
        self.assertRegex(self._run(), r"A\s+cryptography")


if __name__ == "__main__":
    unittest.main()
