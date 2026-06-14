"""Hardening tests — edge cases, bad input, and error-path coverage."""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from depgraph.cli import main  # noqa: E402
from depgraph.core import (  # noqa: E402
    Dependency,
    Finding,
    audit_text,
    parse_manifest,
)


class TestEmptyManifests(unittest.TestCase):
    """Empty or whitespace-only manifests must not crash — they return no deps."""

    def test_empty_requirements_txt(self):
        deps = parse_manifest("", "requirements.txt")
        self.assertEqual(deps, [])

    def test_whitespace_only_requirements(self):
        deps = parse_manifest("   \n\n\t\n", "requirements.txt")
        self.assertEqual(deps, [])

    def test_comments_only_requirements(self):
        deps = parse_manifest("# just a comment\n# another comment\n", "requirements.txt")
        self.assertEqual(deps, [])

    def test_empty_package_json_object(self):
        # A valid JSON object with no dep keys is fine — returns empty list.
        deps = parse_manifest(json.dumps({"name": "my-app", "version": "1.0.0"}), "package.json")
        self.assertEqual(deps, [])

    def test_empty_string_package_json(self):
        # Completely empty string for package.json — returns empty list (not a crash).
        deps = parse_manifest("", "package.json")
        self.assertEqual(deps, [])

    def test_empty_pipfile(self):
        deps = parse_manifest("", "Pipfile")
        self.assertEqual(deps, [])

    def test_none_text_treated_as_empty(self):
        # parse_manifest must not crash if caller passes None.
        deps = parse_manifest(None, "requirements.txt")  # type: ignore[arg-type]
        self.assertEqual(deps, [])


class TestMalformedInput(unittest.TestCase):
    """Malformed manifests raise clear ValueError, not raw tracebacks."""

    def test_malformed_package_json_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_manifest("{not valid json}", "package.json")
        self.assertIn("JSON", str(ctx.exception))

    def test_package_json_not_object_raises_value_error(self):
        # Top-level JSON array is not a valid package.json.
        with self.assertRaises(ValueError) as ctx:
            parse_manifest(json.dumps([1, 2, 3]), "package.json")
        self.assertIn("JSON object", str(ctx.exception))

    def test_malformed_package_json_via_cli_returns_2(self):
        # CLI must print an error to stderr and return exit code 2.
        tmp = os.path.join(os.path.dirname(__file__), "_tmp_bad_package.json")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("{bad json!!}")
        try:
            err_buf = StringIO()
            old_err = sys.stderr
            sys.stderr = err_buf
            try:
                rc = main(["audit", tmp])
            finally:
                sys.stderr = old_err
            self.assertEqual(rc, 2)
            self.assertIn("error", err_buf.getvalue().lower())
        finally:
            os.remove(tmp)


class TestMissingSeverityRobustness(unittest.TestCase):
    """Unknown severity strings must not crash max_severity."""

    def test_unknown_severity_does_not_crash(self):
        dep = Dependency("test-pkg", "1.0.0", "pypi")
        dep.findings = [
            Finding(kind="vuln", severity="UNKNOWN_LEVEL", penalty=2.0, message="test"),
            Finding(kind="vuln", severity="HIGH", penalty=4.0, message="real high"),
        ]
        # Should not raise ValueError — returns the severity of the highest known finding.
        result = dep.max_severity
        # HIGH should dominate since UNKNOWN has no order position.
        self.assertEqual(result, "HIGH")

    def test_all_unknown_severities_returns_none_or_unknown(self):
        dep = Dependency("test-pkg", "1.0.0", "pypi")
        dep.findings = [
            Finding(kind="vuln", severity="BOGUS", penalty=1.0, message="test"),
        ]
        result = dep.max_severity
        # Should not crash — returns either the unknown string or "NONE".
        self.assertIsInstance(result, str)


class TestAuditTextEdgeCases(unittest.TestCase):
    """audit_text on edge-case inputs must produce valid AuditResult objects."""

    def test_audit_empty_string(self):
        result = audit_text("", "requirements.txt")
        self.assertEqual(result.dependencies, [])
        self.assertEqual(result.project_score, 10.0)
        self.assertEqual(result.project_grade, "A")
        self.assertEqual(result.finding_count, 0)
        self.assertEqual(result.vuln_count, 0)

    def test_audit_comment_only(self):
        result = audit_text("# no deps here\n", "requirements.txt")
        self.assertEqual(result.dependencies, [])

    def test_audit_single_clean_dep(self):
        result = audit_text("cryptography==42.0.0\n", "requirements.txt")
        self.assertEqual(len(result.dependencies), 1)
        self.assertEqual(result.dependencies[0].grade, "A")

    def test_as_dict_empty(self):
        result = audit_text("", "requirements.txt")
        d = result.as_dict()
        self.assertEqual(d["dependency_count"], 0)
        self.assertEqual(d["finding_count"], 0)
        self.assertEqual(d["project_grade"], "A")


class TestCLIErrorPaths(unittest.TestCase):
    """CLI must return non-zero exit and message to stderr for bad inputs."""

    def _run(self, argv, input_text=None):
        out_buf = StringIO()
        err_buf = StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = out_buf
        sys.stderr = err_buf
        if input_text is not None:
            old_stdin = sys.stdin
            sys.stdin = StringIO(input_text)
        try:
            rc = main(argv)
        finally:
            sys.stdout = old_out
            sys.stderr = old_err
            if input_text is not None:
                sys.stdin = old_stdin
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_missing_file_returns_exit_2(self):
        rc, out, err = self._run(["audit", "no_such_file_xyz_987.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.lower())
        self.assertEqual(out, "")

    def test_multiple_missing_files_returns_exit_2(self):
        rc, out, err = self._run(["audit", "missing_a.txt", "missing_b.txt"])
        self.assertEqual(rc, 2)

    def test_empty_stdin_audit_zero_exit(self):
        # Empty requirements from stdin = no deps = no findings = exit 0.
        rc, out, err = self._run(["audit", "--format", "json"], input_text="")
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["dependency_count"], 0)

    def test_clean_stdin_audit_zero_exit(self):
        rc, out, err = self._run(
            ["audit", "--format", "json"], input_text="cryptography==42.0.0\n"
        )
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["dependency_count"], 1)


if __name__ == "__main__":
    unittest.main()
