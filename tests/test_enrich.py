"""Tests for OSV-offline enrichment against the bundled 262k-record corpus.

All offline, stdlib only. Proves real lookups resolve (log4j / requests / lodash)
and that enrichment is additive and conservative.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from depgraph.core import Dependency, audit_text  # noqa: E402
from depgraph.enrich import (  # noqa: E402
    EnrichmentHit,
    enrich_dependency,
    enrich_result,
    enrichment_findings,
    lookup_cve,
    lookup_package,
)
from depgraph.vulndb_local import VulnDB  # noqa: E402
from depgraph.cli import main  # noqa: E402

DB = VulnDB()


class TestDBBaseline(unittest.TestCase):
    def test_db_has_262k_records(self):
        self.assertGreaterEqual(DB.count(), 260000)

    def test_record_shape(self):
        r = next(iter(DB))
        for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(f, r)


class TestCveLookup(unittest.TestCase):
    def test_log4shell_resolves(self):
        # The canonical proof: CVE-2021-44228 (Log4Shell) must be in the bundle.
        recs = lookup_cve("CVE-2021-44228")
        self.assertTrue(recs, "CVE-2021-44228 must resolve in the bundled OSV DB")
        # GHSA for Log4Shell is GHSA-jfh8-c2jp-5v3q
        ids = {r["id"] for r in recs}
        aliases = {a for r in recs for a in (r.get("aliases") or [])}
        self.assertTrue("GHSA-jfh8-c2jp-5v3q" in ids or "CVE-2021-44228" in aliases)

    def test_log4shell_mentions_log4j(self):
        recs = lookup_cve("CVE-2021-44228")
        pkgs = {p.lower() for r in recs for p in (r.get("packages") or [])}
        self.assertTrue(any("log4j" in p for p in pkgs))

    def test_cve_case_insensitive(self):
        a = lookup_cve("CVE-2021-44228")
        b = lookup_cve("cve-2021-44228")
        self.assertEqual(len(a), len(b))

    def test_unknown_cve_empty(self):
        self.assertEqual(lookup_cve("CVE-0000-00000"), [])

    def test_ghsa_lookup(self):
        recs = lookup_cve("GHSA-jfh8-c2jp-5v3q")
        self.assertTrue(recs)

    def test_other_known_cves_resolve(self):
        # A spread of well-known historical CVEs that should be in any real OSV bundle.
        for cve in ("CVE-2023-32681", "CVE-2021-33503", "CVE-2021-23337"):
            self.assertTrue(lookup_cve(cve), f"{cve} should resolve")


class TestPackageLookup(unittest.TestCase):
    def test_requests_has_many_advisories(self):
        recs = lookup_package("requests", ecosystem="PyPI")
        self.assertGreaterEqual(len(recs), 3)

    def test_lodash_resolves(self):
        recs = lookup_package("lodash")
        self.assertTrue(recs)

    def test_django_resolves(self):
        recs = lookup_package("django", ecosystem="PyPI")
        self.assertTrue(recs)

    def test_package_case_insensitive(self):
        self.assertEqual(len(lookup_package("Requests")), len(lookup_package("requests")))

    def test_nonexistent_package_empty(self):
        self.assertEqual(lookup_package("zzz-not-a-real-package-9988"), [])

    def test_ecosystem_filter(self):
        # filtering to a wrong ecosystem should reduce/zero the hits for a pypi pkg
        pypi = lookup_package("requests", ecosystem="PyPI")
        npm = lookup_package("requests", ecosystem="npm")
        self.assertGreater(len(pypi), len(npm))


class TestEnrichDependency(unittest.TestCase):
    def test_enrich_requests(self):
        hits = enrich_dependency(Dependency("requests", "2.28.0", "pypi"))
        self.assertTrue(hits)
        self.assertIsInstance(hits[0], EnrichmentHit)
        self.assertTrue(all(isinstance(h.advisory_id, str) for h in hits))

    def test_enrich_respects_limit(self):
        hits = enrich_dependency(Dependency("requests", None, "pypi"), limit=2)
        self.assertLessEqual(len(hits), 2)

    def test_enrich_dedupes(self):
        hits = enrich_dependency(Dependency("requests", "2.28.0", "pypi"), limit=200)
        ids = [h.advisory_id for h in hits]
        self.assertEqual(len(ids), len(set(ids)))

    def test_enrich_internal_package_empty(self):
        hits = enrich_dependency(Dependency("my-internal-thing-xyz", "1.0.0", "pypi"))
        self.assertEqual(hits, [])

    def test_hit_as_dict(self):
        hits = enrich_dependency(Dependency("requests", "2.28.0", "pypi"), limit=1)
        d = hits[0].as_dict()
        self.assertEqual(set(d), {"advisory_id", "aliases", "ecosystem", "severity", "summary"})


class TestEnrichResult(unittest.TestCase):
    def test_enrich_audit_result(self):
        res = audit_text("requests==2.28.0\nlodash\n", "requirements.txt")
        report = enrich_result(res)
        self.assertEqual(report["db_record_count"], DB.count())
        self.assertGreaterEqual(report["dependencies_with_osv_refs"], 1)
        self.assertGreater(report["total_osv_references"], 0)
        self.assertIn("pypi:requests", report["packages"])

    def test_enrich_does_not_mutate(self):
        res = audit_text("requests==2.28.0", "r.txt")
        before = len(res.dependencies[0].findings)
        enrich_result(res)
        self.assertEqual(len(res.dependencies[0].findings), before)

    def test_enrich_clean_manifest(self):
        res = audit_text("my-internal-lib-aaa==1.0.0", "r.txt")
        report = enrich_result(res)
        self.assertEqual(report["total_osv_references"], 0)
        self.assertEqual(report["packages"], {})


class TestEnrichmentFindings(unittest.TestCase):
    def test_findings_are_zero_penalty(self):
        fs = enrichment_findings(Dependency("requests", "2.28.0", "pypi"), limit=5)
        self.assertTrue(fs)
        self.assertTrue(all(f.penalty == 0.0 for f in fs))
        self.assertTrue(all(f.kind == "osv-ref" for f in fs))

    def test_findings_do_not_change_grade(self):
        dep = Dependency("numpy", "1.26.4", "pypi")
        dep.findings = enrichment_findings(dep, limit=5)
        # numpy clean curated -> osv-ref findings are informational, grade stays A
        self.assertEqual(dep.grade, "A")


class TestEnrichCLI(unittest.TestCase):
    def _run(self, argv):
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = main(argv)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_enrich_json(self):
        tmp = os.path.join(os.path.dirname(__file__), "_enrich_reqs.txt")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("requests==2.28.0\n")
        try:
            rc, out = self._run(["enrich", tmp, "--format", "json"])
            self.assertEqual(rc, 0)
            data = json.loads(out)
            self.assertIn("osv_enrichment", data)
            self.assertGreater(data["osv_enrichment"]["total_osv_references"], 0)
        finally:
            os.remove(tmp)

    def test_enrich_table(self):
        rc, out = self._run(["enrich", "--format", "table"])  # reads stdin? no -> empty
        # with no stdin in test runner, just ensure command path is wired
        self.assertIn(rc, (0, 1, 2))

    def test_vulndb_count(self):
        rc, out = self._run(["vulndb", "--count", "--format", "json"])
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(json.loads(out)["db_record_count"], 260000)

    def test_vulndb_cve(self):
        rc, out = self._run(["vulndb", "--cve", "CVE-2021-44228", "--format", "json"])
        self.assertEqual(rc, 1)  # match found -> non-zero CI signal
        data = json.loads(out)
        self.assertGreater(data["count"], 0)

    def test_vulndb_cve_table(self):
        rc, out = self._run(["vulndb", "--cve", "CVE-2021-44228"])
        self.assertEqual(rc, 1)
        self.assertIn("log4j", out.lower())

    def test_vulndb_package(self):
        rc, out = self._run(["vulndb", "--package", "lodash", "--format", "json"])
        self.assertEqual(rc, 1)
        self.assertGreater(json.loads(out)["count"], 0)

    def test_vulndb_search(self):
        rc, out = self._run(["vulndb", "--search", "deserialization", "--limit", "5",
                             "--format", "json"])
        self.assertEqual(rc, 0)  # search is not a CI-gate
        self.assertGreaterEqual(json.loads(out)["count"], 1)

    def test_vulndb_no_args(self):
        old = sys.stderr
        sys.stderr = StringIO()
        try:
            rc = main(["vulndb"])
        finally:
            sys.stderr = old
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
