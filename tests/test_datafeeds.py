"""Tests for the edge/air-gap data-feed catalog. OFFLINE ONLY — never hits the
network. Validates the bundled catalog + the offline cache/snapshot paths.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from depgraph import datafeeds  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_catalog_loads(self):
        cat = datafeeds.load_catalog()
        self.assertIn("feeds", cat)
        self.assertGreaterEqual(len(cat["feeds"]), 20)

    def test_known_feeds_present(self):
        ids = {f["id"] for f in datafeeds.list_feeds()}
        for expected in ("cisa-kev", "epss", "osv", "nvd-cve"):
            self.assertIn(expected, ids)

    def test_feed_records_have_required_fields(self):
        for f in datafeeds.list_feeds():
            self.assertIn("id", f)
            self.assertIn("url", f)
            self.assertIn("name", f)
            self.assertTrue(f["url"].startswith("http"))

    def test_domain_filter(self):
        vuln = datafeeds.list_feeds(domain="vuln")
        self.assertTrue(vuln)
        self.assertTrue(all(f.get("domain") == "vuln" for f in vuln))

    def test_domain_filter_unknown_empty(self):
        self.assertEqual(datafeeds.list_feeds(domain="no-such-domain-zzz"), [])


class TestCacheOffline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._old = os.environ.get("COGNIS_FEEDS_CACHE")
        os.environ["COGNIS_FEEDS_CACHE"] = self._tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("COGNIS_FEEDS_CACHE", None)
        else:
            os.environ["COGNIS_FEEDS_CACHE"] = self._old

    def test_cache_dir_created(self):
        d = datafeeds.cache_dir()
        self.assertTrue(d.exists())

    def test_offline_get_without_cache_raises(self):
        with self.assertRaises(FileNotFoundError):
            datafeeds.get("cisa-kev", offline=True)

    def test_cached_age_none_when_absent(self):
        self.assertIsNone(datafeeds.cached_age_hours("cisa-kev"))

    def test_snapshot_roundtrip(self):
        # Write a fake cached feed, export, wipe, import, read back offline.
        data_path, meta_path = datafeeds._paths("cisa-kev")
        data_path.write_bytes(json.dumps({"vulnerabilities": [{"cveID": "CVE-X"}]}).encode())
        meta_path.write_text(json.dumps({"feed": "cisa-kev", "fetched_at": 1e9,
                                         "format": "json"}), encoding="utf-8")
        snap = os.path.join(self._tmp, "snap.tar.gz")
        n = datafeeds.snapshot_export(snap)
        self.assertGreaterEqual(n, 1)
        data_path.unlink()
        meta_path.unlink()
        imported = datafeeds.snapshot_import(snap)
        self.assertGreaterEqual(imported, 1)
        self.assertTrue(data_path.exists())

    def test_offline_get_after_import(self):
        data_path, meta_path = datafeeds._paths("osv")
        data_path.write_bytes(json.dumps({"vulns": []}).encode())
        meta_path.write_text(json.dumps({"feed": "osv", "fetched_at": 9e18,
                                         "format": "json"}), encoding="utf-8")
        out = datafeeds.get("osv", offline=True)
        self.assertEqual(out, {"vulns": []})


class TestCLIOffline(unittest.TestCase):
    def _run(self, argv):
        from io import StringIO
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = datafeeds.main(argv)
        finally:
            sys.stdout = old
        return rc, buf.getvalue()

    def test_list_command(self):
        rc, out = self._run(["list"])
        self.assertEqual(rc, 0)
        self.assertIn("cisa-kev", out)

    def test_list_domain(self):
        rc, out = self._run(["list", "--domain", "vuln"])
        self.assertEqual(rc, 0)
        self.assertIn("epss", out)


if __name__ == "__main__":
    unittest.main()
