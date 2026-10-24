"""Unit tests for Melqart Sentinel. Run from the melqart folder:

    python -m unittest discover tests
"""

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sentinel  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEV = FIXTURES / "kev_sample.json"
EPSS = FIXTURES / "epss_sample.json"
TODAY = dt.date(2026, 10, 24)


class FilteringTests(unittest.TestCase):
    def test_keeps_only_last_seven_days(self):
        vulns = json.loads(KEV.read_text(encoding="utf-8"))["vulnerabilities"]
        kept = sentinel.recent_entries(vulns, 7, TODAY)
        ids = {v["cveID"] for v in kept}
        self.assertEqual(len(kept), 4)
        self.assertNotIn("CVE-0000-00005", ids)

    def test_skips_bad_dates_instead_of_crashing(self):
        kept = sentinel.recent_entries([{"cveID": "X", "dateAdded": "not-a-date"}], 7, TODAY)
        self.assertEqual(kept, [])


class ClassificationTests(unittest.TestCase):
    def test_watchlist_match_is_act_now(self):
        vuln = {"vendorProject": "PHP Group", "product": "PHP"}
        hits = sentinel.watchlist_hits(vuln, ["php", "chrome"])
        self.assertEqual(hits, ["php"])
        self.assertEqual(sentinel.classify(vuln, None, hits, 0.1), sentinel.LEVEL_ACT_NOW)

    def test_ransomware_is_high(self):
        vuln = {"knownRansomwareCampaignUse": "Known"}
        self.assertEqual(sentinel.classify(vuln, None, [], 0.1), sentinel.LEVEL_HIGH)

    def test_high_epss_is_high(self):
        vuln = {"knownRansomwareCampaignUse": "Unknown"}
        epss = {"epss": 0.45, "percentile": 0.98}
        self.assertEqual(sentinel.classify(vuln, epss, [], 0.1), sentinel.LEVEL_HIGH)

    def test_everything_else_is_monitor(self):
        vuln = {"knownRansomwareCampaignUse": "Unknown"}
        epss = {"epss": 0.02, "percentile": 0.81}
        self.assertEqual(sentinel.classify(vuln, epss, [], 0.1), sentinel.LEVEL_MONITOR)


class EndToEndTests(unittest.TestCase):
    def test_full_offline_run_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            watch = Path(tmp) / "watch.txt"
            watch.write_text("# comment\nphp\n", encoding="utf-8")
            code = sentinel.run([
                "--kev-file", str(KEV), "--epss-file", str(EPSS),
                "--watchlist", str(watch), "--out", tmp, "--today", "2026-10-24",
            ])
            self.assertEqual(code, 0)
            data = json.loads((Path(tmp) / "digest-2026-10-24.json").read_text(encoding="utf-8"))
            levels = [f["level"] for f in data["findings"]]
            self.assertEqual(levels, ["Act now", "High", "High", "Monitor"])
            self.assertEqual(data["findings"][0]["cve"], "CVE-0000-00001")
            self.assertTrue(data["meta"]["test_mode"])
            markdown = (Path(tmp) / "digest-2026-10-24.md").read_text(encoding="utf-8")
            self.assertIn("TEST MODE", markdown)

    def test_missing_kev_file_fails_cleanly(self):
        code = sentinel.run(["--kev-file", "does-not-exist.json", "--no-epss"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
