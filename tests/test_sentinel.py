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
                "--no-open",
            ])
            self.assertEqual(code, 0)
            data = json.loads((Path(tmp) / "digest-2026-10-24.json").read_text(encoding="utf-8"))
            levels = [f["level"] for f in data["findings"]]
            self.assertEqual(levels, ["Act now", "High", "High", "Monitor"])
            self.assertEqual(data["findings"][0]["cve"], "CVE-0000-00001")
            self.assertTrue(data["meta"]["test_mode"])
            markdown = (Path(tmp) / "digest-2026-10-24.md").read_text(encoding="utf-8")
            self.assertIn("TEST MODE", markdown)
            page = (Path(tmp) / "digest-2026-10-24.html").read_text(encoding="utf-8")
            self.assertIn("TEST MODE", page)
            self.assertIn("Act now", page)

    def test_missing_kev_file_fails_cleanly(self):
        code = sentinel.run(["--kev-file", "does-not-exist.json", "--no-epss"])
        self.assertEqual(code, 2)


class HtmlBriefingTests(unittest.TestCase):
    def finding(self, **changes):
        base = {
            "cve": "CVE-0000-00009", "level": sentinel.LEVEL_MONITOR,
            "vendor": "TestCo", "product": "TestApp", "name": "TEST",
            "summary": "TEST summary", "date_added": "2026-10-24",
            "cisa_due_date": "2026-11-14", "required_action": "Patch it.",
            "ransomware_use": "Unknown", "cwes": [], "epss": 0.05,
            "epss_percentile": 0.9, "watchlist_hits": [], "notes": "",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-0000-00009",
        }
        base.update(changes)
        return base

    def meta(self):
        return {"today": "2026-10-24", "days": 7, "catalog_version": "TEST",
                "epss_status": "TEST", "watchlist": [], "test_mode": True,
                "sentinel_version": sentinel.VERSION}

    def test_outside_text_cannot_inject_code(self):
        evil = self.finding(summary='<script>alert("x")</script>',
                            notes="javascript:alert(1)")
        page = sentinel.render_html(self.meta(), [evil])
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn('href="javascript:', page)

    def test_verdict_sentences(self):
        empty = {sentinel.LEVEL_ACT_NOW: 0, sentinel.LEVEL_HIGH: 0, sentinel.LEVEL_MONITOR: 3}
        self.assertEqual(sentinel.verdict(empty)[0], "ok")
        high = dict(empty, **{sentinel.LEVEL_HIGH: 2})
        self.assertEqual(sentinel.verdict(high)[0], "high")
        act = dict(high, **{sentinel.LEVEL_ACT_NOW: 1})
        self.assertIn("1 actively exploited flaw affects", sentinel.verdict(act)[1])

    def test_high_sentence_grammar(self):
        # Regression test: 2026-10-26 the banner said "1 high-risk flaw are".
        counts = {sentinel.LEVEL_ACT_NOW: 0, sentinel.LEVEL_HIGH: 1, sentinel.LEVEL_MONITOR: 7}
        self.assertIn("1 high-risk flaw is worth", sentinel.verdict(counts)[1])
        counts[sentinel.LEVEL_HIGH] = 2
        self.assertIn("2 high-risk flaws are worth", sentinel.verdict(counts)[1])


if __name__ == "__main__":
    unittest.main()
