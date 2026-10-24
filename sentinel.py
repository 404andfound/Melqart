#!/usr/bin/env python3
"""
Melqart Sentinel v0 - a digest of actively exploited vulnerabilities.

Agent 1 of the Melqart defensive system: WATCH.

What it does
    1. Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog:
       flaws that attackers are confirmed to be using in real attacks.
    2. Keeps only the entries added in the last N days (default 7).
    3. Adds an EPSS score from FIRST for each one: the estimated probability
       that the flaw will be exploited in the next 30 days.
    4. Flags entries that match products in your watchlist (what YOU run).
    5. Ranks everything and writes two reports:
         reports/digest-YYYY-MM-DD.md    for humans
         reports/digest-YYYY-MM-DD.json  for the next Melqart agents

Scope and ethics
    Sentinel only READS two public data feeds. It never scans, connects to,
    or touches any other system. Defensive use only.

Needs only Python 3.9+ and its standard library. No pip installs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "0.1.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = f"Melqart-Sentinel/{VERSION} (defensive research project)"
EPSS_BATCH_SIZE = 50  # CVEs per EPSS request, keeps the URL a safe length

LEVEL_ACT_NOW = "Act now"
LEVEL_HIGH = "High"
LEVEL_MONITOR = "Monitor"
LEVEL_ORDER = [LEVEL_ACT_NOW, LEVEL_HIGH, LEVEL_MONITOR]
LEVEL_REASON = {
    LEVEL_ACT_NOW: "matches a product on your watchlist",
    LEVEL_HIGH: "linked to ransomware, or a high chance of wide exploitation",
    LEVEL_MONITOR: "exploited somewhere, but not in your watchlist",
}


# ---------------------------------------------------------------- loading data

def warn(message: str) -> None:
    print(f"[warning] {message}", file=sys.stderr)


def fetch_json(url: str, timeout: int = 30) -> dict:
    """Download a URL and parse it as JSON."""
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def read_json_file(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_kev(kev_file: Path | None) -> dict:
    """Return the KEV catalog, from a local file if given, else from CISA."""
    if kev_file:
        return read_json_file(kev_file)
    return fetch_json(KEV_URL)


def parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def recent_entries(vulns: list[dict], days: int, today: dt.date) -> list[dict]:
    """Keep entries whose dateAdded falls within the last `days` days."""
    since = today - dt.timedelta(days=days)
    kept = []
    for vuln in vulns:
        added = parse_date(vuln.get("dateAdded", ""))
        if added is None:
            warn(f"skipping {vuln.get('cveID', '?')}: unreadable dateAdded")
            continue
        if since <= added <= today:
            kept.append(vuln)
    return kept


def parse_epss_rows(rows: list[dict]) -> dict[str, dict]:
    scores = {}
    for row in rows:
        try:
            scores[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            }
        except (KeyError, TypeError, ValueError):
            continue
    return scores


def load_epss(cves: list[str], epss_file: Path | None, skip: bool) -> dict[str, dict]:
    """Return {cve: {epss, percentile, date}}. Empty dict if unavailable."""
    if skip or not cves:
        return {}
    if epss_file:
        return parse_epss_rows(read_json_file(epss_file).get("data", []))
    scores: dict[str, dict] = {}
    for start in range(0, len(cves), EPSS_BATCH_SIZE):
        batch = cves[start:start + EPSS_BATCH_SIZE]
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(batch)})}"
        try:
            scores.update(parse_epss_rows(fetch_json(url).get("data", [])))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            warn(f"EPSS scores unavailable, continuing without them ({error})")
            return scores
    return scores


def load_watchlist(path: Path | None) -> list[str]:
    """One product keyword per line. Lines starting with # are comments."""
    if path is None or not path.exists():
        return []
    keywords = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keywords.append(line.lower())
    return keywords


# ---------------------------------------------------------------- analysis

def watchlist_hits(vuln: dict, keywords: list[str]) -> list[str]:
    """Return the watchlist keywords found in the vendor or product name."""
    haystack = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}".lower()
    return [word for word in keywords if word in haystack]


def classify(vuln: dict, epss: dict | None, hits: list[str], threshold: float) -> str:
    if hits:
        return LEVEL_ACT_NOW
    ransomware = vuln.get("knownRansomwareCampaignUse", "").lower() == "known"
    likely = epss is not None and epss["epss"] >= threshold
    if ransomware or likely:
        return LEVEL_HIGH
    return LEVEL_MONITOR


def build_findings(vulns: list[dict], scores: dict, keywords: list[str],
                   threshold: float) -> list[dict]:
    findings = []
    for vuln in vulns:
        cve = vuln.get("cveID", "UNKNOWN")
        epss = scores.get(cve)
        hits = watchlist_hits(vuln, keywords)
        findings.append({
            "cve": cve,
            "level": classify(vuln, epss, hits, threshold),
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "name": vuln.get("vulnerabilityName", ""),
            "summary": vuln.get("shortDescription", ""),
            "date_added": vuln.get("dateAdded", ""),
            "cisa_due_date": vuln.get("dueDate", ""),
            "required_action": vuln.get("requiredAction", ""),
            "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": vuln.get("cwes", []),
            "epss": epss["epss"] if epss else None,
            "epss_percentile": epss["percentile"] if epss else None,
            "watchlist_hits": hits,
            "notes": vuln.get("notes", ""),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        })
    # Most urgent level first; inside a level, highest EPSS first, then newest.
    findings.sort(key=lambda f: f["date_added"], reverse=True)
    findings.sort(key=lambda f: (LEVEL_ORDER.index(f["level"]), -(f["epss"] or 0.0)))
    return findings


# ---------------------------------------------------------------- reporting

def percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def epss_text(finding: dict) -> str:
    if finding["epss"] is None:
        return "not available"
    top = max((1 - finding["epss_percentile"]) * 100, 0.1)
    top_text = f"{top:.1f}" if top < 1 else f"{top:.0f}"
    return f"{percent(finding['epss'])} chance of exploitation in 30 days (top {top_text}% of all CVEs)"


def note_links(notes: str) -> list[str]:
    return [part.strip() for part in notes.split(";") if part.strip().startswith("http")]


def render_markdown(meta: dict, findings: list[dict]) -> str:
    counts = {level: sum(f["level"] == level for f in findings) for level in LEVEL_ORDER}
    ransomware = sum(f["ransomware_use"].lower() == "known" for f in findings)
    lines = [
        f"# Melqart Sentinel digest - {meta['today']}",
        "",
        f"**Window:** last {meta['days']} days (since {meta['since']})  ",
        f"**Source:** CISA KEV catalog, version {meta['catalog_version']}  ",
        f"**EPSS scores:** {meta['epss_status']}  ",
        f"**Watchlist:** {', '.join(meta['watchlist']) or 'empty'}",
    ]
    if meta["test_mode"]:
        lines += ["", "> **TEST MODE:** built from local sample files, not live data."]
    lines += [
        "",
        "## Summary",
        "",
        f"- {len(findings)} newly confirmed exploited vulnerabilities",
        f"- {counts[LEVEL_ACT_NOW]} match your watchlist",
        f"- {ransomware} linked to ransomware campaigns",
        "",
    ]
    if not findings:
        lines.append("Nothing new in this window.")
    for level in LEVEL_ORDER:
        group = [f for f in findings if f["level"] == level]
        if not group:
            continue
        lines += [f"## {level} ({len(group)}): {LEVEL_REASON[level]}", ""]
        for f in group:
            lines += [
                f"### {f['cve']} - {f['vendor']} {f['product']}",
                "",
                f"- **What:** {f['name']}",
                f"- **Summary:** {f['summary']}",
                f"- **Added to KEV:** {f['date_added']} (CISA deadline for US agencies: {f['cisa_due_date']})",
                f"- **Ransomware use:** {f['ransomware_use']}",
                f"- **EPSS:** {epss_text(f)}",
            ]
            if f["watchlist_hits"]:
                lines.append(f"- **Watchlist match:** {', '.join(f['watchlist_hits'])}")
            if f["cwes"]:
                lines.append(f"- **Weakness type:** {', '.join(f['cwes'])}")
            lines.append(f"- **Required action:** {f['required_action']}")
            links = [f["nvd_url"]]
            links += [link for link in note_links(f["notes"]) if link not in links]
            lines.append(f"- **Links:** {' | '.join(links)}")
            lines.append("")
    lines += [
        "---",
        f"Generated by Melqart Sentinel {VERSION}. Reads public feeds only; "
        "scans and touches nothing.",
        "",
    ]
    return "\n".join(lines)


def console_summary(meta: dict, findings: list[dict], paths: list[Path]) -> str:
    counts = {level: sum(f["level"] == level for f in findings) for level in LEVEL_ORDER}
    out = [
        f"Melqart Sentinel {VERSION} - {meta['today']}"
        + (" [TEST MODE]" if meta["test_mode"] else ""),
        f"  {len(findings)} new exploited vulnerabilities in the last {meta['days']} days",
        f"  Act now: {counts[LEVEL_ACT_NOW]} | High: {counts[LEVEL_HIGH]} | Monitor: {counts[LEVEL_MONITOR]}",
    ]
    for f in findings:
        if f["level"] == LEVEL_ACT_NOW:
            out.append(f"  !! {f['cve']}  {f['vendor']} {f['product']}")
    out += [f"  Report: {path}" for path in paths]
    return "\n".join(out)


# ---------------------------------------------------------------- main

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Melqart Sentinel: exploited-vulnerability digest")
    parser.add_argument("--days", type=int, default=7, help="look-back window in days (default 7)")
    parser.add_argument("--watchlist", type=Path, default=here / "watchlist.txt",
                        help="file of product keywords you run (default watchlist.txt)")
    parser.add_argument("--out", type=Path, default=here / "reports", help="report folder")
    parser.add_argument("--epss-threshold", type=float, default=0.10,
                        help="EPSS score that counts as High (default 0.10 = 10%%)")
    parser.add_argument("--no-epss", action="store_true", help="skip EPSS scores")
    parser.add_argument("--kev-file", type=Path, help="use a local KEV JSON file instead of downloading")
    parser.add_argument("--epss-file", type=Path, help="use a local EPSS JSON file instead of downloading")
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today(),
                        help="pretend today is this date (YYYY-MM-DD), for testing")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.days < 1:
        parser.error("--days must be at least 1")
    return args


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        kev = load_kev(args.kev_file)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
        print(f"[error] could not load the KEV catalog: {error}", file=sys.stderr)
        print("        Check your internet connection, or pass --kev-file.", file=sys.stderr)
        return 2

    vulns = recent_entries(kev.get("vulnerabilities", []), args.days, args.today)
    cves = [v.get("cveID", "") for v in vulns if v.get("cveID")]
    scores = load_epss(cves, args.epss_file, args.no_epss)
    keywords = load_watchlist(args.watchlist)
    findings = build_findings(vulns, scores, keywords, args.epss_threshold)

    epss_dates = sorted({s["date"] for s in scores.values() if s.get("date")})
    if args.no_epss:
        epss_status = "skipped"
    elif scores:
        epss_status = f"FIRST EPSS, scored {epss_dates[-1] if epss_dates else 'date unknown'}"
    elif cves:
        epss_status = "unavailable this run"
    else:
        epss_status = "not needed (no new entries)"

    meta = {
        "today": args.today.isoformat(),
        "since": (args.today - dt.timedelta(days=args.days)).isoformat(),
        "days": args.days,
        "catalog_version": kev.get("catalogVersion", "unknown"),
        "epss_status": epss_status,
        "watchlist": keywords,
        "test_mode": bool(args.kev_file),
        "sentinel_version": VERSION,
    }

    args.out.mkdir(parents=True, exist_ok=True)
    md_path = args.out / f"digest-{meta['today']}.md"
    json_path = args.out / f"digest-{meta['today']}.json"
    md_path.write_text(render_markdown(meta, findings), encoding="utf-8")
    json_path.write_text(json.dumps({"meta": meta, "findings": findings}, indent=2),
                         encoding="utf-8")
    print(console_summary(meta, findings, [md_path, json_path]))
    return 0


if __name__ == "__main__":
    sys.exit(run())
