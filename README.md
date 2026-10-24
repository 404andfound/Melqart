# Melqart

> Named after Melqart, "king of the city," the patron and protector of
> Tyre on the Phoenician coast of what is now Lebanon. The system's job is
> the same: guard what is yours.

A defensive, human-in-the-loop system of AI agents that helps a small
organization answer three questions within hours of a new attack wave:

1. **Am I affected?**
2. **How bad is it?**
3. **What do I do first?**

Built as a portfolio project. Inspired by the week of 17–24 October 2026,
when critical PHP and Node.js flaws were exploited at scale, in some cases
before patches existed.

## Scope and ethics (read first)

- **Defense only.** Melqart watches, analyzes and helps fix systems its
  operator owns or is authorized to protect. It never attacks, scans or
  "hacks back" against anyone. Private hack-back is illegal in Sweden and
  most other countries.
- **Human approves every action.** Agents propose; a person decides.
- **Lab first.** All testing happens in an isolated lab (Punchbag) that the
  operator owns.

## The agents

| Agent | Job | Status |
|---|---|---|
| **Sentinel** | Watches public feeds of actively exploited flaws | **v0 built** |
| Scout | Knows what runs in the lab; scans it with Nuclei | planned |
| Analyst | Matches flaws to assets, ranks, explains in plain language | planned |
| Responder | Proposes a fix, waits for approval, rescans to verify | planned |
| Scribe | Writes the incident report (NIS2-style, 24h / 72h) | planned |

## Sentinel v0

Reads two public data sources:

- **CISA KEV** (Known Exploited Vulnerabilities): flaws confirmed to be
  used in real attacks.
- **FIRST EPSS**: the estimated probability that a flaw is exploited in the
  next 30 days.

It keeps the last 7 days of new KEV entries, adds EPSS scores, checks them
against your `watchlist.txt`, and sorts them into three levels:

| Level | Meaning |
|---|---|
| **Act now** | Matches a product on your watchlist |
| **High** | Linked to ransomware, or EPSS ≥ 10% |
| **Monitor** | Exploited somewhere, but not in your watchlist |

Output: `reports/digest-YYYY-MM-DD.md` (for people) and `.json` (for the
next agents).

### Run it on Windows

Needs Python 3.9 or newer, nothing else. Check with `python --version` in
PowerShell.

```powershell
cd path\to\melqart
python sentinel.py
```

Useful options:

```powershell
python sentinel.py --days 14              # look back two weeks
python sentinel.py --epss-threshold 0.05  # stricter "High" level
python sentinel.py --no-epss              # skip EPSS scores
```

### Test it without internet

```powershell
python -m unittest discover tests
python sentinel.py --kev-file tests\fixtures\kev_sample.json --epss-file tests\fixtures\epss_sample.json --today 2026-10-24
```

The sample files contain **fake** entries (CVE-0000-xxxxx) in the real
formats, and reports built from them are marked TEST MODE.

## Known limits of v0

- **KEV lags behind the news.** CISA adds a flaw only after confirming
  exploitation. PHP2Shell was being exploited for days before it appeared
  there. Fix in v1: add vendor advisories and security news as a second
  source.
- **Everything in KEV is already exploited**, so EPSS here measures how
  widely, not whether.
- **Watchlist matching is simple keyword matching.** It over-matches on
  purpose; Scout will replace it with a real asset inventory.

## Roadmap

- v0: Sentinel digest ✔
- v1: Punchbag lab, Scout, Analyst
- v2: Responder with approve-then-verify loop
- v3: Scribe, NIS2-style reports, full write-up
