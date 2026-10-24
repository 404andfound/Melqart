# Melqart: rules for any AI assistant working in this repo

Melqart is a defensive, human-in-the-loop system of agents for vulnerability
triage. It is JP's portfolio project: JP must be able to explain every line.

## Hard rules
- Defense only. Never write code that scans, probes or attacks systems the
  operator does not own. No hack-back, no exploit code outside the local lab.
- Agents propose; a human approves. No autonomous changes to real systems.
- Python standard library only, unless JP agrees to a new dependency.

## How we work
1. Read PROGRESS.md first. It says what is done and what is next.
2. Explain a change in plain language before making it.
3. Every change keeps `python -m unittest discover tests` passing; new logic
   gets a test.
4. Small commits with clear messages. Update PROGRESS.md before committing.

## Layout
- sentinel.py: agent 1 (watch), reads CISA KEV + FIRST EPSS
- watchlist.txt: products the operator runs
- tests/: unit tests and fake fixture data (CVE-0000-xxxxx, never real)
- reports/: generated digests, not committed
