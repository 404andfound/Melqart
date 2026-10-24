# Progress

Update this at the end of every session, before committing.

## Done
- [x] v0 Sentinel: KEV + EPSS digest, watchlist matching, Markdown + JSON
      reports, 8 unit tests passing on fake data (2026-10-24)

## Next
- [ ] First live run on real CISA data
- [ ] JP walkthrough of sentinel.py: can explain every function
- [ ] v1: second source (vendor advisories / security news), since KEV lags
- [ ] v1: Punchbag lab (isolated Docker, PHP app) + Scout (Nuclei scans of the lab only)
- [ ] v1: Analyst (match findings to lab assets, plain-language summary)
- [ ] v2: Responder (propose fix, human approves, rescan to verify)
- [ ] v3: Scribe (NIS2-style report: 24h early warning, 72h notification) + write-up

## Decisions
- Name: Melqart, after the protector of Tyre (2026-10-24)
- Defense only, human approves every action
- Standard library only for Sentinel, so it runs anywhere with plain Python
- No third-party Claude Code plugins for now (supply-chain risk)

## Last session
2026-10-24: built Sentinel v0 in Claude chat; tested offline only (sandbox
could not reach CISA/FIRST).
