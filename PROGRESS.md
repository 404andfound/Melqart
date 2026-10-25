# Progress

Update this at the end of every session, before committing.

## Done
- [x] v0 Sentinel: KEV + EPSS digest, watchlist matching, Markdown + JSON
      reports, 8 unit tests passing on fake data (2026-10-24)
- [x] First live run on real CISA data: 8 new KEV entries, 0 watchlist
      matches, EPSS loaded (2026-10-24)
- [x] Published on GitHub: github.com/404andfound/Melqart (2026-10-24)
- [x] Real watchlist built from `winget list` inventory (2026-10-25)
- [x] v0.2: HTML briefing with one-line verdict, opens in browser,
      outside text escaped against XSS; 10 tests (2026-10-25)

## Next
- [ ] v0.2: automatic morning run (Windows Task Scheduler)
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
- Edit Markdown files in a code editor (VS Code), not Windows Notepad
- Treat all feed text as untrusted: escape before display (2026-10-25)

## Findings
- PHP2Shell (biggest story of the week) was not in KEV by 2026-10-24,
  confirming the KEV-lag limit: v1 needs a faster second source
- Windows PowerShell 5.1 shows UTF-8 files garbled; read reports with
  Get-Content -Encoding UTF8 (the files themselves are correct)
- CISA names Chrome/Edge engine flaws "Google Chromium": the keyword
  "chrome" would never have matched (fixed in watchlist)
- Inventory run on JP's PC (2026-10-25): Node.js 24.18.0 predated the
  Oct 21 security release; patched, then uninstalled as unused. Unofficial
  "Grok" chatbot app from an individual publisher removed. Attack surface
  reduced by two programs.

## Last session
2026-10-25: VS Code installed; real watchlist; Node.js and unofficial
chatbot removed; v0.2 HTML briefing built and run live (green, quiet
morning). Next: automatic morning run, then sentinel.py walkthrough.
