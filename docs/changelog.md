# Changelog - LinkTester

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-09-15
### Added
- **Core Detection Engine**:
  - `UrlParser`: URL normalization, unshortening (safe HTTP redirect tracing), and Anti-SSRF protection.
  - `HeuristicEngine`: IP as host, IDN Punycode homoglyph, subdomain trick, suspicious TLDs, phish keywords, and dangerous extension (.apk, .exe) checks.
  - `WhoisLookup`: RDAP / WHOIS domain age inspection.
  - `ThreatIntel`: Google Safe Browsing, VirusTotal, and URLhaus threat intel connectors with graceful degradation.
  - `ScoreEngine`: Dynamic risk scoring (0-100) with localized mitigation tips.
- **Modern Cybersecurity Dashboard UI**:
  - Dark-mode glassmorphism interface.
  - Animated multi-stage scanning radar (Parsing, Heuristic, Threat Intel, Domain Age, Final Verdict).
  - Risk score gauge with interactive breakdown accordions.
  - Real-time recent scans history.
- **Portability & Deployment**:
  - Ready for XAMPP (Windows/Linux Apache & MySQL).
  - Added `Dockerfile` and `docker-compose.yml` for aaPanel Docker deployment.
  - Clean PHP 8.x PDO without external framework lock-in for seamless cPanel shared hosting compatibility.
  - Full documentation in `docs/` (`prd.md`, `architecture.md`, `schema.md`, `rules.md`, `readme.md`, `changelog.md`).
