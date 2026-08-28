# Changelog

## 2.0.0 - Unreleased

- Replaced sequential boolean checks with an evidence-driven, concurrent scan engine.
- Added passive TXT, SPF, CNAME, MX, NS, SRV, and provider-specific subdomain discovery.
- Added a validated catalog of 266 providers and stable provider IDs.
- Added passive-by-default safety, explicit active profiles, verified TLS, rate limiting, retries, and cancellation.
- Added JSON, JSONL, CSV, bulk input, stdin, SQLite history/cache, and scan diffing.
- Added deterministic confidence, sensitive-evidence redaction, and non-vulnerability risk leads.
- Added tests, CI, cross-platform release automation, SBOMs, and signed checksums.
- Added a live TTY-aware operator console that streams accepted findings, evidence updates, and confidence upgrades before the scan finishes.
- Added 12 provider-specific DNS integrations, exact SPF mechanism parsing, official rule references, and label-boundary regression fixtures to reduce false positives.
- Removed crt.sh enrichment so passive scans no longer send target names to a third-party discovery service.
