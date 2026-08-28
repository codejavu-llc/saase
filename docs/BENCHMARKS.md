# Benchmark and accuracy methodology

Performance and accuracy claims must be reproducible and must not depend on a cherry-picked live target.

## Local CPU benchmark

```bash
go test -run '^$' -bench . -benchmem ./internal/engine
```

`BenchmarkPassiveRuleMatching` measures the complete TXT rule set against matched and unmatched records. It excludes network latency.

## Controlled end-to-end benchmark

Use an authorized corpus containing at least:

- 25 domains with documented positive TXT, MX, NS, and CNAME relationships
- 25 negative/control domains
- NXDOMAIN, SERVFAIL, timeout, wildcard, 403, 429, and 5xx fixtures
- domains below multi-label public suffixes and IDN targets

Run each domain three times with a cold cache and the default passive profile:

```bash
/usr/bin/time -v saase scan -l benchmark-domains.txt --no-cache --format json -o results.json
```

Report median and p95 wall time, peak RSS, requests per signal source, findings, probe errors, precision, recall, and the exact catalog/version commit. The release target is passive p95 below 30 seconds, at least 95% precision, and no false finding produced by an error status.

Do not publish customer domains or unredacted verification tokens. A public benchmark corpus should use controlled DNS zones, vendor-provided examples, and synthetic HTTP/DNS fixtures.

## Regression gates

- Every YAML catalog revision must pass schema and matcher validation.
- The engine test suite must remain above 80% statement coverage.
- Active matcher tests must include positive, explicit negative, malformed, timeout, 403, 429, and 5xx behavior.
- Live provider health checks, when maintained, must be opt-in and must never run against arbitrary organizations in CI.
