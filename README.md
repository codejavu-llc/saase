# saase

`saase` is a passive-first SaaS exposure intelligence CLI for authorized bug bounty, red-team, and attack-surface research. Give it an organization domain and it correlates DNS verification records, mail and nameserver infrastructure, provider CNAMEs, and optional tenant probes into evidence-backed findings.

The default scan does not contact target SaaS login endpoints. Active HTTP checks require `--active` or an active profile.

## Why it is different

- 266 provider identities backed by 196 TXT rules and 73 DNS infrastructure rules
- TXT, SPF, CNAME, MX, NS, and SRV signals
- Deterministic `low`, `medium`, `high`, and `confirmed` confidence
- Evidence and errors instead of boolean-only guesses
- Explicit candidates for verification-record review and dangling CNAME review
- Bounded concurrency, per-provider rate limits, retries, cancellation, and verified TLS
- Bulk domains, stdin, provider filtering, proxy support, and tenant slug overrides
- Text, JSON, JSONL, and CSV designed for both humans and pipelines
- Live operator-console text UI that prints accepted findings while scans are still running
- Modern TTY-aware color, elapsed-time markers, confidence upgrades, and evidence trees
- Optional SQLite history, versioned evidence cache, and scan diffs
- No telemetry and no target uploads other than the passive sources selected by the user

## Install

Requires the Go version declared in [`go.mod`](go.mod).

```bash
go install github.com/codejavu-llc/saase/v2@latest
```

From a checkout:

```bash
go build -trimpath -o saase .
./saase version
```

Release archives and the container image are produced for tagged releases.

## Quick start

```bash
# Passive discovery (default)
saase scan -d example.com

# JSONL for jq or another recon tool
saase scan -d example.com --format jsonl | jq -r '.provider_id'

# Multiple domains from a file or stdin
saase scan -l scope.txt --format json
cat scope.txt | saase scan --stdin --silent

# One provider, with bounded tenant probing explicitly enabled
saase scan -d example.com -s slack --active -v

# Save history and reuse evidence for 24 hours
saase scan -d example.com --store recon.db
saase diff --db recon.db --list
saase diff --db recon.db
```

The old root-level flags still work during the v2 compatibility window:

```bash
saase -d example.com -s slack -v -x http://127.0.0.1:8080
```

`-c` remains a deprecated alias for `--providers-file`. Unlike v1, unknown providers are errors rather than silently ignored.

The default text view streams each accepted finding as soon as it is observed, then closes with the aggregated scan summary. It uses a Unicode operator-console layout and enables ANSI color only on an interactive terminal. `--no-color` keeps the layout without escape sequences. `--silent` also streams unique tab-separated matches immediately, while JSON, JSONL, CSV, and files written with `-o` remain deterministic final reports without terminal decoration.

## Profiles and safety

| Profile | Network behavior |
|---|---|
| `passive` | DNS resolution only; no HTTP requests to discovery services or target SaaS endpoints |
| `standard` | Passive signals plus bounded, non-destructive tenant probes |
| `deep` | Currently equivalent to `standard`; reserved for reviewed multi-step SSO probes |

`--active` enables standard active probes without changing the profile name. Active probes never create accounts, claim tenants, send password resets, submit credentials, or attempt exploitation. A detected endpoint is not automatically a vulnerability.

TLS verification is always enabled unless `--insecure` is explicitly supplied. This choice is recorded in JSON metadata.

## Important flags

```text
Input:
  -d, --domain DOMAIN          target domain; repeatable or comma-separated
  -l, --list FILE              target domains, one per line
      --stdin                  read target domains from stdin
  -s, --provider PROVIDER      provider name or stable ID
      --providers-file FILE    provider names or IDs, one per line
      --org NAME               organization override for a single target
      --slug SLUG              extra tenant slug candidate

Scanning:
      --profile PROFILE        passive, standard, or deep
      --active                 enable bounded tenant HTTP probes
      --concurrency N          maximum concurrent operations (default 20)
      --rate-limit N           requests/second/provider (default 2)
      --timeout DURATION       per-operation timeout (default 10s)
      --retries N              transient retries (default 2)
  -x, --proxy URL              HTTP or SOCKS proxy
      --insecure               explicitly disable TLS verification

Output:
      --format FORMAT          text, json, jsonl, or csv
  -o FILE                     mirror stdout results to a file
  -v, --verbose               include evidence and print probe errors to stderr
      --silent                print target, provider ID, and endpoint only
      --show-sensitive-evidence
                              do not redact verification tokens
      --store FILE             persist reports and versioned cache in SQLite
      --cache-ttl DURATION     evidence cache lifetime (default 24h)
```

Run `saase -h`, `saase providers list`, or `saase rules validate` for live information.

## Result semantics

Every structured finding includes a schema version, target, stable provider ID, category, confidence, detector, observation time, and one or more evidence records. Verification tokens are redacted by default.

- `high`: an explicit verification record or strong provider-positive response
- `medium`: provider-specific DNS infrastructure or a validated tenant endpoint
- `confirmed`: at least two independent signal types
- `low`: reserved for ambiguous evidence; low-confidence guesses are not emitted by current built-in detectors

`risk_lead` is triage guidance, not a vulnerability verdict:

- `verification_record_review`: confirm that the SaaS relationship and TXT record are still required
- `potential_dangling_tenant`: a provider CNAME target did not resolve and needs manual validation
- `public_tenant_endpoint`: a bounded active check located a likely tenant URL

Exit codes are `0` for a usable completed scan (including zero findings), `1` for invalid input/configuration, and `2` when all primary discovery probes fail.

## Provider rules

Built-in rules live in [`rules`](rules). `providers.yml` contains exact TXT/SPF patterns, `dns.yml` contains infrastructure suffixes, and `metadata.yml` describes active-only providers. Validate a modified catalog with:

```bash
saase rules validate --rules-dir ./rules
go test ./internal/catalog
```

Simple fingerprints belong in YAML. Stateful flows require a reviewed Go detector, deterministic positive and negative fixtures, rate-limit behavior, and proof that the request cannot mutate vendor state. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

```bash
go test ./...
go test -race ./internal/...
go vet ./...
go test -run '^$' -bench . ./internal/engine
```

The CI workflow also runs rule validation, vulnerability scanning, cross-platform builds, and static analysis. Release artifacts include checksums, SBOMs, and signed checksum files.

## Responsible use

Use `saase` only on assets you own or are explicitly authorized to assess. Respect program scope, provider terms, and rate limits. Do not treat discovery evidence as authorization to access a tenant or attempt a takeover. See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Rights and attribution

Copyright © CodejaVu. All rights reserved. Public source visibility does not grant permission to copy, modify, redistribute, or create derivatives. See [COPYRIGHT](COPYRIGHT).

The built-in rule catalog incorporates BSD-3-Clause material from `mubix/saas-enum`; required attribution is preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
