# Architecture

`saase` separates target normalization, provider knowledge, network execution, result modeling, output, and persistence so detector behavior can be tested without live vendor requests.

## Data flow

```text
domains / stdin
      │
      ▼
IDNA + public-suffix normalization ──► apex and explicit slug candidates
      │
      ▼
versioned provider catalog ──────────► TXT/SPF and DNS matchers
      │
      ├── passive DNS: TXT, MX, NS, SRV, common CNAMEs
      ├── direct DNS: bounded provider-specific CNAME resolution
      └── explicit active mode: reviewed tenant/SSO probes
      │
      ▼
evidence aggregation ────────────────► deterministic confidence and risk leads
      │
      ├── ordered scan events → live text / silent streams
      ├── deterministic final JSON / JSONL / CSV
      ├── public Go API
      └── SQLite reports, versioned cache, and diffs
```

## Boundaries

- `internal/target` accepts domains and URLs, rejects IPs and malformed names, converts IDNs, and uses the public suffix list rather than taking the first label.
- `internal/catalog` parses and validates embedded or user-supplied YAML. DNS suffix matches require a label boundary, preventing `evilokta.com` from matching `okta.com`; SPF matches require an exact `include:` mechanism domain rather than a substring.
- `internal/engine` owns concurrency, cancellation, timeouts, retries, per-provider pacing, response limits, safe redirects, evidence aggregation, and detector execution.
- `internal/model` is the schema source of truth. Every serialized finding declares schema version `2.0`.
- `internal/output` renders ordered findings immediately for text and silent modes while keeping structured final reports deterministic. Operational errors are returned separately for stderr.
- `internal/store` stores complete reports and indexed finding identities in SQLite. Cache keys include target normalization, selected providers, profile, safety settings, and catalog dimensions.
- `pkg/saase` is the supported public Go API. Internal packages are intentionally not importable by downstream modules.

## Detector policy

Declarative rules are preferred. Go code is reserved for behavior YAML cannot safely express. A detector may only emit a finding after an explicit positive matcher; network success alone is insufficient when a provider offers a stable positive or negative marker.

HTTP 403, 429, and 5xx responses cannot produce findings. Active endpoints are contacted only after `--active`, `--profile standard`, or `--profile deep`. Redirects are not automatically followed, response bodies are capped at 2 MiB, and TLS 1.2 or newer is required by default.

Complex historical v1 probes were removed rather than silently carried forward without fixtures. Git history retains them for controlled migration. New or restored probes must meet the requirements in `CONTRIBUTING.md`.

## Confidence

Confidence measures evidence quality, not impact:

- `medium`: a provider-specific infrastructure relationship or validated tenant response
- `high`: explicit domain verification or provider-positive SSO response
- `confirmed`: two or more independent signal types for the same target/provider

Impact text explains why a provider matters if compromised. `risk_lead` identifies manual review opportunities; it never asserts successful exploitation.
