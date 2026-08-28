# Contributing

The highest-impact contributions are documented provider fingerprints, deterministic fixtures, and false-positive corrections.

## Rule changes

1. Add TXT/SPF fingerprints to `rules/providers.yml`, DNS infrastructure to `rules/dns.yml`, or active-only provider descriptions to `rules/metadata.yml`.
2. Use a stable provider name and category. Prefer exact prefixes and DNS suffix boundaries over broad substrings.
3. Include a primary vendor documentation URL whenever one exists.
4. Never commit a real verification token, credential, cookie, customer domain, or private response.
5. Run `go run . rules validate`, `go test ./...`, and `go vet ./...`.

Active detectors must be non-destructive, bounded, and supported by positive, negative, 403, 429, 5xx, timeout, and malformed-response tests. Account creation, tenant claiming, password reset, credential submission, and authenticated exploitation are out of scope.

## Contribution terms

This repository is source-available and all-rights-reserved; it is not distributed under an open-source license. By intentionally submitting a contribution, you represent that you have the right to submit it and grant CodejaVu a perpetual, worldwide, non-exclusive, irrevocable, royalty-free license to use, reproduce, modify, distribute, sublicense, and relicense that contribution as part of this project and related products.

Do not submit a contribution if you cannot grant those rights. Organizations should have these terms reviewed by their own counsel.
