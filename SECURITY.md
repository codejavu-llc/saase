# Security policy

## Supported versions

Security fixes are provided for the latest tagged v2 release. Users should upgrade before reporting behavior already fixed on the default branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in `saase`, its release process, or a built-in detector that could cause unintended vendor-side actions.

Use GitHub's private vulnerability reporting feature for this repository. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. Remove real target domains, credentials, session tokens, and unredacted verification values from reports.

CodejaVu will acknowledge a complete report when maintainers are available, investigate it privately, and coordinate disclosure after a fix. This policy does not create a bug bounty or promise payment.

## Scope

Provider behavior changes and false positives are normally correctness bugs, not security vulnerabilities. They become security issues when a detector can mutate remote state, disclose non-public data, bypass authorization, leak sensitive local data, or expose users through the update/release chain.
