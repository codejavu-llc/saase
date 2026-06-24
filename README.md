# saase — SaaS Attack Surface Enumerator

> The first tool purpose-built to enumerate the SaaS attack surface of a target organization.

`saase` discovers third-party SaaS services and integrations used by a company using only their domain name. By combining DNS TXT record analysis, SSO fingerprinting, and workspace slug detection, it gives security researchers and red teamers a fast, comprehensive view of a target's SaaS footprint — a goldmine for finding misconfigurations and exposed workspaces.

---

## Features

- **DNS TXT Record Analysis** — Parses domain TXT records to identify service verification tokens and ownership signatures
- **SSO Fingerprinting** — Detects which SaaS platforms have SSO configured for the target domain
- **Workspace Slug / ACME Detection** — Identifies target-specific workspaces on platforms that expose tenant slugs (e.g. `target.slack.com`, `target.atlassian.net`)
- **Single & Bulk Service Checks** — Test one service at a time or feed a config list for full-spectrum enumeration
- **Proxy Support** — Route all requests through a proxy for anonymity or traffic inspection
- **Verbose Mode** — See exactly how each service was detected (Slug Only / Via SSO)
- **Output to File** — Save results directly to a plain-text file
- **Written in Go** — Fast, lightweight, and easy to compile on any platform

---

## Why saase?

Most recon tools focus on subdomains, ports, or technologies. `saase` fills a gap that has been largely ignored: **SaaS-based attack surface**. A company's Slack, Notion, Jira, or GitHub workspace can expose sensitive data, allow unauthorized access, or reveal organizational structure — often with zero traditional vulnerability involved. `saase` is the **first tool specialized for this purpose**.

---

## Installation

**Requirements:** Go 1.18+

```bash
git clone https://github.com/codejavu-llc/saase.git
cd saase
go mod init
go mod tidy
go build -o saase
```

---

## Usage

```
./saase -h

Usage of ./saase:
  -c string
        config file with one service name per line
  -d string
        target domain to fingerprint
  -o string
        write a plain-text copy of the output to this file
  -s string
        single service name to check
  -v    verbose: show detection method (Slug Only / Via SSO) and errors
  -x string
        proxy to route requests through
```

### Flags

| Flag | Type | Description |
|------|------|-------------|
| `-d` | string | **Required.** Target domain to enumerate (e.g. `example.com`) |
| `-s` | string | Check a single service by name |
| `-c` | string | Path to a config file with one service name per line |
| `-o` | string | Save output to a plain-text file |
| `-v` | bool | Verbose mode — shows detection method and errors |
| `-x` | string | Proxy URL to route all requests through |

---

## Examples

**Enumerate all detectable services for a domain:**
```bash
./saase -d example.com
```

**Check a single service:**
```bash
./saase -d example.com -s slack
```

**Run against a list of services and save the results:**
```bash
./saase -d example.com -c services.txt -o results.txt
```

**Verbose output with proxy:**
```bash
./saase -d example.com -v -x http://127.0.0.1:8080
```

**Full enumeration with verbose output and file save:**
```bash
./saase -d example.com -c services.txt -v -o recon_output.txt
```

### Example Config File (`services.txt`)

```
slack
notion
jira
github
gitlab
salesforce
zendesk
hubspot
figma
```

---

## Detection Methods

`saase` uses multiple techniques to confirm whether a service is in use:

| Method | Description |
|--------|-------------|
| **Via SSO** | The target domain is registered as an SSO identity provider or verified login domain on the service |
| **Slug Only** | A workspace matching the target's domain or brand name exists on the platform (e.g. `target.atlassian.net`) |

Use the `-v` flag to see which method was used for each detected service.

---

## Use Cases

- **Red Team Recon** — Map a target's SaaS footprint before an engagement
- **Bug Bounty Hunting** — Discover exposed workspaces and SaaS misconfigurations
- **Attack Surface Management** — Audit your own organization's SaaS exposure
- **Third-Party Risk** — Identify shadow IT and unsanctioned SaaS usage

---

## Disclaimer

`saase` is intended for **authorized security testing and research only**. Use of this tool against systems you do not own or have explicit written permission to test may be illegal. The authors are not responsible for any misuse or damage caused by this tool.

---

## Author

Built by [CodeJavu LLC](https://github.com/codejavu-llc)

