# Competitive analysis

The v2 design focuses on the gap between specialist SaaS enumeration and mature bug-bounty pipeline tooling.

| Capability | saase v2 | mubix/saas-enum | saas-reconn | General recon frameworks |
|---|---|---|---|---|
| Domain verification fingerprints | TXT/SPF catalog | TXT/SPF catalog | Limited | Usually indirect |
| SaaS infrastructure | CNAME/MX/NS/SRV + CT enrichment | CNAME/MX/NS + zone walk | CT, passive sources, zone walking | Broad DNS/subdomain discovery |
| Tenant and SSO checks | Explicit opt-in, bounded active probes | Primarily DNS | Active content validation | Module-dependent |
| Evidence/confidence | Typed evidence and deterministic confidence | Records and provider context | Confidence scoring | Event/finding dependent |
| Pipeline output | Text, JSON, JSONL, CSV, stdin | Text, JSON, HTML | HTML/report workflow | Usually strong |
| History/diff | Local SQLite cache/history/diff | No local history | Caching and reports | Framework-dependent |
| Safety default | Passive-first; TLS verified | Passive-first | Command-dependent | Profile-dependent |

Key references:

- [mubix/saas-enum](https://github.com/mubix/saas-enum): contributor-friendly DNS rule catalog and reporting.
- [vanjo9800/saas-reconn](https://github.com/vanjo9800/saas-reconn): CT sources, zone walking, caching, active validation, and confidence.
- [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder): fast, focused, stdin/stdout-friendly CLI behavior.
- [BBOT events and findings](https://www.blacklanternsecurity.com/bbot/Stable/scanning/events/): evidence provenance, severity, confidence, and modular output.
- [OWASP subdomain takeover testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover): enumeration, fingerprinting, and manual validation as separate stages.

The deliberate product boundary is SaaS exposure intelligence—not generic subdomain enumeration, port scanning, credential testing, or automated exploitation. This lets `saase` integrate into existing recon stacks while specializing in provider attribution and tenant evidence.
