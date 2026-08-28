package rules

import "embed"

// FS contains the built-in, versioned provider fingerprint catalog.
//
//go:embed providers.yml dns.yml metadata.yml
var FS embed.FS
