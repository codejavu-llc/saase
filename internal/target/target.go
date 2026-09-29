package target

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Target struct {
	Input          string   `json:"input"`
	Host           string   `json:"host"`
	Apex           string   `json:"apex"`
	Slug           string   `json:"slug,omitempty"`
	Organization   string   `json:"organization"`
	SlugCandidates []string `json:"slug_candidates"`
}

type Overrides struct {
	Organization string
	Slugs        []string
}

// Name identifies a target in reports, whether it is a hostname or a slug.
func (t Target) Name() string {
	if t.Slug != "" {
		return t.Slug
	}
	return t.Host
}

func (t Target) IsSlugOnly() bool { return t.Slug != "" }

// NormalizeSlugs creates one target per unique tenant slug, without inventing
// a domain or deriving additional candidates. Slugs must fit a DNS label since
// tenant probes commonly interpolate them into provider hostnames.
func NormalizeSlugs(raw []string) ([]Target, error) {
	var targets []Target
	seen := make(map[string]bool)
	for _, input := range raw {
		slug := strings.ToLower(strings.TrimSpace(input))
		if !validSlug(slug) {
			return nil, fmt.Errorf("invalid tenant slug %q: use 1-63 ASCII letters, digits, or internal hyphens", input)
		}
		if !seen[slug] {
			targets = append(targets, Target{Input: input, Slug: slug, Organization: slug, SlugCandidates: []string{slug}})
			seen[slug] = true
		}
	}
	return targets, nil
}

func validSlug(slug string) bool {
	if len(slug) == 0 || len(slug) > 63 || slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}
	for _, ch := range slug {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func Normalize(raw string, overrides Overrides) (Target, error) {
	original := strings.TrimSpace(raw)
	if original == "" {
		return Target{}, fmt.Errorf("target is empty")
	}

	host := original
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || u.Hostname() == "" {
			return Target{}, fmt.Errorf("invalid target %q", original)
		}
		host = u.Hostname()
	} else {
		host = strings.Split(strings.Split(host, "/")[0], ":")[0]
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if net.ParseIP(host) != nil {
		return Target{}, fmt.Errorf("target %q is an IP address; a domain is required", original)
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return Target{}, fmt.Errorf("invalid internationalized domain %q: %w", original, err)
	}
	if !validHostname(ascii) {
		return Target{}, fmt.Errorf("invalid domain %q", original)
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return Target{}, fmt.Errorf("domain %q has no registrable suffix", original)
	}
	label := strings.Split(apex, ".")[0]
	org := strings.TrimSpace(overrides.Organization)
	if org == "" {
		org = label
	}
	slugs := make([]string, 0, len(overrides.Slugs)+4)
	for _, candidate := range append(overrides.Slugs, org, label, strings.ReplaceAll(label, "-", ""), strings.ReplaceAll(label, "_", "")) {
		candidate = slugify(candidate)
		if candidate != "" && !contains(slugs, candidate) {
			slugs = append(slugs, candidate)
		}
	}
	return Target{Input: original, Host: ascii, Apex: apex, Organization: org, SlugCandidates: slugs}, nil
}

func validHostname(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return false
			}
		}
	}
	return true
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
