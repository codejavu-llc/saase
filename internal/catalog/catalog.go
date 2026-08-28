package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const CatalogVersion = "2026.08"

type TXTRule struct {
	Name        string `yaml:"name"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Website     string `yaml:"website"`
	MatchType   string `yaml:"match_type"`
	Pattern     string `yaml:"pattern"`
	Reference   string `yaml:"reference"`
	Impact      string `yaml:"impact"`
	regex       *regexp.Regexp
}

type DNSRule struct {
	Name              string   `yaml:"name"`
	Category          string   `yaml:"category"`
	Description       string   `yaml:"description"`
	Website           string   `yaml:"website"`
	Reference         string   `yaml:"reference"`
	Impact            string   `yaml:"impact"`
	CNAMETargets      []string `yaml:"cname_targets"`
	SubdomainsToCheck []string `yaml:"subdomains_to_check"`
	MXTargets         []string `yaml:"mx_targets"`
	NSTargets         []string `yaml:"ns_targets"`
	IPRanges          []string `yaml:"ip_ranges"`
}

type Provider struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Category    string `json:"category" yaml:"category"`
	Description string `json:"description" yaml:"description"`
	Website     string `json:"website" yaml:"website"`
	Impact      string `json:"impact" yaml:"impact"`
}

type Catalog struct {
	TXT         []TXTRule
	DNS         []DNSRule
	providers   map[string]Provider
	aliases     map[string]string
	fingerprint string
}

func Load(source fs.FS) (*Catalog, error) {
	c := &Catalog{providers: make(map[string]Provider), aliases: make(map[string]string)}
	if err := decode(source, "providers.yml", &c.TXT); err != nil {
		return nil, err
	}
	if err := decode(source, "dns.yml", &c.DNS); err != nil {
		return nil, err
	}
	var metadata []Provider
	if err := decode(source, "metadata.yml", &metadata); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, provider := range metadata {
		if provider.ID == "" {
			provider.ID = ProviderID(provider.Name)
		}
		c.providers[provider.ID] = provider
		c.aliases[normalizeSelector(provider.ID)] = provider.ID
		c.aliases[normalizeSelector(provider.Name)] = provider.ID
	}
	if err := c.prepare(); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(struct {
		TXT       []TXTRule
		DNS       []DNSRule
		Providers []Provider
	}{TXT: c.TXT, DNS: c.DNS, Providers: c.Providers()})
	if err != nil {
		return nil, fmt.Errorf("fingerprint rule catalog: %w", err)
	}
	sum := sha256.Sum256(canonical)
	c.fingerprint = hex.EncodeToString(sum[:])
	return c, nil
}

func decode(source fs.FS, name string, dest any) error {
	data, err := fs.ReadFile(source, name)
	if err != nil {
		return fmt.Errorf("read rule catalog %s: %w", name, err)
	}
	if err := yaml.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse rule catalog %s: %w", name, err)
	}
	return nil
}

func (c *Catalog) prepare() error {
	var errs []error
	for i := range c.TXT {
		rule := &c.TXT[i]
		if rule.Name == "" || rule.Category == "" || rule.Pattern == "" {
			errs = append(errs, fmt.Errorf("TXT rule %d is missing name, category, or pattern", i+1))
			continue
		}
		if rule.Reference != "" && !validHTTPURL(rule.Reference) {
			errs = append(errs, fmt.Errorf("TXT rule %q has invalid reference URL %q", rule.Name, rule.Reference))
		}
		switch rule.MatchType {
		case "prefix", "substring", "spf_include":
		case "regex":
			rx, err := regexp.Compile("(?i)" + rule.Pattern)
			if err != nil {
				errs = append(errs, fmt.Errorf("TXT rule %q has invalid regex: %w", rule.Name, err))
			} else {
				rule.regex = rx
			}
		default:
			errs = append(errs, fmt.Errorf("TXT rule %q uses unknown matcher %q", rule.Name, rule.MatchType))
		}
		c.addProvider(rule.Name, rule.Category, rule.Description, rule.Website, rule.Impact)
	}
	for i := range c.DNS {
		rule := &c.DNS[i]
		if rule.Name == "" || rule.Category == "" {
			errs = append(errs, fmt.Errorf("DNS rule %d is missing name or category", i+1))
			continue
		}
		if len(rule.CNAMETargets)+len(rule.MXTargets)+len(rule.NSTargets) == 0 {
			errs = append(errs, fmt.Errorf("DNS rule %q has no targets", rule.Name))
		}
		if rule.Reference != "" && !validHTTPURL(rule.Reference) {
			errs = append(errs, fmt.Errorf("DNS rule %q has invalid reference URL %q", rule.Name, rule.Reference))
		}
		for _, value := range append(append(append([]string{}, rule.CNAMETargets...), rule.MXTargets...), rule.NSTargets...) {
			if !validDNSSuffix(value) {
				errs = append(errs, fmt.Errorf("DNS rule %q has invalid target %q", rule.Name, value))
			}
		}
		for _, value := range rule.IPRanges {
			if _, _, err := net.ParseCIDR(value); err != nil {
				errs = append(errs, fmt.Errorf("DNS rule %q has invalid CIDR %q", rule.Name, value))
			}
		}
		c.addProvider(rule.Name, rule.Category, rule.Description, rule.Website, rule.Impact)
	}
	for alias, providerID := range map[string]string{
		"jira": "atlassian", "confluence": "atlassian", "office365": "microsoft-365", "m365": "microsoft-365",
		"google": "google-workspace", "monday": "monday-com", "bambbohr": "bamboohr",
	} {
		if _, exists := c.providers[providerID]; exists {
			c.aliases[normalizeSelector(alias)] = providerID
		}
	}
	for _, provider := range c.providers {
		if provider.ID == "" || provider.Name == "" || provider.Category == "" {
			errs = append(errs, fmt.Errorf("provider metadata is missing id, name, or category: %#v", provider))
		}
		if provider.Website != "" && !validHTTPURL(provider.Website) {
			errs = append(errs, fmt.Errorf("provider %q has invalid website %q", provider.Name, provider.Website))
		}
	}
	return errors.Join(errs...)
}

func validHTTPURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

var dnsSuffixPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*[A-Za-z0-9_]$`)

func validDNSSuffix(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	return len(value) <= 253 && strings.Contains(value, ".") && dnsSuffixPattern.MatchString(value)
}

func (c *Catalog) addProvider(name, category, description, website, impact string) {
	id := ProviderID(name)
	p := c.providers[id]
	if p.ID == "" {
		p = Provider{ID: id, Name: name, Category: category, Description: description, Website: website, Impact: impact}
	} else {
		if p.Description == "" {
			p.Description = description
		}
		if p.Website == "" {
			p.Website = website
		}
		if p.Impact == "" {
			p.Impact = impact
		}
	}
	c.providers[id] = p
	c.aliases[normalizeSelector(name)] = id
	c.aliases[normalizeSelector(id)] = id
}

func ProviderID(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizeSelector(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ProviderID(value), "-", ""), ".", "")
}

func (c *Catalog) Providers() []Provider {
	providers := make([]Provider, 0, len(c.providers))
	for _, provider := range c.providers {
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	return providers
}

// Fingerprint identifies the exact parsed rule content used by a scan.
func (c *Catalog) Fingerprint() string { return c.fingerprint }

func (c *Catalog) Provider(name string) (Provider, bool) {
	id, ok := c.aliases[normalizeSelector(name)]
	if !ok {
		return Provider{}, false
	}
	p, ok := c.providers[id]
	return p, ok
}

func (c *Catalog) ResolveSelectors(selectors []string) (map[string]bool, error) {
	if len(selectors) == 0 {
		return nil, nil
	}
	selected := make(map[string]bool)
	for _, selector := range selectors {
		provider, ok := c.Provider(selector)
		if !ok {
			return nil, fmt.Errorf("unknown provider %q", selector)
		}
		selected[provider.ID] = true
	}
	return selected, nil
}

func (r TXTRule) Match(record string) bool {
	value := strings.ToLower(strings.TrimSpace(record))
	pattern := strings.ToLower(r.Pattern)
	switch r.MatchType {
	case "prefix":
		return strings.HasPrefix(value, pattern)
	case "substring":
		return strings.Contains(value, pattern)
	case "spf_include":
		if !strings.HasPrefix(value, "v=spf1") {
			return false
		}
		pattern = strings.TrimPrefix(pattern, "include:")
		pattern = strings.TrimSuffix(pattern, ".")
		for _, mechanism := range strings.Fields(value) {
			mechanism = strings.TrimLeft(mechanism, "+-~?")
			if !strings.HasPrefix(mechanism, "include:") {
				continue
			}
			domain := strings.TrimSuffix(strings.TrimPrefix(mechanism, "include:"), ".")
			if domain == pattern {
				return true
			}
		}
		return false
	case "regex":
		return r.regex != nil && r.regex.MatchString(record)
	default:
		return false
	}
}

func DNSNameMatches(value, suffix string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	suffix = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), "."), ".")
	return value == suffix || strings.HasSuffix(value, "."+suffix)
}
