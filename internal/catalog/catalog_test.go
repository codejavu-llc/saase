package catalog

import (
	"strings"
	"testing"
	"testing/fstest"

	builtin "github.com/codejavu-llc/saase/v2/rules"
)

func TestCatalogFingerprintChangesWithRuleContent(t *testing.T) {
	load := func(pattern string) *Catalog {
		t.Helper()
		providerRules := "- name: Example\n  category: Testing\n  match_type: substring\n  pattern: " + pattern + "\n"
		catalog, err := Load(fstest.MapFS{
			"providers.yml": &fstest.MapFile{Data: []byte(providerRules)},
			"dns.yml":       &fstest.MapFile{Data: []byte("[]\n")},
		})
		if err != nil {
			t.Fatal(err)
		}
		return catalog
	}
	first, second := load("alpha"), load("beta")
	if first.Fingerprint() == "" || first.Fingerprint() == second.Fingerprint() {
		t.Fatalf("catalog fingerprints were not content-sensitive: %q and %q", first.Fingerprint(), second.Fingerprint())
	}
}

func TestBuiltInCatalog(t *testing.T) {
	c, err := Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TXT) != 196 {
		t.Fatalf("TXT rules = %d, want 196", len(c.TXT))
	}
	if len(c.DNS) != 73 {
		t.Fatalf("DNS rules = %d, want 73", len(c.DNS))
	}
	if len(c.Providers()) != 266 {
		t.Fatalf("providers = %d, want 266", len(c.Providers()))
	}
	provider, ok := c.Provider("Monday.com")
	if !ok || provider.ID != "monday-com" {
		t.Fatalf("provider resolution failed: %#v %v", provider, ok)
	}
	if _, err := c.ResolveSelectors([]string{"definitely-not-real"}); err == nil {
		t.Fatal("unknown selector was accepted")
	}
}

func TestNewProviderRulesRejectSuffixLookalikes(t *testing.T) {
	c, err := Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"WorkOS":        "tenant.cname.workos-dns.com",
		"Help Scout":    "company.helpscoutdocs.com",
		"GitBook":       "company.gitbook.io",
		"ReadMe":        "tenant.readmessl.com",
		"Read the Docs": "readthedocs.io",
		"Render":        "service.onrender.com",
		"Railway":       "g05ns7.up.railway.app",
		"Fly.io":        "application.fly.dev",
		"Supabase":      "project.supabase.co",
		"Mailgun":       "pdk1._domainkey.tenant.dkim1.mailgun.com",
		"Postmark":      "pm.mtasv.net",
		"Better Stack":  "statuspage.betteruptime.com",
	}
	for providerName, target := range expected {
		matched := false
		for _, rule := range c.DNS {
			if rule.Name != providerName {
				continue
			}
			if rule.Reference == "" {
				t.Errorf("%s has no official reference", providerName)
			}
			for _, suffix := range rule.CNAMETargets {
				if DNSNameMatches(target, suffix) {
					matched = true
				}
				for _, lookalike := range []string{"not" + suffix, suffix + ".evil.test"} {
					if DNSNameMatches(lookalike, suffix) {
						t.Errorf("%s unsafe suffix %q matched %q", providerName, suffix, lookalike)
					}
				}
			}
		}
		if !matched {
			t.Errorf("%s documented target %q did not match", providerName, target)
		}
	}
}

func TestInvalidCatalogs(t *testing.T) {
	tests := []struct{ name, providers, dns, contains string }{
		{"unknown matcher", "- name: Test\n  category: test\n  match_type: mystery\n  pattern: value\n", "[]\n", "unknown matcher"},
		{"invalid regex", "- name: Test\n  category: test\n  match_type: regex\n  pattern: '[unterminated'\n", "[]\n", "invalid regex"},
		{"invalid reference", "- name: Test\n  category: test\n  match_type: prefix\n  pattern: test=\n  reference: not-a-url\n", "[]\n", "invalid reference"},
		{"invalid DNS", "[]\n", "- name: Test\n  category: test\n  cname_targets: ['bad]target.com']\n", "invalid target"},
		{"invalid DNS reference", "[]\n", "- name: Test\n  category: test\n  reference: not-a-url\n  cname_targets: [example.com]\n", "invalid reference"},
		{"missing DNS targets", "[]\n", "- name: Test\n  category: test\n", "no targets"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := fstest.MapFS{"providers.yml": {Data: []byte(test.providers)}, "dns.yml": {Data: []byte(test.dns)}}
			_, err := Load(files)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestSPFIncludeRequiresExactMechanismDomain(t *testing.T) {
	rule := TXTRule{MatchType: "spf_include", Pattern: "mailgun.org"}
	for _, record := range []string{
		"v=spf1 include:mailgun.org ~all",
		"V=SPF1 -include:mailgun.org. include:_spf.example.com ~all",
	} {
		if !rule.Match(record) {
			t.Errorf("valid SPF include did not match: %q", record)
		}
	}
	for _, record := range []string{
		"mailgun.org",
		"v=spf1 include:notmailgun.org ~all",
		"v=spf1 include:mailgun.org.evil.test ~all",
		"v=spf1 exists:mailgun.org ~all",
	} {
		if rule.Match(record) {
			t.Errorf("unsafe SPF look-alike matched: %q", record)
		}
	}
}

func TestTXTRulesAndDNSSuffixBoundary(t *testing.T) {
	c, err := Load(builtin.FS)
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, rule := range c.TXT {
		if rule.Name == "Slack" && rule.Match("slack-domain-verification=secret") {
			matched = true
		}
	}
	if !matched {
		t.Fatal("Slack TXT rule did not match")
	}
	if !DNSNameMatches("tenant.okta.com.", "okta.com") {
		t.Fatal("valid DNS suffix did not match")
	}
	if DNSNameMatches("tenant.evilokta.com", "okta.com") {
		t.Fatal("unsafe partial DNS suffix matched")
	}
}
