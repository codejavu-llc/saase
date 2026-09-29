package target

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name, input, host, apex, slug string
	}{
		{"apex", "Example.COM.", "example.com", "example.com", "example"},
		{"subdomain", "subdomains.domain.com", "subdomains.domain.com", "domain.com", "domain"},
		{"nested subdomain", "One.Two.Example.COM.", "one.two.example.com", "example.com", "example"},
		{"subdomain and public suffix", "https://www.acme.co.uk:443/path", "www.acme.co.uk", "acme.co.uk", "acme"},
		{"absolute URL hostname", "https://Sub.Example.com.:443/path", "sub.example.com", "example.com", "example"},
		{"idn", "bücher.de", "xn--bcher-kva.de", "xn--bcher-kva.de", "xn-bcher-kva"},
		{"idn subdomain", "shop.bücher.de", "shop.xn--bcher-kva.de", "xn--bcher-kva.de", "xn-bcher-kva"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Normalize(test.input, Overrides{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Apex != test.apex {
				t.Fatalf("apex = %q, want %q", got.Apex, test.apex)
			}
			if got.Host != test.host {
				t.Fatalf("host = %q, want %q", got.Host, test.host)
			}
			found := false
			for _, slug := range got.SlugCandidates {
				if slug == test.slug {
					found = true
				}
			}
			if !found {
				t.Fatalf("slug candidates %v do not contain %q", got.SlugCandidates, test.slug)
			}
		})
	}
}

func TestNormalizeOverridesAndErrors(t *testing.T) {
	got, err := Normalize("app.example.com", Overrides{Organization: "Example Corporation", Slugs: []string{"custom_tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Organization != "Example Corporation" {
		t.Fatalf("organization = %q", got.Organization)
	}
	if len(got.SlugCandidates) == 0 || got.SlugCandidates[0] != "custom-tenant" {
		t.Fatalf("unexpected slugs: %v", got.SlugCandidates)
	}
	found := false
	for _, slug := range got.SlugCandidates {
		if slug == "custom-tenant" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom slug missing: %v", got.SlugCandidates)
	}

	for _, input := range []string{"", "localhost", "127.0.0.1", "bad_domain.com", "https://", "example.com..", "sub..example.com"} {
		if _, err := Normalize(input, Overrides{}); err == nil {
			t.Errorf("Normalize(%q) unexpectedly succeeded", input)
		}
	}
}

func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{"example.com", "https://sub.example.co.uk/path", "bücher.de", "bad_domain", "127.0.0.1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) { _, _ = Normalize(input, Overrides{}) })
}

func TestNormalizeSlugs(t *testing.T) {
	targets, err := NormalizeSlugs([]string{" ACME ", "acme", "team-42", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %#v", targets)
	}
	for i, want := range []string{"acme", "team-42", "x"} {
		got := targets[i]
		if !got.IsSlugOnly() || got.Name() != want || got.Host != "" || got.Apex != "" {
			t.Fatalf("slug target = %#v, want %s without a domain", got, want)
		}
		if len(got.SlugCandidates) != 1 || got.SlugCandidates[0] != want {
			t.Fatalf("unexpected candidates: %v", got.SlugCandidates)
		}
	}
	for _, input := range []string{"", " ", "-acme", "acme-", "a.b", "acme/corp", "https://acme.com", "acme?x=y", "a_b", "bücher", strings.Repeat("a", 64)} {
		if _, err := NormalizeSlugs([]string{input}); err == nil {
			t.Errorf("invalid slug %q accepted", input)
		}
	}
	if _, err := NormalizeSlugs([]string{strings.Repeat("a", 63)}); err != nil {
		t.Fatal(err)
	}
}
