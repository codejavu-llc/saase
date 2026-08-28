package target

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name, input, apex, slug string
	}{
		{"apex", "Example.COM.", "example.com", "example"},
		{"subdomain and public suffix", "https://www.acme.co.uk:443/path", "acme.co.uk", "acme"},
		{"idn", "bücher.de", "xn--bcher-kva.de", "xn-bcher-kva"},
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

	for _, input := range []string{"", "localhost", "127.0.0.1", "bad_domain.com", "https://"} {
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
