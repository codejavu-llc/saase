package app

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

func TestInformationalCommands(t *testing.T) {
	for _, test := range []struct {
		args     []string
		contains string
	}{
		{[]string{"version"}, "SAASE // 2.0.0"},
		{[]string{"rules", "validate"}, "196 TXT"},
		{[]string{"providers", "list"}, "PROVIDER MATRIX"},
		{[]string{"help"}, "SAASE // EXPOSURE INTELLIGENCE"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("%v exit = %d, stderr=%s", test.args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), test.contains) {
			t.Fatalf("%v output %q missing %q", test.args, stdout.String(), test.contains)
		}
	}
}

func TestScanValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"scan", "-d", "example.com", "-s", "not-a-provider"}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown provider") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMoreCommandBranches(t *testing.T) {
	tests := []struct {
		args           []string
		code           int
		stdout, stderr string
	}{
		{[]string{"-h"}, 0, "", "Usage: saase scan"},
		{[]string{"providers", "list", "--format", "json"}, 0, `"id": "slack"`, ""},
		{[]string{"providers", "list", "--format", "xml"}, 1, "", "unsupported"},
		{[]string{"scan"}, 1, "", "no target specified"},
		{[]string{"scan", "-d", "localhost"}, 1, "", "invalid domain"},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr)
		if code != test.code {
			t.Fatalf("%v exit=%d want=%d stderr=%s", test.args, code, test.code, stderr.String())
		}
		if test.stdout != "" && !strings.Contains(stdout.String(), test.stdout) {
			t.Fatalf("%v stdout=%q", test.args, stdout.String())
		}
		if test.stderr != "" && !strings.Contains(stderr.String(), test.stderr) {
			t.Fatalf("%v stderr=%q", test.args, stderr.String())
		}
	}
}

func TestDiffCommands(t *testing.T) {
	database := filepath.Join(t.TempDir(), "history.db")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"diff", "--db", database, "--list"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("list exit=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"diff", "--db", database}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("diff exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "two stored scans") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestScanSubdomainScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	// The started event exposes normalized scope even when scanning is cancelled.
	Run(ctx, []string{"scan", "--no-color", "-d", "example.com,one.example.com,two.example.com,https://ONE.example.com.:443/path"}, strings.NewReader(""), &stdout, &stderr)
	if !strings.Contains(stdout.String(), "example.com, one.example.com, two.example.com") {
		t.Fatalf("subdomains missing from scope: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "TARGETS 3") {
		t.Fatalf("equivalent hostname was not deduplicated: %s", stdout.String())
	}
}

func TestSlugOnlyCLI(t *testing.T) {
	for _, mode := range [][]string{{"--active"}, {"--profile", "standard"}, {"--profile", "deep"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"scan", "--slug", "ACME,beta", "--slug", "acme", "-s", "microsoft-365,google-workspace", "--format", "json"}, mode...)
		// Domain-only providers are skipped. Unrequested stdin must not be read.
		code := Run(context.Background(), args, strings.NewReader("not-a-domain"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%s", args, code, stderr.String())
		}
		var report model.ScanReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Metadata.Targets != 2 || strings.Join(report.Metadata.TargetNames, ",") != "acme,beta" || !report.Metadata.Active {
			t.Fatalf("metadata = %#v", report.Metadata)
		}
		if len(report.Findings) != 0 || len(report.Errors) != 0 {
			t.Fatalf("domain-only providers should be skipped: %#v", report)
		}
	}
}

func TestSlugCLIValidation(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--slug", "acme"}, "require --active"},
		{[]string{"--slug", "example.com", "--active"}, "invalid tenant slug"},
		{[]string{"--slug", "acme", "--active", "-s", "not-a-provider"}, "unknown provider"},
		{[]string{"--slug", "acme", "--active", "--org", "Example"}, "--org can only be used with one target"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), test.want) {
			t.Fatalf("%v exit=%d stderr=%s", test.args, code, stderr.String())
		}
	}
}

func TestDomainWithSlugStillReadsExplicitStdin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	Run(ctx, []string{"scan", "--slug", "acme", "--stdin", "--no-color"}, strings.NewReader("example.com"), &stdout, &stderr)
	if !strings.Contains(stdout.String(), "SCOPE     example.com") || strings.Contains(stderr.String(), "require --active") {
		t.Fatalf("domain plus slug stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
