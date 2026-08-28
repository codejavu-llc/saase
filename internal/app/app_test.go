package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
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
