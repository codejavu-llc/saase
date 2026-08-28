package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/engine"
	"github.com/codejavu-llc/saase/v2/internal/output"
	"github.com/codejavu-llc/saase/v2/internal/store"
	"github.com/codejavu-llc/saase/v2/internal/target"
	builtinrules "github.com/codejavu-llc/saase/v2/rules"
)

const Version = "2.0.0"

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "scan", "providers", "rules", "diff", "version", "help":
			command, args = args[0], args[1:]
		}
	}
	var err error
	switch command {
	case "scan":
		err = runScan(ctx, args, stdin, stdout, stderr)
	case "providers":
		err = runProviders(args, stdout, stderr)
	case "rules":
		err = runRules(args, stdout, stderr)
	case "diff":
		err = runDiff(ctx, args, stdout, stderr)
	case "version":
		_, err = fmt.Fprintf(stdout, "%s // %s\n%s\n", consolePaint(stdout, "1;38;5;46", "SAASE"), Version,
			consolePaint(stdout, "38;5;244", "schema 2.0 · catalog "+catalog.CatalogVersion+" · passive-first"))
	case "help":
		writeRootUsage(stdout)
	default:
		err = fmt.Errorf("unknown command %q", command)
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "%s %v\n", consolePaint(stderr, "1;38;5;196", "[ SAASE // ERROR ]"), err)
	var coded exitError
	if errors.As(err, &coded) {
		return coded.code
	}
	return 1
}

type scanOptions struct {
	domains, domainFiles, providers, providerFiles, slugs                 stringList
	organization, outputFile, format, profile, proxy, rulesDir, storePath string
	active, verbose, silent, noColor, insecure, sensitive, forceStdin     bool
	noCache                                                               bool
	timeout, cacheTTL                                                     time.Duration
	retries, concurrency                                                  int
	rateLimit                                                             float64
}

func runScan(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	options := scanOptions{}
	defaults := engine.DefaultConfig()
	set := flag.NewFlagSet("saase scan", flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Var(&options.domains, "d", "target domain (repeatable or comma-separated)")
	set.Var(&options.domains, "domain", "target domain (repeatable or comma-separated)")
	set.Var(&options.domainFiles, "l", "file containing target domains")
	set.Var(&options.domainFiles, "list", "file containing target domains")
	set.Var(&options.providers, "s", "provider name or ID (repeatable or comma-separated)")
	set.Var(&options.providers, "provider", "provider name or ID (repeatable or comma-separated)")
	set.Var(&options.providerFiles, "c", "deprecated: file containing provider names")
	set.Var(&options.providerFiles, "providers-file", "file containing provider names")
	set.Var(&options.slugs, "slug", "explicit tenant slug candidate")
	set.StringVar(&options.organization, "org", "", "organization name override")
	set.StringVar(&options.outputFile, "o", "", "mirror findings to a file")
	set.StringVar(&options.format, "format", "text", "output format: text, json, jsonl, csv")
	set.StringVar(&options.profile, "profile", defaults.Profile, "scan profile: passive, standard, deep")
	set.StringVar(&options.proxy, "x", "", "HTTP or SOCKS proxy URL")
	set.StringVar(&options.proxy, "proxy", "", "HTTP or SOCKS proxy URL")
	set.StringVar(&options.rulesDir, "rules-dir", "", "external provider rule directory")
	set.StringVar(&options.storePath, "store", "", "SQLite database for scan history")
	set.BoolVar(&options.active, "active", false, "enable bounded HTTP tenant probes")
	set.BoolVar(&options.verbose, "v", false, "show evidence and probe errors")
	set.BoolVar(&options.verbose, "verbose", false, "show evidence and probe errors")
	set.BoolVar(&options.silent, "silent", false, "print pipe-friendly findings only")
	set.BoolVar(&options.noColor, "no-color", false, "disable ANSI color")
	set.BoolVar(&options.insecure, "insecure", false, "disable TLS verification (recorded in metadata)")
	set.BoolVar(&options.sensitive, "show-sensitive-evidence", false, "do not redact verification tokens")
	set.BoolVar(&options.forceStdin, "stdin", false, "read target domains from stdin")
	set.BoolVar(&options.noCache, "no-cache", false, "ignore and do not update stored evidence cache")
	set.DurationVar(&options.timeout, "timeout", defaults.Timeout, "per-request timeout")
	set.DurationVar(&options.cacheTTL, "cache-ttl", defaults.CacheTTL, "stored evidence cache lifetime")
	set.IntVar(&options.retries, "retries", defaults.Retries, "transient request retries")
	set.IntVar(&options.concurrency, "concurrency", defaults.Concurrency, "maximum concurrent operations")
	set.Float64Var(&options.rateLimit, "rate-limit", defaults.RateLimit, "requests per second per provider")
	set.Usage = func() { writeScanUsage(set.Output()) }
	if err := set.Parse(args); err != nil {
		return err
	}
	options.domains = append(options.domains, set.Args()...)
	if len(options.providerFiles) > 0 && hasShortConfig(args) {
		_, _ = fmt.Fprintln(stderr, "warning: -c is deprecated; use --providers-file")
	}
	for _, path := range options.domainFiles {
		values, err := readLinesFile(path)
		if err != nil {
			return fmt.Errorf("read target file %q: %w", path, err)
		}
		options.domains = append(options.domains, values...)
	}
	for _, path := range options.providerFiles {
		values, err := readLinesFile(path)
		if err != nil {
			return fmt.Errorf("read provider file %q: %w", path, err)
		}
		options.providers = append(options.providers, values...)
	}
	if options.forceStdin || (len(options.domains) == 0 && !readerIsTerminal(stdin)) {
		values, err := readLines(stdin)
		if err != nil {
			return fmt.Errorf("read targets from stdin: %w", err)
		}
		options.domains = append(options.domains, values...)
	}
	if len(options.domains) == 0 {
		return fmt.Errorf("no target specified; use -d, -l, or --stdin")
	}
	if options.organization != "" && len(options.domains) != 1 {
		return fmt.Errorf("--org can only be used with one target")
	}

	providerCatalog, err := loadCatalog(options.rulesDir)
	if err != nil {
		return err
	}
	if _, err := providerCatalog.ResolveSelectors(options.providers); err != nil {
		return err
	}
	normalized := make([]target.Target, 0, len(options.domains))
	seen := make(map[string]bool)
	for _, raw := range options.domains {
		item, err := target.Normalize(raw, target.Overrides{Organization: options.organization, Slugs: options.slugs})
		if err != nil {
			return err
		}
		if !seen[item.Apex] {
			normalized, seen[item.Apex] = append(normalized, item), true
		}
	}
	cfg := defaults
	cfg.Profile, cfg.Active, cfg.Concurrency, cfg.RateLimit = options.profile, options.active, options.concurrency, options.rateLimit
	cfg.Timeout, cfg.Retries, cfg.Proxy, cfg.InsecureTLS = options.timeout, options.retries, options.proxy, options.insecure
	cfg.ShowSensitiveEvidence = options.sensitive
	cfg.CacheTTL, cfg.DisableCache = options.cacheTTL, options.noCache
	scanner, err := engine.New(cfg, providerCatalog)
	if err != nil {
		return err
	}
	var database *store.Store
	if options.storePath != "" {
		database, err = store.Open(options.storePath)
		if err != nil {
			return fmt.Errorf("open scan store: %w", err)
		}
		defer database.Close()
		scanner.SetCache(database)
	}
	color := !options.noColor && strings.EqualFold(options.format, "text") && writerIsTerminal(stdout)
	renderOptions := output.Options{Format: options.format, Verbose: options.verbose, Silent: options.silent, Color: color}
	var live *output.LiveWriter
	if options.format == "" || strings.EqualFold(options.format, "text") {
		live = output.NewLiveWriter(stdout, renderOptions)
		scanner.SetEventHandler(live.Handle)
	}
	report, scanErr := scanner.Scan(ctx, normalized, options.providers)
	if live != nil {
		if err := live.Finish(report); err != nil {
			return err
		}
	}
	if scanErr != nil && len(report.Findings) == 0 {
		return scanErr
	}

	var file *os.File
	if options.outputFile != "" {
		file, err = os.Create(options.outputFile)
		if err != nil {
			return fmt.Errorf("create output %q: %w", options.outputFile, err)
		}
		defer file.Close()
	}
	if live == nil {
		if err := output.Write(stdout, report, renderOptions); err != nil {
			return err
		}
	}
	if file != nil {
		renderOptions.Color = false
		if err := output.Write(file, report, renderOptions); err != nil {
			return err
		}
	}
	if options.verbose {
		for _, probeError := range report.Errors {
			_, _ = fmt.Fprintf(stderr, "[!] %s %s: %s\n", probeError.Detector, probeError.Subject, probeError.Message)
		}
	}
	if database != nil {
		if err := database.Save(ctx, report); err != nil {
			return err
		}
		if !options.silent {
			_, _ = fmt.Fprintf(stderr, "%s session %s → %s\n", consolePaint(stderr, "1;38;5;45", "[ SAASE // STORE ]"), report.Metadata.ScanID, options.storePath)
		}
	}
	if scanErr == nil && len(report.Findings) == 0 && len(report.Errors) >= len(normalized)*3 {
		return exitError{code: 2, err: fmt.Errorf("scan completed but all primary discovery probes failed")}
	}
	return scanErr
}

func runProviders(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "list" {
		args = args[1:]
	}
	set := flag.NewFlagSet("saase providers list", flag.ContinueOnError)
	set.SetOutput(stderr)
	format, rulesDir := "text", ""
	set.StringVar(&format, "format", format, "output format: text or json")
	set.StringVar(&rulesDir, "rules-dir", "", "external provider rule directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("unexpected providers argument %q", set.Arg(0))
	}
	providerCatalog, err := loadCatalog(rulesDir)
	if err != nil {
		return err
	}
	providers := providerCatalog.Providers()
	active := make(map[string]bool)
	for _, id := range engine.ActiveProviderIDs() {
		active[id] = true
	}
	if format == "json" {
		type providerView struct {
			catalog.Provider
			Active bool `json:"active"`
		}
		views := make([]providerView, 0, len(providers))
		for _, provider := range providers {
			views = append(views, providerView{Provider: provider, Active: active[provider.ID]})
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(views)
	}
	if format != "text" {
		return fmt.Errorf("unsupported provider-list format %q", format)
	}
	var buffer strings.Builder
	fmt.Fprintln(&buffer, "╭─[ SAASE // PROVIDER MATRIX ]")
	fmt.Fprintln(&buffer, "│  ID                               CATEGORY               MODE            PROVIDER")
	fmt.Fprintln(&buffer, "│  ───────────────────────────────  ─────────────────────  ──────────────  ────────────────────")
	for _, provider := range providers {
		mode := "PASSIVE"
		if active[provider.ID] {
			mode = "PASSIVE+ACTIVE"
		}
		fmt.Fprintf(&buffer, "│  %-32s %-22s %-15s %s\n", provider.ID, strings.ToUpper(provider.Category), mode, provider.Name)
	}
	fmt.Fprintf(&buffer, "╰─[ %d PROVIDERS · %d ACTIVE PROBES ]\n", len(providers), len(active))
	_, err = io.WriteString(stdout, buffer.String())
	return err
}

func runRules(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "validate" {
		args = args[1:]
	}
	set := flag.NewFlagSet("saase rules validate", flag.ContinueOnError)
	set.SetOutput(stderr)
	rulesDir := ""
	set.StringVar(&rulesDir, "rules-dir", "", "external provider rule directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("unexpected rules argument %q", set.Arg(0))
	}
	providerCatalog, err := loadCatalog(rulesDir)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s RULE MATRIX VALID // %d providers · %d TXT · %d DNS · %d active · catalog %s\n",
		consolePaint(stdout, "1;38;5;46", "[✓]"), len(providerCatalog.Providers()), len(providerCatalog.TXT), len(providerCatalog.DNS), len(engine.ActiveProviderIDs()), catalog.CatalogVersion)
	return err
}

func runDiff(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("saase diff", flag.ContinueOnError)
	set.SetOutput(stderr)
	databasePath, from, to, format := "saase.db", "", "", "text"
	list := false
	set.StringVar(&databasePath, "db", databasePath, "SQLite scan database")
	set.StringVar(&from, "from", "", "baseline scan ID")
	set.StringVar(&to, "to", "", "comparison scan ID")
	set.StringVar(&format, "format", format, "output format: text, json, jsonl")
	set.BoolVar(&list, "list", false, "list recent scans")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("unexpected diff argument %q", set.Arg(0))
	}
	database, err := store.Open(databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	scans, err := database.Recent(ctx, 50)
	if err != nil {
		return err
	}
	if list {
		return output.WriteScanList(stdout, scans, format)
	}
	if to == "" && len(scans) > 0 {
		to = scans[0].ID
	}
	if from == "" && len(scans) > 1 {
		from = scans[1].ID
	}
	if from == "" || to == "" {
		return fmt.Errorf("two stored scans are required, or specify --from and --to")
	}
	before, err := database.Load(ctx, from)
	if err != nil {
		return fmt.Errorf("load baseline scan %q: %w", from, err)
	}
	after, err := database.Load(ctx, to)
	if err != nil {
		return fmt.Errorf("load comparison scan %q: %w", to, err)
	}
	return output.WriteChanges(stdout, store.Diff(before, after), format)
}

func loadCatalog(directory string) (*catalog.Catalog, error) {
	var source fs.FS = builtinrules.FS
	if directory != "" {
		source = os.DirFS(directory)
	}
	providerCatalog, err := catalog.Load(source)
	if err != nil {
		return nil, fmt.Errorf("invalid provider catalog: %w", err)
	}
	return providerCatalog, nil
}

func readLinesFile(path string) ([]string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLines(file)
}
func readLines(reader io.Reader) ([]string, error) {
	var values []string
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			values = append(values, line)
		}
	}
	return values, scanner.Err()
}
func readerIsTerminal(reader io.Reader) bool {
	if file, ok := reader.(*os.File); ok {
		info, err := file.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
	return false
}
func writerIsTerminal(writer io.Writer) bool {
	if file, ok := writer.(*os.File); ok {
		info, err := file.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
	return false
}

func consolePaint(writer io.Writer, code, value string) string {
	if !writerIsTerminal(writer) {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}
func hasShortConfig(args []string) bool {
	for _, arg := range args {
		if arg == "-c" || strings.HasPrefix(arg, "-c=") {
			return true
		}
	}
	return false
}

func writeRootUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `╭─[ SAASE // EXPOSURE INTELLIGENCE ]
╰─ passive-first SaaS reconnaissance for authorized targets

Usage:
  saase scan [options] [domain ...]
  saase providers list [--format text|json]
  saase rules validate [--rules-dir DIR]
  saase diff [--db saase.db] [--from ID --to ID]
  saase version

Legacy scan flags (-d, -s, -c, -o, -v, -x) continue to work without the "scan" command.`)
}
func writeScanUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: saase scan -d example.com [--active] [--format text|json|jsonl|csv]")
}
