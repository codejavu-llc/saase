package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codejavu-llc/saase/v2/internal/model"
)

type Options struct {
	Format  string
	Verbose bool
	Silent  bool
	Color   bool
}

type liveFindingState struct {
	confidence model.Confidence
	evidence   map[string]bool
}

// LiveWriter renders accepted findings immediately as the engine discovers
// them. It is safe to call from concurrent scanner workers.
type LiveWriter struct {
	w       io.Writer
	options Options
	mu      sync.Mutex
	started time.Time
	seen    map[string]*liveFindingState
	err     error
	count   int
}

func NewLiveWriter(w io.Writer, options Options) *LiveWriter {
	return &LiveWriter{w: w, options: options, seen: make(map[string]*liveFindingState)}
}

func (l *LiveWriter) Handle(event model.ScanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return
	}
	switch event.Type {
	case model.ScanEventStarted:
		if event.Metadata == nil || l.options.Silent {
			return
		}
		l.started = event.Metadata.StartedAt
		var buffer strings.Builder
		writeScanHeader(&buffer, model.ScanReport{Metadata: *event.Metadata}, l.options.Color)
		fmt.Fprintf(&buffer, "\n%s\n", paint(l.options.Color, "38;5;45", "╭─[ LIVE FINDINGS // STREAMING ]"))
		l.write(buffer.String())
	case model.ScanEventFinding:
		if event.Finding != nil {
			l.finding(*event.Finding)
		}
	}
}

func (l *LiveWriter) finding(finding model.Finding) {
	key := finding.Target + "\x00" + finding.ProviderID
	state, exists := l.seen[key]
	if !exists {
		state = &liveFindingState{confidence: finding.Confidence, evidence: make(map[string]bool)}
		l.seen[key] = state
		l.count++
		if l.options.Silent {
			value := finding.Tenant
			if value == "" {
				value = finding.Provider
			}
			l.write(fmt.Sprintf("%s\t%s\t%s\n", finding.Target, finding.ProviderID, value))
			for _, evidence := range finding.Evidence {
				state.evidence[evidenceKey(evidence, l.options.Verbose)] = true
			}
			return
		}
		l.write(liveFindingBlock(l.started, l.count, finding, l.options))
		for _, evidence := range finding.Evidence {
			state.evidence[evidenceKey(evidence, l.options.Verbose)] = true
		}
		return
	}

	confidenceRaised := finding.Confidence.Rank() > state.confidence.Rank()
	if confidenceRaised {
		state.confidence = finding.Confidence
	}
	for _, evidence := range finding.Evidence {
		evidenceID := evidenceKey(evidence, l.options.Verbose)
		if state.evidence[evidenceID] {
			continue
		}
		state.evidence[evidenceID] = true
		if !l.options.Silent {
			l.write(liveEvidenceUpdate(l.started, finding, evidence, l.options))
		}
	}
	if confidenceRaised && !l.options.Silent {
		badge := strings.ToUpper(string(finding.Confidence))
		if l.options.Color {
			badge = colorConfidence(finding.Confidence, badge)
		}
		l.write(fmt.Sprintf("│     %s confidence upgraded to [%s]\n", paint(l.options.Color, "38;5;244", "↳"), badge))
	}
}

func (l *LiveWriter) Finish(report model.ScanReport) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.options.Silent {
		return l.err
	}
	for _, finding := range report.Findings {
		key := finding.Target + "\x00" + finding.ProviderID
		state := l.seen[key]
		if state == nil {
			l.finding(finding)
			continue
		}
		if finding.Confidence.Rank() > state.confidence.Rank() {
			state.confidence = finding.Confidence
			badge := strings.ToUpper(string(finding.Confidence))
			if l.options.Color {
				badge = colorConfidence(finding.Confidence, badge)
			}
			l.write(fmt.Sprintf("│     %s %s finalized at [%s]\n", paint(l.options.Color, "38;5;244", "↳"), finding.Provider, badge))
		}
	}
	if len(report.Findings) == 0 {
		l.write(fmt.Sprintf("│  %s  NO MATCHED SAAS SIGNALS\n", paint(l.options.Color, "38;5;244", "◇")))
	}
	l.write(fmt.Sprintf("%s\n", paint(l.options.Color, "38;5;45", fmt.Sprintf("╰─[ %d UNIQUE FINDING(S) OBSERVED ]", len(report.Findings)))))
	var summary strings.Builder
	writeScanSummary(&summary, report, l.options.Color)
	l.write(summary.String())
	return l.err
}

func (l *LiveWriter) write(value string) {
	if l.err != nil {
		return
	}
	_, l.err = io.WriteString(l.w, value)
}

func liveFindingBlock(started time.Time, number int, finding model.Finding, options Options) string {
	var buffer strings.Builder
	badge := strings.ToUpper(string(finding.Confidence))
	if options.Color {
		badge = colorConfidence(finding.Confidence, badge)
	}
	fmt.Fprintf(&buffer, "│\n│  %s +%-7s %02d  [%s]  %s %s\n", paint(options.Color, "38;5;45", "◆"),
		liveElapsed(started), number, badge, paint(options.Color, "1;37", finding.Provider), paint(options.Color, "38;5;244", "// "+finding.ProviderID))
	fmt.Fprintf(&buffer, "│     %s %-9s %s\n", paint(options.Color, "38;5;45", "├─"), paint(options.Color, "38;5;244", "TARGET"), finding.Target)
	if finding.Tenant != "" {
		fmt.Fprintf(&buffer, "│     %s %-9s %s\n", paint(options.Color, "38;5;45", "├─"), paint(options.Color, "38;5;244", "TENANT"), finding.Tenant)
	}
	if len(finding.Evidence) > 0 {
		evidence := finding.Evidence[0]
		fmt.Fprintf(&buffer, "│     %s %-9s %s @ %s\n", paint(options.Color, "38;5;45", "└─"), paint(options.Color, "38;5;244", "SIGNAL"), humanToken(string(evidence.Signal)), evidence.Subject)
		if options.Verbose {
			fmt.Fprintf(&buffer, "│        %s %s\n", paint(options.Color, "38;5;244", "↳"), evidence.Value)
			if evidence.Reference != "" {
				fmt.Fprintf(&buffer, "│        %s %s\n", paint(options.Color, "38;5;244", "ref"), evidence.Reference)
			}
		}
	}
	return buffer.String()
}

func liveEvidenceUpdate(started time.Time, finding model.Finding, evidence model.Evidence, options Options) string {
	var buffer strings.Builder
	fmt.Fprintf(&buffer, "│     %s +%-7s %s added %s @ %s\n", paint(options.Color, "38;5;244", "↳"), liveElapsed(started),
		finding.Provider, humanToken(string(evidence.Signal)), evidence.Subject)
	if options.Verbose {
		fmt.Fprintf(&buffer, "│        %s %s\n", paint(options.Color, "38;5;244", "↳"), evidence.Value)
	}
	return buffer.String()
}

func evidenceKey(evidence model.Evidence, verbose bool) string {
	key := string(evidence.Signal) + "\x00" + evidence.Subject
	if verbose {
		key += "\x00" + evidence.Value
	}
	return key
}

func liveElapsed(started time.Time) string {
	if started.IsZero() {
		return "0ms"
	}
	duration := time.Since(started)
	if duration < 0 {
		duration = 0
	}
	return duration.Truncate(time.Millisecond).String()
}

func Write(w io.Writer, report model.ScanReport, options Options) error {
	switch strings.ToLower(options.Format) {
	case "text", "":
		return writeText(w, report, options)
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "jsonl":
		encoder := json.NewEncoder(w)
		for _, finding := range report.Findings {
			if err := encoder.Encode(finding); err != nil {
				return err
			}
		}
		return nil
	case "csv":
		return writeCSV(w, report)
	default:
		return fmt.Errorf("unsupported output format %q", options.Format)
	}
}

func writeText(w io.Writer, report model.ScanReport, options Options) error {
	var buffer strings.Builder
	if options.Silent {
		for _, finding := range report.Findings {
			value := finding.Tenant
			if value == "" {
				value = finding.Provider
			}
			fmt.Fprintf(&buffer, "%s\t%s\t%s\n", finding.Target, finding.ProviderID, value)
		}
		_, err := io.WriteString(w, buffer.String())
		return err
	}
	writeScanHeader(&buffer, report, options.Color)
	if len(report.Findings) == 0 {
		fmt.Fprintf(&buffer, "\n%s  %s\n", paint(options.Color, "38;5;244", "◇"), paint(options.Color, "1;38;5;244", "NO MATCHED SAAS SIGNALS"))
		fmt.Fprintln(&buffer, "   Passive probes completed without provider evidence.")
	} else {
		for index, finding := range report.Findings {
			writeFinding(&buffer, index+1, finding, options)
		}
	}
	writeScanSummary(&buffer, report, options.Color)
	_, err := io.WriteString(w, buffer.String())
	return err
}

func writeScanHeader(buffer *strings.Builder, report model.ScanReport, color bool) {
	mode := "PASSIVE"
	if report.Metadata.Active {
		mode = "ACTIVE"
	}
	accent := func(value string) string { return paint(color, "38;5;45", value) }
	fmt.Fprintf(buffer, "%s%s%s\n", accent("╭─[ "), paint(color, "1;38;5;46", "SAASE"), accent(" // EXPOSURE INTELLIGENCE ]"))
	fmt.Fprintf(buffer, "%s  %-9s %s\n", accent("│"), paint(color, "38;5;244", "SESSION"), report.Metadata.ScanID)
	fmt.Fprintf(buffer, "%s  %-9s %s  %s %d  %s %d\n", accent("│"), paint(color, "38;5;244", "MODE"),
		paint(color, modeColor(report.Metadata.Active), mode), paint(color, "38;5;244", "TARGETS"), report.Metadata.Targets,
		paint(color, "38;5;244", "RULES"), report.Metadata.ProviderRules)
	if len(report.Metadata.TargetNames) > 0 {
		fmt.Fprintf(buffer, "%s  %-9s %s\n", accent("│"), paint(color, "38;5;244", "SCOPE"), compactTargets(report.Metadata.TargetNames))
	}
	fmt.Fprintf(buffer, "%s\n", accent("╰─[ PASSIVE-FIRST · AUTHORIZED TARGETS ONLY ]"))
}

func writeFinding(buffer *strings.Builder, number int, finding model.Finding, options Options) {
	accent := func(value string) string { return paint(options.Color, "38;5;45", value) }
	dim := func(value string) string { return paint(options.Color, "38;5;244", value) }
	badge := strings.ToUpper(string(finding.Confidence))
	if options.Color {
		badge = colorConfidence(finding.Confidence, badge)
	}
	fmt.Fprintf(buffer, "\n%s %02d  [%s]  %s %s\n", accent("◆"), number, badge,
		paint(options.Color, "1;37", finding.Provider), dim("// "+finding.ProviderID))

	type field struct{ label, value string }
	fields := []field{
		{label: "target", value: finding.Target},
		{label: "category", value: humanToken(finding.Category)},
	}
	if finding.Tenant != "" {
		fields = append(fields, field{label: "tenant", value: finding.Tenant})
	}
	if finding.RiskLead != "" {
		fields = append(fields, field{label: "lead", value: humanToken(finding.RiskLead)})
	}
	if options.Verbose && finding.Detector != "" {
		fields = append(fields, field{label: "detector", value: finding.Detector})
	}
	if !options.Verbose {
		fields = append(fields, field{label: "signals", value: signalSummary(finding.Evidence)})
	}
	for index, item := range fields {
		connector := "├─"
		if index == len(fields)-1 && !options.Verbose {
			connector = "└─"
		}
		fmt.Fprintf(buffer, "  %s %-10s %s\n", accent(connector), dim(strings.ToUpper(item.label)), item.value)
	}
	if options.Verbose {
		fmt.Fprintf(buffer, "  %s %s\n", accent("└─"), dim("EVIDENCE"))
		for index, evidence := range finding.Evidence {
			connector := "├─"
			if index == len(finding.Evidence)-1 {
				connector = "└─"
			}
			fmt.Fprintf(buffer, "     %s %-10s %s\n", accent(connector), paint(options.Color, "38;5;214", humanToken(string(evidence.Signal))), evidence.Subject)
			fmt.Fprintf(buffer, "        %s %s\n", dim("↳"), evidence.Value)
			if evidence.Reference != "" {
				fmt.Fprintf(buffer, "        %s %s\n", dim("ref"), evidence.Reference)
			}
		}
	}
}

func writeScanSummary(buffer *strings.Builder, report model.ScanReport, color bool) {
	accent := func(value string) string { return paint(color, "38;5;45", value) }
	dim := func(value string) string { return paint(color, "38;5;244", value) }
	findings := fmt.Sprintf("%d", len(report.Findings))
	if len(report.Findings) > 0 {
		findings = paint(color, "1;38;5;46", findings)
	}
	errors := fmt.Sprintf("%d", len(report.Errors))
	if len(report.Errors) > 0 {
		errors = paint(color, "1;38;5;196", errors)
	}
	fmt.Fprintf(buffer, "\n%s\n", accent("╭─[ SCAN COMPLETE ]"))
	fmt.Fprintf(buffer, "%s  %s %s   %s %s   %s %s\n", accent("│"), dim("FINDINGS"), findings, dim("ERRORS"), errors,
		dim("ELAPSED"), elapsed(report.Metadata.DurationMS))
	if len(report.Errors) > 0 {
		fmt.Fprintf(buffer, "%s  %s\n", accent("│"), dim("Use -v to inspect probe errors on stderr."))
	}
	fmt.Fprintf(buffer, "%s %s\n", accent("╰─"), dim("session "+report.Metadata.ScanID))
}

func writeCSV(w io.Writer, report model.ScanReport) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()
	if err := writer.Write([]string{"target", "provider_id", "provider", "category", "confidence", "tenant", "signals", "observed_at"}); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		signals := make([]string, 0, len(finding.Evidence))
		for _, evidence := range finding.Evidence {
			signals = append(signals, string(evidence.Signal))
		}
		sort.Strings(signals)
		if err := writer.Write([]string{finding.Target, finding.ProviderID, finding.Provider, finding.Category, string(finding.Confidence), finding.Tenant, strings.Join(unique(signals), ";"), finding.ObservedAt.Format("2006-01-02T15:04:05Z07:00")}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func WriteChanges(w io.Writer, changes []model.Change, format string) error {
	format = strings.ToLower(format)
	if format != "" && format != "text" && format != "json" && format != "jsonl" {
		return fmt.Errorf("unsupported diff output format %q", format)
	}
	if format == "json" || format == "jsonl" {
		encoder := json.NewEncoder(w)
		if format == "json" {
			encoder.SetIndent("", "  ")
			return encoder.Encode(changes)
		}
		for _, change := range changes {
			if err := encoder.Encode(change); err != nil {
				return err
			}
		}
		return nil
	}
	var buffer strings.Builder
	fmt.Fprintln(&buffer, "╭─[ SAASE // CHANGE MONITOR ]")
	if len(changes) == 0 {
		fmt.Fprintln(&buffer, "│  ◇ NO EXPOSURE DRIFT DETECTED")
	}
	for index, change := range changes {
		confidence := ""
		if change.Before != nil || change.After != nil {
			before, after := "-", "-"
			if change.Before != nil {
				before = string(*change.Before)
			}
			if change.After != nil {
				after = string(*change.After)
			}
			confidence = " " + before + " -> " + after
		}
		fmt.Fprintf(&buffer, "│\n│  %s %02d  [%-18s] %s // %s\n", changeGlyph(change.Type), index+1, strings.ToUpper(string(change.Type)), change.Provider, change.Target)
		if change.Tenant != "" {
			fmt.Fprintf(&buffer, "│      ├─ TENANT     %s\n", change.Tenant)
		}
		if confidence != "" {
			fmt.Fprintf(&buffer, "│      └─ CONFIDENCE%s\n", confidence)
		}
	}
	fmt.Fprintf(&buffer, "╰─[ %d CHANGE(S) ]\n", len(changes))
	_, err := io.WriteString(w, buffer.String())
	return err
}

func WriteScanList(w io.Writer, scans []model.StoredScan, format string) error {
	format = strings.ToLower(format)
	if format != "" && format != "text" && format != "json" {
		return fmt.Errorf("unsupported scan-list output format %q", format)
	}
	if format == "json" {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(scans)
	}
	var buffer strings.Builder
	fmt.Fprintln(&buffer, "╭─[ SAASE // SESSION ARCHIVE ]")
	fmt.Fprintln(&buffer, "│  SESSION           STARTED                    PROFILE    SCOPE")
	fmt.Fprintln(&buffer, "│  ────────────────  ─────────────────────────  ─────────  ────────────────────")
	for _, scan := range scans {
		fmt.Fprintf(&buffer, "│  %-16s  %-25s  %-9s  %s\n", scan.ID, scan.StartedAt.Format("2006-01-02T15:04:05Z07:00"), strings.ToUpper(scan.Profile), strings.Join(scan.TargetList, ","))
	}
	fmt.Fprintf(&buffer, "╰─[ %d SESSION(S) ]\n", len(scans))
	_, err := io.WriteString(w, buffer.String())
	return err
}

func colorConfidence(confidence model.Confidence, value string) string {
	code := "33"
	switch confidence {
	case model.ConfidenceConfirmed:
		code = "36"
	case model.ConfidenceHigh:
		code = "32"
	case model.ConfidenceLow, model.ConfidenceUnknown:
		code = "90"
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func paint(enabled bool, code, value string) string {
	if !enabled {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func modeColor(active bool) string {
	if active {
		return "1;38;5;201"
	}
	return "1;38;5;46"
}

func compactTargets(targets []string) string {
	if len(targets) <= 3 {
		return strings.Join(targets, ", ")
	}
	return strings.Join(targets[:3], ", ") + fmt.Sprintf(" +%d more", len(targets)-3)
}

func signalSummary(evidence []model.Evidence) string {
	signals := make([]string, 0, len(evidence))
	for _, item := range evidence {
		signals = append(signals, humanToken(string(item.Signal)))
	}
	sort.Strings(signals)
	return strings.Join(unique(signals), " · ")
}

func humanToken(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "_", " "))
}

func elapsed(milliseconds int64) string {
	return (time.Duration(milliseconds) * time.Millisecond).String()
}

func changeGlyph(change model.ChangeType) string {
	switch change {
	case model.ChangeAdded:
		return "+"
	case model.ChangeRemoved:
		return "−"
	default:
		return "~"
	}
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:0]
	for i, value := range values {
		if i == 0 || value != values[i-1] {
			result = append(result, value)
		}
	}
	return result
}
