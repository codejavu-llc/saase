// Package saase exposes the evidence-driven SaaS discovery engine for Go programs.
package saase

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/codejavu-llc/saase/v2/internal/catalog"
	"github.com/codejavu-llc/saase/v2/internal/engine"
	"github.com/codejavu-llc/saase/v2/internal/model"
	"github.com/codejavu-llc/saase/v2/internal/target"
	builtinrules "github.com/codejavu-llc/saase/v2/rules"
)

type Config = engine.Config
type Finding = model.Finding
type Evidence = model.Evidence
type ProbeError = model.ProbeError
type ScanReport = model.ScanReport
type ScanMetadata = model.ScanMetadata
type ScanEvent = model.ScanEvent
type ScanEventType = model.ScanEventType
type Confidence = model.Confidence
type Signal = model.Signal
type Provider = catalog.Provider
type Target = target.Target
type TargetOverrides = target.Overrides

const SchemaVersion = model.SchemaVersion

const (
	ScanEventStarted    = model.ScanEventStarted
	ScanEventFinding    = model.ScanEventFinding
	ScanEventFinished   = model.ScanEventFinished
	ConfidenceUnknown   = model.ConfidenceUnknown
	ConfidenceLow       = model.ConfidenceLow
	ConfidenceMedium    = model.ConfidenceMedium
	ConfidenceHigh      = model.ConfidenceHigh
	ConfidenceConfirmed = model.ConfidenceConfirmed
	SignalTXT           = model.SignalTXT
	SignalSPF           = model.SignalSPF
	SignalCNAME         = model.SignalCNAME
	SignalMX            = model.SignalMX
	SignalNS            = model.SignalNS
	SignalSRV           = model.SignalSRV
	SignalTenant        = model.SignalTenant
	SignalSSO           = model.SignalSSO
)

type Scanner struct {
	engine  *engine.Scanner
	catalog *catalog.Catalog
}

func DefaultConfig() Config { return engine.DefaultConfig() }

// NewScanner creates a scanner with the embedded provider catalog.
func NewScanner(cfg Config) (*Scanner, error) {
	return NewScannerWithRules(cfg, builtinrules.FS)
}

// NewScannerWithRules creates a scanner with providers.yml, dns.yml, and an
// optional metadata.yml loaded from the supplied filesystem.
func NewScannerWithRules(cfg Config, ruleFS fs.FS) (*Scanner, error) {
	providerCatalog, err := catalog.Load(ruleFS)
	if err != nil {
		return nil, fmt.Errorf("load provider rules: %w", err)
	}
	inner, err := engine.New(cfg, providerCatalog)
	if err != nil {
		return nil, err
	}
	return &Scanner{engine: inner, catalog: providerCatalog}, nil
}

func NormalizeTarget(input string, overrides TargetOverrides) (Target, error) {
	return target.Normalize(input, overrides)
}

// Scan normalizes domain inputs and runs the selected provider detectors.
func (s *Scanner) Scan(ctx context.Context, domains, providers []string) (ScanReport, error) {
	targets := make([]target.Target, 0, len(domains))
	seen := make(map[string]bool)
	for _, domain := range domains {
		item, err := target.Normalize(domain, target.Overrides{})
		if err != nil {
			return ScanReport{}, err
		}
		if !seen[item.Apex] {
			targets = append(targets, item)
			seen[item.Apex] = true
		}
	}
	return s.engine.Scan(ctx, targets, providers)
}

func (s *Scanner) Providers() []Provider { return s.catalog.Providers() }

// SetEventHandler receives ordered scan and finding events while Scan runs.
func (s *Scanner) SetEventHandler(handler func(ScanEvent)) { s.engine.SetEventHandler(handler) }

func ActiveProviderIDs() []string { return engine.ActiveProviderIDs() }
