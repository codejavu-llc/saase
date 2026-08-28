package model

import "time"

const SchemaVersion = "2.0"

type Confidence string

const (
	ConfidenceUnknown   Confidence = "unknown"
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

func (c Confidence) Rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

type Signal string

const (
	SignalTXT    Signal = "dns_txt"
	SignalSPF    Signal = "dns_spf"
	SignalCNAME  Signal = "dns_cname"
	SignalMX     Signal = "dns_mx"
	SignalNS     Signal = "dns_ns"
	SignalSRV    Signal = "dns_srv"
	SignalTenant Signal = "tenant_http"
	SignalSSO    Signal = "sso_http"
)

type Evidence struct {
	Signal    Signal `json:"signal"`
	Subject   string `json:"subject"`
	Value     string `json:"value"`
	Reference string `json:"reference,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

type Finding struct {
	SchemaVersion string     `json:"schema_version"`
	Target        string     `json:"target"`
	ProviderID    string     `json:"provider_id"`
	Provider      string     `json:"provider"`
	Category      string     `json:"category,omitempty"`
	Description   string     `json:"description,omitempty"`
	Website       string     `json:"website,omitempty"`
	Tenant        string     `json:"tenant,omitempty"`
	Confidence    Confidence `json:"confidence"`
	RiskLead      string     `json:"risk_lead,omitempty"`
	Impact        string     `json:"impact,omitempty"`
	Evidence      []Evidence `json:"evidence"`
	Detector      string     `json:"detector"`
	ObservedAt    time.Time  `json:"observed_at"`
	LatencyMS     int64      `json:"latency_ms,omitempty"`
}

type ProbeError struct {
	Target   string `json:"target"`
	Detector string `json:"detector"`
	Subject  string `json:"subject,omitempty"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

type ScanMetadata struct {
	SchemaVersion string        `json:"schema_version"`
	ScanID        string        `json:"scan_id"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Duration      time.Duration `json:"-"`
	DurationMS    int64         `json:"duration_ms"`
	Profile       string        `json:"profile"`
	Active        bool          `json:"active"`
	InsecureTLS   bool          `json:"insecure_tls"`
	Targets       int           `json:"targets"`
	TargetNames   []string      `json:"target_names"`
	ProviderRules int           `json:"provider_rules"`
}

type ScanReport struct {
	Metadata ScanMetadata `json:"metadata"`
	Findings []Finding    `json:"findings"`
	Errors   []ProbeError `json:"errors,omitempty"`
}

type ScanEventType string

const (
	ScanEventStarted  ScanEventType = "scan_started"
	ScanEventFinding  ScanEventType = "finding_observed"
	ScanEventFinished ScanEventType = "scan_finished"
)

// ScanEvent reports scan progress as it happens. Finding events are emitted
// only after a detector's positive matcher accepts the evidence.
type ScanEvent struct {
	Type     ScanEventType `json:"type"`
	Metadata *ScanMetadata `json:"metadata,omitempty"`
	Finding  *Finding      `json:"finding,omitempty"`
}

type StoredScan struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	Profile    string    `json:"profile"`
	TargetList []string  `json:"targets"`
}

type ChangeType string

const (
	ChangeAdded      ChangeType = "added"
	ChangeRemoved    ChangeType = "removed"
	ChangeConfidence ChangeType = "confidence_changed"
)

type Change struct {
	Type     ChangeType  `json:"type"`
	Target   string      `json:"target"`
	Provider string      `json:"provider"`
	Tenant   string      `json:"tenant,omitempty"`
	Before   *Confidence `json:"before,omitempty"`
	After    *Confidence `json:"after,omitempty"`
}
