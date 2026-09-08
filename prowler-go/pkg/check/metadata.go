// Package check defines the metadata model, the Check contract and the
// registry through which every check makes itself known to the scan engine.
package check

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Severity ranks the impact of a failing check.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

var severityRank = map[Severity]int{
	SeverityInformational: 0,
	SeverityLow:           1,
	SeverityMedium:        2,
	SeverityHigh:          3,
	SeverityCritical:      4,
}

func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(s))
	if _, ok := severityRank[sev]; !ok {
		return "", fmt.Errorf("invalid severity %q", s)
	}
	return sev, nil
}

func (s Severity) AtLeast(other Severity) bool { return severityRank[s] >= severityRank[other] }

// Code holds the remediation snippets for a check.
type Code struct {
	NativeIaC string `json:"NativeIaC"`
	Terraform string `json:"Terraform"`
	CLI       string `json:"CLI"`
	Other     string `json:"Other"`
}

// Recommendation points at the guidance for a remediation.
type Recommendation struct {
	Text string `json:"Text"`
	Url  string `json:"Url"`
}

// Remediation describes how to fix a failing check.
type Remediation struct {
	Code           Code           `json:"Code"`
	Recommendation Recommendation `json:"Recommendation"`
}

// Metadata is the compile-time description of a check, loaded from its
// sibling <check_id>.metadata.json file.
type Metadata struct {
	Provider           string          `json:"Provider"`
	CheckID            string          `json:"CheckID"`
	CheckTitle         string          `json:"CheckTitle"`
	CheckType          []string        `json:"CheckType"`
	CheckAliases       []string        `json:"CheckAliases,omitempty"`
	ServiceName        string          `json:"ServiceName"`
	SubServiceName     string          `json:"SubServiceName"`
	ResourceIdTemplate string          `json:"ResourceIdTemplate"`
	Severity           Severity        `json:"Severity"`
	ResourceType       string          `json:"ResourceType"`
	ResourceGroup      string          `json:"ResourceGroup,omitempty"`
	Description        string          `json:"Description"`
	Risk               string          `json:"Risk"`
	RelatedUrl         string          `json:"RelatedUrl"`
	Remediation        Remediation     `json:"Remediation"`
	AdditionalURLs     []string        `json:"AdditionalURLs,omitempty"`
	Categories         []string        `json:"Categories"`
	DependsOn          []string        `json:"DependsOn"`
	RelatedTo          []string        `json:"RelatedTo"`
	Notes              string          `json:"Notes"`
	Compliance         []ComplianceRef `json:"Compliance,omitempty"`
}

// ComplianceRef links a check to one requirement of a compliance framework.
// It is populated at load time, not read from the metadata file.
type ComplianceRef struct {
	Framework    string   `json:"Framework"`
	Provider     string   `json:"Provider"`
	Version      string   `json:"Version"`
	Requirements []string `json:"Requirements"`
}

var (
	categoryPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	urlPrefix       = regexp.MustCompile(`^https?://`)
)

// UnmarshalMetadata decodes and validates a metadata document, applying the
// same normalisation and constraints as the Python implementation.
func UnmarshalMetadata(data []byte) (*Metadata, error) {
	var m Metadata
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	if err := m.normalize(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Metadata) normalize() error {
	m.Severity = Severity(strings.ToLower(string(m.Severity)))
	if _, ok := severityRank[m.Severity]; !ok {
		return fmt.Errorf("invalid severity %q", m.Severity)
	}

	for i, category := range m.Categories {
		lowered := strings.ToLower(category)
		if !categoryPattern.MatchString(lowered) {
			return fmt.Errorf("invalid category %q: only lowercase letters, numbers and hyphen are allowed", category)
		}
		m.Categories[i] = lowered
	}

	if urlPrefix.MatchString(m.Remediation.Code.CLI) {
		return fmt.Errorf("CLI command cannot be an URL")
	}
	if m.ResourceType == "" {
		return fmt.Errorf("ResourceType must be a non-empty string")
	}
	if m.CheckID == "" {
		return fmt.Errorf("CheckID must be a non-empty string")
	}
	if m.ServiceName == "" {
		return fmt.Errorf("ServiceName must be a non-empty string")
	}

	if m.Provider != "iac" && m.Provider != "llm" {
		if strings.Contains(m.CheckID, "-") {
			return fmt.Errorf("CheckID %s contains a hyphen, which is not allowed", m.CheckID)
		}
		service, _, _ := strings.Cut(m.CheckID, "_")
		if m.ServiceName != service {
			return fmt.Errorf("ServiceName %s does not belong to CheckID %s", m.ServiceName, m.CheckID)
		}
		if m.ServiceName != strings.ToLower(m.ServiceName) {
			return fmt.Errorf("ServiceName %s must be in lowercase", m.ServiceName)
		}
	}

	seen := make(map[string]struct{}, len(m.AdditionalURLs))
	for _, url := range m.AdditionalURLs {
		if strings.TrimSpace(url) == "" {
			return fmt.Errorf("AdditionalURLs cannot contain empty items")
		}
		if _, dup := seen[url]; dup {
			return fmt.Errorf("AdditionalURLs cannot contain duplicate items")
		}
		seen[url] = struct{}{}
	}
	return nil
}

// UnmarshalBundle decodes a generated metadata bundle into a lookup keyed by
// check ID, validating every entry as it goes.
func UnmarshalBundle(data []byte) (map[string]*Metadata, error) {
	var all []*Metadata
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	byID := make(map[string]*Metadata, len(all))
	for _, m := range all {
		if err := m.normalize(); err != nil {
			return nil, fmt.Errorf("check %s: %w", m.CheckID, err)
		}
		if _, dup := byID[m.CheckID]; dup {
			return nil, fmt.Errorf("check %s appears twice in bundle", m.CheckID)
		}
		byID[m.CheckID] = m
	}
	return byID, nil
}
