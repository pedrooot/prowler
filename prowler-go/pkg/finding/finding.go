// Package finding holds the provider-independent result of evaluating one
// check against one resource, as it travels from the engine to the writers.
package finding

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
)

// Finding is the unit the engine streams to every output writer.
//
// It deliberately keeps the raw resource as encoded JSON: most writers never
// look at it, and decoding it for all of them would dominate the memory of a
// large scan.
type Finding struct {
	AuthMethod string    `json:"auth_method"`
	Timestamp  time.Time `json:"timestamp"`

	AccountUID              string            `json:"account_uid"`
	AccountName             string            `json:"account_name,omitempty"`
	AccountEmail            string            `json:"account_email,omitempty"`
	AccountOrganizationUID  string            `json:"account_organization_uid,omitempty"`
	AccountOrganizationName string            `json:"account_organization_name,omitempty"`
	AccountTags             map[string]string `json:"account_tags,omitempty"`

	Metadata *check.Metadata `json:"metadata"`

	UID            string       `json:"uid"`
	Status         check.Status `json:"status"`
	StatusExtended string       `json:"status_extended"`
	Muted          bool         `json:"muted"`

	ResourceUID      string            `json:"resource_uid"`
	ResourceName     string            `json:"resource_name"`
	ResourceDetails  string            `json:"resource_details"`
	ResourceTags     map[string]string `json:"resource_tags,omitempty"`
	ResourceMetadata json.RawMessage   `json:"resource_metadata,omitempty"`

	Partition string `json:"partition,omitempty"`
	Region    string `json:"region"`

	Compliance     map[string][]string `json:"compliance,omitempty"`
	ProwlerVersion string              `json:"prowler_version"`

	Raw json.RawMessage `json:"raw,omitempty"`
}

// FormatTimestamp renders a scan timestamp the way the reports expect:
// seconds since the epoch when unix is set, otherwise Python's isoformat,
// which drops the fractional part when it is zero.
func FormatTimestamp(t time.Time, unix bool) string {
	if unix {
		return strconv.FormatInt(t.Unix(), 10)
	}
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}

// Stats accumulates the counters the summary table and the exit code need,
// without keeping any finding alive.
type Stats struct {
	Total    int
	Pass     int
	Fail     int
	Muted    int
	Manual   int
	Critical int
	High     int
	Medium   int
	Low      int

	// FailBySeverity counts only non-muted failures, which is what drives
	// the severity breakdown of the summary.
	FailBySeverity map[check.Severity]int
	ByService      map[string]ServiceStats
}

// ServiceStats is the per-service breakdown of the summary table.
type ServiceStats struct {
	Pass  int
	Fail  int
	Muted int
}

func NewStats() *Stats {
	return &Stats{
		FailBySeverity: make(map[check.Severity]int, 5),
		ByService:      make(map[string]ServiceStats, 64),
	}
}

// Add folds one finding into the counters. It never retains the finding.
func (s *Stats) Add(f *Finding) {
	s.Total++
	service := s.ByService[f.Metadata.ServiceName]

	switch {
	case f.Muted:
		s.Muted++
		service.Muted++
	case f.Status == check.StatusPass:
		s.Pass++
		service.Pass++
	case f.Status == check.StatusFail:
		s.Fail++
		service.Fail++
		s.FailBySeverity[f.Metadata.Severity]++
	case f.Status == check.StatusManual:
		s.Manual++
	}

	s.ByService[f.Metadata.ServiceName] = service

	switch f.Metadata.Severity {
	case check.SeverityCritical:
		s.Critical++
	case check.SeverityHigh:
		s.High++
	case check.SeverityMedium:
		s.Medium++
	case check.SeverityLow:
		s.Low++
	}
}
