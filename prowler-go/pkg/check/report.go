package check

import (
	"encoding/json"
	"strings"
)

// Status is the outcome of evaluating a check against one resource.
type Status string

const (
	StatusPass    Status = "PASS"
	StatusFail    Status = "FAIL"
	StatusManual  Status = "MANUAL"
	StatusMuted   Status = "MUTED"
	StatusUnknown Status = ""
)

// Report is what a check emits for a single resource. Providers extend it
// through the embedded fields their findings need, and the engine turns it
// into a finding once the provider context is known.
type Report struct {
	Metadata       *Metadata
	Status         Status
	StatusExtended string
	Muted          bool

	ResourceID      string
	ResourceARN     string
	ResourceName    string
	ResourceDetails string
	ResourceTags    map[string]string
	Region          string
	Partition       string

	// Resource carries the provider-specific resource as it was collected.
	// It stays encoded until an output format asks for it.
	Resource json.RawMessage
}

// Resourcer is implemented by collected resources so a report can pick up
// their identity without provider-specific code in the engine.
type Resourcer interface {
	ResourceID() string
	ResourceName() string
	ResourceRegion() string
	ResourceTags() map[string]string
}

// ARNer is implemented by resources that carry a cloud-native ARN.
type ARNer interface {
	ResourceARN() string
}

// NewReport builds a report pre-filled from a collected resource.
func NewReport(metadata *Metadata, resource Resourcer) *Report {
	r := &Report{
		Metadata:     metadata,
		ResourceID:   resource.ResourceID(),
		ResourceName: resource.ResourceName(),
		Region:       resource.ResourceRegion(),
		ResourceTags: resource.ResourceTags(),
	}
	if a, ok := resource.(ARNer); ok {
		r.ResourceARN = a.ResourceARN()
	}
	if r.ResourceID == "" {
		r.ResourceID = r.ResourceName
	}
	return r
}

// Pass marks the report as passing with the given extended status.
func (r *Report) Pass(statusExtended string) *Report {
	r.Status = StatusPass
	r.StatusExtended = statusExtended
	return r
}

// Fail marks the report as failing with the given extended status.
func (r *Report) Fail(statusExtended string) *Report {
	r.Status = StatusFail
	r.StatusExtended = statusExtended
	return r
}

// Manual marks the report as requiring human review.
func (r *Report) Manual(statusExtended string) *Report {
	r.Status = StatusManual
	r.StatusExtended = statusExtended
	return r
}

// Decide sets PASS or FAIL from a boolean, which is how most checks read.
func (r *Report) Decide(ok bool, passExtended, failExtended string) *Report {
	if ok {
		return r.Pass(passExtended)
	}
	return r.Fail(failExtended)
}

func ParseStatus(s string) (Status, bool) {
	switch Status(strings.ToUpper(s)) {
	case StatusPass:
		return StatusPass, true
	case StatusFail:
		return StatusFail, true
	case StatusManual:
		return StatusManual, true
	case StatusMuted:
		return StatusMuted, true
	}
	return StatusUnknown, false
}
