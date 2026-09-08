package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

// OCSF writes findings as an array of OCSF Detection Finding events.
//
// The array brackets and separators are written as findings arrive, so the
// document is streamed rather than assembled.
type OCSF struct {
	enc     *json.Encoder
	w       io.Writer
	written int
	err     error
}

func NewOCSF(w io.Writer) *OCSF {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	enc.SetEscapeHTML(false)
	o := &OCSF{enc: enc, w: w}
	o.write("[")
	return o
}

func (o *OCSF) Write(f *finding.Finding) error {
	if o.err != nil {
		return o.err
	}
	if o.written > 0 {
		o.write(", ")
	}
	if o.err != nil {
		return o.err
	}
	o.err = o.enc.Encode(detectionFinding(f))
	o.written++
	return o.err
}

func (o *OCSF) Close() error {
	o.write("]")
	return o.err
}

func (o *OCSF) write(s string) {
	if o.err != nil {
		return
	}
	_, o.err = io.WriteString(o.w, s)
}

type severityID int

const (
	severityUnknown severityID = iota
	severityInformational
	severityLow
	severityMedium
	severityHigh
	severityCritical
)

var severityIDs = map[check.Severity]severityID{
	check.SeverityInformational: severityInformational,
	check.SeverityLow:           severityLow,
	check.SeverityMedium:        severityMedium,
	check.SeverityHigh:          severityHigh,
	check.SeverityCritical:      severityCritical,
}

func (s severityID) name() string {
	switch s {
	case severityInformational:
		return "Informational"
	case severityLow:
		return "Low"
	case severityMedium:
		return "Medium"
	case severityHigh:
		return "High"
	case severityCritical:
		return "Critical"
	}
	return "Unknown"
}

// accountTypeIDs maps a provider onto the OCSF account type it reports.
var accountTypeIDs = map[string]struct {
	id   int
	name string
}{
	"aws":   {10, "AWS Account"},
	"azure": {12, "Azure AD Account"},
	"gcp":   {11, "GCP Account"},
}

func detectionFinding(f *finding.Finding) map[string]any {
	m := f.Metadata
	sev := severityIDs[m.Severity]

	statusID, statusName := 1, "New"
	if f.Muted {
		statusID, statusName = 3, "Suppressed"
	}

	isKubernetes := m.Provider == "kubernetes"
	profiles := []string{"cloud", "datetime"}
	if isKubernetes {
		profiles = []string{"container", "datetime"}
	}

	resource := map[string]any{
		"labels": labelsOf(f.ResourceTags),
		"name":   f.ResourceName,
		"uid":    f.ResourceUID,
		"group":  map[string]any{"name": m.ServiceName},
		"type":   m.ResourceType,
		"data": map[string]any{
			"details":  f.ResourceDetails,
			"metadata": rawOrNil(f.ResourceMetadata),
		},
	}
	if isKubernetes {
		resource["namespace"] = strings.TrimPrefix(f.Region, "namespace: ")
	} else {
		resource["cloud_partition"] = f.Partition
		resource["region"] = f.Region
	}

	event := map[string]any{
		"message":       f.StatusExtended,
		"activity_id":   1,
		"activity_name": "Create",
		"finding_info": map[string]any{
			"created_time_dt": f.Timestamp,
			"created_time":    f.Timestamp.Unix(),
			"desc":            m.Description,
			"title":           m.CheckTitle,
			"uid":             f.UID,
			"name":            f.ResourceName,
			"types":           m.CheckType,
		},
		"time_dt": f.Timestamp,
		"time":    f.Timestamp.Unix(),
		"remediation": map[string]any{
			"desc":       m.Remediation.Recommendation.Text,
			"references": nonEmpty(m.Remediation.Recommendation.Url),
		},
		"severity_id":   int(sev),
		"severity":      sev.name(),
		"status_id":     statusID,
		"status":        statusName,
		"status_code":   string(f.Status),
		"status_detail": f.StatusExtended,
		"risk_details":  m.Risk,
		"resources":     []any{resource},
		"metadata": map[string]any{
			"event_code": m.CheckID,
			"product": map[string]any{
				"uid":         "prowler",
				"name":        "Prowler",
				"vendor_name": "Prowler",
				"version":     f.ProwlerVersion,
			},
			"profiles":   profiles,
			"tenant_uid": f.AccountOrganizationUID,
		},
		"type_uid":  200401,
		"type_name": "Detection Finding: Create",
		"unmapped": map[string]any{
			"related_url":     m.RelatedUrl,
			"categories":      m.Categories,
			"depends_on":      m.DependsOn,
			"related_to":      m.RelatedTo,
			"additional_urls": m.AdditionalURLs,
			"notes":           m.Notes,
			"compliance":      f.Compliance,
		},
	}

	if !isKubernetes {
		account := accountTypeIDs[m.Provider]
		if account.name == "" {
			account.name = "Unknown"
		}
		event["cloud"] = map[string]any{
			"account": map[string]any{
				"name":    f.AccountName,
				"type_id": account.id,
				"type":    account.name,
				"uid":     f.AccountUID,
				"labels":  labelsOf(f.AccountTags),
			},
			"org": map[string]any{
				"uid":  f.AccountOrganizationUID,
				"name": f.AccountOrganizationName,
			},
			"provider": m.Provider,
			"region":   f.Region,
		}
	}

	return event
}

// labelsOf renders tags as the "key: value" list OCSF expects.
func labelsOf(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	labels := make([]string, 0, len(keys))
	for _, key := range keys {
		labels = append(labels, fmt.Sprintf("%s: %s", key, tags[key]))
	}
	return labels
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func rawOrNil(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
