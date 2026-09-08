// Package output turns findings into report files. Every writer consumes
// findings one at a time and flushes as it goes, so no output format ever
// holds the full result set in memory.
package output

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

var csvHeader = []string{
	"AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
	"ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
	"FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE",
	"STATUS", "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME",
	"SEVERITY", "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME",
	"RESOURCE_DETAILS", "RESOURCE_TAGS", "PARTITION", "REGION", "DESCRIPTION",
	"RISK", "RELATED_URL", "REMEDIATION_RECOMMENDATION_TEXT",
	"REMEDIATION_RECOMMENDATION_URL", "REMEDIATION_CODE_NATIVEIAC",
	"REMEDIATION_CODE_TERRAFORM", "REMEDIATION_CODE_CLI",
	"REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES", "DEPENDS_ON",
	"RELATED_TO", "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS",
}

// CSV writes findings as the semicolon-delimited report Prowler has always
// produced.
type CSV struct {
	w             *csv.Writer
	row           []string
	err           error
	unixTimestamp bool
}

// NewCSV starts a CSV report on w, writing the header immediately.
func NewCSV(w io.Writer, unixTimestamp bool) *CSV {
	writer := csv.NewWriter(w)
	writer.Comma = ';'
	c := &CSV{w: writer, row: make([]string, 0, len(csvHeader)), unixTimestamp: unixTimestamp}
	c.err = writer.Write(csvHeader)
	return c
}

// Write appends one finding. The row buffer is reused across findings.
func (c *CSV) Write(f *finding.Finding) error {
	if c.err != nil {
		return c.err
	}
	m := f.Metadata
	c.row = c.row[:0]
	c.row = append(c.row,
		f.AuthMethod,
		finding.FormatTimestamp(f.Timestamp, c.unixTimestamp),
		f.AccountUID,
		f.AccountName,
		f.AccountEmail,
		f.AccountOrganizationUID,
		f.AccountOrganizationName,
		UnrollMap(f.AccountTags, ":"),
		f.UID,
		m.Provider,
		m.CheckID,
		m.CheckTitle,
		UnrollList(m.CheckType, "|"),
		string(f.Status),
		f.StatusExtended,
		strconv.FormatBool(f.Muted),
		m.ServiceName,
		m.SubServiceName,
		string(m.Severity),
		m.ResourceType,
		f.ResourceUID,
		f.ResourceName,
		f.ResourceDetails,
		UnrollMap(f.ResourceTags, "="),
		f.Partition,
		f.Region,
		m.Description,
		m.Risk,
		m.RelatedUrl,
		m.Remediation.Recommendation.Text,
		m.Remediation.Recommendation.Url,
		m.Remediation.Code.NativeIaC,
		m.Remediation.Code.Terraform,
		m.Remediation.Code.CLI,
		m.Remediation.Code.Other,
		UnrollMapOfLists(f.Compliance, ": "),
		UnrollList(m.Categories, "|"),
		UnrollList(m.DependsOn, "|"),
		UnrollList(m.RelatedTo, "|"),
		m.Notes,
		f.ProwlerVersion,
		UnrollList(m.AdditionalURLs, "|"),
	)
	c.err = c.w.Write(c.row)
	return c.err
}

// Close flushes any buffered row.
func (c *CSV) Close() error {
	c.w.Flush()
	if c.err != nil {
		return c.err
	}
	return c.w.Error()
}
