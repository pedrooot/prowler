package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/finding"
)

func sampleFinding() *finding.Finding {
	return &finding.Finding{
		AuthMethod:  "profile: default",
		Timestamp:   time.Date(2026, 9, 8, 10, 30, 0, 0, time.UTC),
		AccountUID:  "123456789012",
		AccountName: "prod",
		Metadata: &check.Metadata{
			Provider:     "aws",
			CheckID:      "s3_bucket_public_access",
			CheckTitle:   "S3 bucket is not publicly accessible",
			CheckType:    []string{"Effects/Data Exposure"},
			ServiceName:  "s3",
			Severity:     check.SeverityCritical,
			ResourceType: "AwsS3Bucket",
			Description:  "Buckets are checked for public access.",
			Categories:   []string{"internet-exposed"},
			Remediation: check.Remediation{
				Recommendation: check.Recommendation{Text: "Block public access", Url: "https://example.test"},
			},
		},
		UID:            "prowler-aws-s3_bucket_public_access-bucket-eu-west-1",
		Status:         check.StatusFail,
		StatusExtended: "S3 Bucket demo has public access.",
		ResourceUID:    "arn:aws:s3:::demo",
		ResourceName:   "demo",
		ResourceTags:   map[string]string{"env": "prod", "team": "sec"},
		Partition:      "aws",
		Region:         "eu-west-1",
		Compliance:     map[string][]string{"CIS-3.0": {"2.1.1", "2.1.2"}},
		ProwlerVersion: "5.18.0",
	}
}

func TestCSVRowMatchesHeader(t *testing.T) {
	var buf strings.Builder
	w := NewCSV(&buf, false)
	if err := w.Write(sampleFinding()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want header + one row", len(lines))
	}
	header := strings.Split(lines[0], ";")
	if len(header) != len(csvHeader) {
		t.Fatalf("header has %d columns, want %d", len(header), len(csvHeader))
	}
	if !strings.Contains(lines[1], "s3_bucket_public_access") {
		t.Errorf("row is missing the check id: %s", lines[1])
	}
	if !strings.Contains(lines[1], "CIS-3.0: 2.1.1, 2.1.2") {
		t.Errorf("row is missing the unrolled compliance: %s", lines[1])
	}
	if !strings.Contains(lines[1], "env=prod | team=sec") {
		t.Errorf("row is missing the unrolled tags: %s", lines[1])
	}
}

func TestCSVUnixTimestamp(t *testing.T) {
	var buf strings.Builder
	w := NewCSV(&buf, true)
	if err := w.Write(sampleFinding()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Close()
	if !strings.Contains(buf.String(), "1788863400") {
		t.Errorf("expected epoch seconds in output, got %s", buf.String())
	}
}

func TestOCSFProducesValidArray(t *testing.T) {
	var buf strings.Builder
	w := NewOCSF(&buf)
	if err := w.Write(sampleFinding()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Write(sampleFinding()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var events []map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &events); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	e := events[0]
	if e["severity"] != "Critical" {
		t.Errorf("severity = %v, want Critical", e["severity"])
	}
	if e["status_code"] != "FAIL" {
		t.Errorf("status_code = %v, want FAIL", e["status_code"])
	}
	if _, ok := e["cloud"]; !ok {
		t.Error("aws findings must carry the cloud profile")
	}
	meta := e["metadata"].(map[string]any)
	if meta["event_code"] != "s3_bucket_public_access" {
		t.Errorf("event_code = %v", meta["event_code"])
	}
}

func TestOCSFKubernetesUsesContainerProfile(t *testing.T) {
	f := sampleFinding()
	f.Metadata.Provider = "kubernetes"
	f.Region = "namespace: kube-system"

	var buf strings.Builder
	w := NewOCSF(&buf)
	w.Write(f)
	w.Close()

	var events []map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &events); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := events[0]["cloud"]; ok {
		t.Error("kubernetes findings must not carry the cloud profile")
	}
	resource := events[0]["resources"].([]any)[0].(map[string]any)
	if resource["namespace"] != "kube-system" {
		t.Errorf("namespace = %v, want kube-system", resource["namespace"])
	}
}

func TestUnrollList(t *testing.T) {
	tests := []struct {
		values    []string
		separator string
		want      string
	}{
		{nil, "|", ""},
		{[]string{"a"}, "|", "a"},
		{[]string{"a", "b", "c"}, "|", "a | b | c"},
		{[]string{"a", "b"}, ",", "a, b"},
	}
	for _, tt := range tests {
		if got := UnrollList(tt.values, tt.separator); got != tt.want {
			t.Errorf("UnrollList(%v, %q) = %q, want %q", tt.values, tt.separator, got, tt.want)
		}
	}
}

func TestUnrollMap(t *testing.T) {
	got := UnrollMap(map[string]string{"b": "2", "a": "1"}, "=")
	if got != "a=1 | b=2" {
		t.Errorf("UnrollMap = %q, want %q", got, "a=1 | b=2")
	}
	if got := UnrollMap(nil, "="); got != "" {
		t.Errorf("UnrollMap(nil) = %q, want empty", got)
	}
}
