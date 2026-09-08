// Package e2e drives a whole scan through the real engine, checks and
// writers, with only the cloud API replaced.
package e2e

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/compliance"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/mutelist"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/output"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/scan"

	s3svc "github.com/prowler-cloud/prowler/prowler-go/pkg/provider/aws/services/s3"
)

// provider serves pre-built S3 state so the scan exercises the real engine
// without any AWS call.
type provider struct {
	s3        *s3svc.Service
	s3control *s3svc.AccountAccessBlock
	collected []string
}

func (*provider) Type() string           { return "aws" }
func (*provider) Config() map[string]any { return nil }
func (*provider) Identity() scan.Identity {
	return scan.Identity{AuthMethod: "profile: test", AccountUID: "123456789012", Partition: "aws"}
}

func (p *provider) Collect(_ context.Context, name string) (any, error) {
	p.collected = append(p.collected, name)
	switch name {
	case "s3":
		return p.s3, nil
	case "s3control":
		return p.s3control, nil
	}
	return nil, nil
}

func fixture() *provider {
	return &provider{s3: &s3svc.Service{
		Account:   "123456789012",
		Partition: "aws",
		Buckets: []*s3svc.Bucket{
			{
				Name: "hardened", ARN: "arn:aws:s3:::hardened", Region: "eu-west-1",
				Versioning: true, MFADelete: true, Logging: true, Encryption: "aws:kms",
				PublicAccessBlock: &s3svc.PublicAccessBlock{IgnorePublicACLs: true, RestrictPublicBuckets: true},
				Tags:              map[string]string{"env": "prod"},
			},
			{
				Name: "open", ARN: "arn:aws:s3:::open", Region: "us-east-1",
				PublicAccessBlock: &s3svc.PublicAccessBlock{},
				ACLGrantees: []s3svc.Grantee{
					{Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers"},
				},
			},
		},
	}}
}

// s3Checks are the checks this slice has ported, in the order the engine runs
// them.
var s3Checks = []string{
	"s3_bucket_default_encryption",
	"s3_bucket_no_mfa_delete",
	"s3_bucket_object_versioning",
	"s3_bucket_public_access",
	"s3_bucket_server_access_logging_enabled",
}

type capture struct{ findings []*outputRow }

type outputRow struct {
	CheckID  string
	Status   check.Status
	Resource string
	Extended string
	Muted    bool
}

func TestScanEndToEnd(t *testing.T) {
	p := fixture()
	engine := scan.New(p, check.Global(), "5.18.0")

	var csvOut, ocsfOut strings.Builder
	sink := output.NewMulti(output.NewCSV(&csvOut, false), output.NewOCSF(&ocsfOut))

	stats, err := engine.Run(context.Background(), s3Checks, sink)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Two buckets across five checks, with public_access reporting on both.
	if stats.Total != 10 {
		t.Errorf("stats.Total = %d, want 10", stats.Total)
	}
	if stats.Pass+stats.Fail != stats.Total {
		t.Errorf("pass %d + fail %d != total %d", stats.Pass, stats.Fail, stats.Total)
	}
	if stats.ByService["s3"].Pass+stats.ByService["s3"].Fail != 10 {
		t.Errorf("service breakdown = %+v", stats.ByService["s3"])
	}

	reader := csv.NewReader(strings.NewReader(csvOut.String()))
	reader.Comma = ';'
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("the CSV report does not parse: %v", err)
	}
	if len(rows) != 11 {
		t.Fatalf("CSV has %d rows, want header + 10 findings", len(rows))
	}

	var events []map[string]any
	if err := json.Unmarshal([]byte(ocsfOut.String()), &events); err != nil {
		t.Fatalf("the OCSF report does not parse: %v", err)
	}
	if len(events) != 10 {
		t.Errorf("OCSF has %d events, want 10", len(events))
	}
}

func TestScanCollectsOnlyWhatTheChecksNeed(t *testing.T) {
	p := fixture()
	engine := scan.New(p, check.Global(), "5.18.0")

	_, err := engine.Run(context.Background(), []string{"s3_bucket_default_encryption"}, output.NewMulti())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(p.collected) != 1 || p.collected[0] != "s3" {
		t.Errorf("collected %v, want only s3 — s3control is not needed by this check", p.collected)
	}
}

func TestScanAppliesTheMutelist(t *testing.T) {
	muter, err := mutelist.Parse([]byte(`
Mutelist:
  Accounts:
    '*':
      Checks:
        s3_bucket_default_encryption:
          Regions: ['*']
          Resources: ['open']
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	p := fixture()
	engine := scan.New(p, check.Global(), "5.18.0", scan.WithMuter(muter))

	stats, err := engine.Run(context.Background(), []string{"s3_bucket_default_encryption"}, output.NewMulti())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Muted != 1 {
		t.Errorf("stats.Muted = %d, want the open bucket to be muted", stats.Muted)
	}
}

func TestScanHonoursTheStatusFilter(t *testing.T) {
	p := fixture()
	engine := scan.New(p, check.Global(), "5.18.0",
		scan.WithStatusFilter([]check.Status{check.StatusFail}))

	stats, err := engine.Run(context.Background(), s3Checks, output.NewMulti())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Pass != 0 {
		t.Errorf("stats.Pass = %d, want the filter to drop passing findings", stats.Pass)
	}
	if stats.Fail == 0 {
		t.Error("the filter dropped everything")
	}
}

func TestPortedChecksAreInTheirComplianceFrameworks(t *testing.T) {
	set, err := compliance.ForProvider("aws")
	if err != nil {
		t.Fatalf("ForProvider: %v", err)
	}
	byCheck := set.ByCheck()

	for _, id := range s3Checks {
		if len(byCheck[id]) == 0 {
			t.Errorf("check %s is mapped to no compliance framework", id)
		}
	}
}
