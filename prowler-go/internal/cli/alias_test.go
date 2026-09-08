package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestEveryPythonAliasIsAccepted pins the alternative flag spellings the
// Python argparse definitions declare. They do not appear in --help, but a
// user or script that types them must still be understood.
func TestEveryPythonAliasIsAccepted(t *testing.T) {
	cases := []struct {
		provider string
		flag     string
		value    string
	}{
		{"aws", "--checks", "s3_bucket_public_access"},
		{"aws", "--services", "s3"},
		{"aws", "--severities", "high"},
		{"aws", "--categories", "internet-exposed"},
		{"aws", "--excluded-checks", "x"},
		{"aws", "--excluded-services", "s3"},
		{"aws", "--filter-region", "eu-west-1"},
		{"aws", "--resource-tags", "a=b"},
		{"aws", "--resource-arns", "arn:x"},
		{"aws", "--output-modes", "csv"},
		{"aws", "--list-compliances", ""},
		{"aws", "--list-fixers", ""},
		{"aws", "--list-remediations", ""},
		{"azure", "--subscription-ids", "sub1"},
		{"gcp", "--project-ids", "p1"},
		{"gcp", "--excluded-project-ids", "p2"},
		{"gcp", "--list-project-ids", ""},
		{"kubernetes", "--namespaces", "default"},
		{"github", "--repositories", "r"},
		{"github", "--organizations", "o"},
		{"github", "--github-app-key-path", "/tmp/key"},
		{"oraclecloud", "--compartment", "c"},
		{"oraclecloud", "--instance-principal", ""},
		{"iac", "--scanner", "secret"},
		{"cloudflare", "--filter-region", "eu"},
		{"alibabacloud", "--filter-region", "eu"},
	}

	for _, tt := range cases {
		args := []string{tt.provider, tt.flag}
		if tt.value != "" {
			args = append(args, tt.value)
		}
		args = append(args, "--list-services")

		var out bytes.Buffer
		root := Root("5.18.0", &recordingRunner{}, &out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil && strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s %s: %v", tt.provider, tt.flag, err)
		}
	}
}
