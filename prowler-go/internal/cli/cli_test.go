package cli

import (
	"bytes"
	"strings"
	"testing"
)

type recordingRunner struct {
	provider string
	opts     *Options
	code     int
}

func (r *recordingRunner) Run(provider string, opts *Options) (int, error) {
	r.provider = provider
	r.opts = opts
	return r.code, nil
}

func run(t *testing.T, args ...string) (*recordingRunner, string, error) {
	t.Helper()
	runner := &recordingRunner{}
	var out bytes.Buffer
	root := Root("5.18.0", runner, &out)
	root.SetArgs(args)
	err := root.Execute()
	return runner, out.String(), err
}

func TestDefaultProviderIsAWS(t *testing.T) {
	known := KnownProviders()
	tests := []struct {
		args []string
		want string
	}{
		{[]string{}, "aws"},
		{[]string{"--services", "s3"}, "aws"},
		{[]string{"-c", "s3_bucket_public_access"}, "aws"},
		{[]string{"azure", "--az-cli-auth"}, "azure"},
		{[]string{"gcp"}, "gcp"},
	}
	for _, tt := range tests {
		got := InsertDefaultProvider(tt.args, known)
		if len(got) == 0 || got[0] != tt.want {
			t.Errorf("InsertDefaultProvider(%v) = %v, want it to start with %q", tt.args, got, tt.want)
		}
	}
}

func TestProviderAliasesResolve(t *testing.T) {
	known := KnownProviders()
	for alias, want := range map[string]string{"microsoft365": "m365", "oci": "oraclecloud"} {
		got := InsertDefaultProvider([]string{alias, "--help"}, known)
		if got[0] != want {
			t.Errorf("alias %q resolved to %q, want %q", alias, got[0], want)
		}
	}
}

func TestHelpAndVersionKeepTheirPlace(t *testing.T) {
	known := KnownProviders()
	for _, flag := range []string{"-h", "--help", "-v", "--version"} {
		got := InsertDefaultProvider([]string{flag}, known)
		if len(got) != 1 || got[0] != flag {
			t.Errorf("InsertDefaultProvider(%q) = %v, want it untouched", flag, got)
		}
	}
}

func TestPluralFlagAliases(t *testing.T) {
	tests := []struct {
		args   []string
		verify func(*testing.T, *Options)
	}{
		{[]string{"aws", "--checks", "s3_one", "--list-checks"}, func(t *testing.T, o *Options) {
			if len(o.Selection.Checks) != 1 || o.Selection.Checks[0] != "s3_one" {
				t.Errorf("--checks did not alias to --check: %v", o.Selection.Checks)
			}
		}},
		{[]string{"aws", "--services", "s3,iam", "--list-checks"}, func(t *testing.T, o *Options) {
			if len(o.Selection.Services) != 2 {
				t.Errorf("--services did not alias to --service: %v", o.Selection.Services)
			}
		}},
		{[]string{"aws", "--severities", "high", "--list-checks"}, func(t *testing.T, o *Options) {
			if len(o.Selection.Severities) != 1 {
				t.Errorf("--severities did not alias to --severity: %v", o.Selection.Severities)
			}
		}},
		{[]string{"aws", "--output-modes", "csv", "--list-checks"}, func(t *testing.T, o *Options) {
			if len(o.Outputs.Formats) != 1 || o.Outputs.Formats[0] != "csv" {
				t.Errorf("--output-modes did not alias to --output-formats: %v", o.Outputs.Formats)
			}
		}},
		{[]string{"aws", "--filter-region", "eu-west-1", "--list-checks"}, func(t *testing.T, o *Options) {
			if len(o.Provider.AWS.Regions) != 1 {
				t.Errorf("--filter-region did not alias to --region: %v", o.Provider.AWS.Regions)
			}
		}},
	}

	for _, tt := range tests {
		runner, _, err := run(t, tt.args...)
		if err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		tt.verify(t, runner.opts)
	}
}

func TestCommonDefaults(t *testing.T) {
	runner, _, err := run(t, "aws", "--list-checks")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	o := runner.opts
	if got := strings.Join(o.Outputs.Formats, ","); got != "csv,json-ocsf,html" {
		t.Errorf("default output formats = %q", got)
	}
	if o.Logging.Level != "CRITICAL" {
		t.Errorf("default log level = %q, want CRITICAL", o.Logging.Level)
	}
	if o.Provider.AWS.SessionDuration != 3600 {
		t.Errorf("default session duration = %d, want 3600", o.Provider.AWS.SessionDuration)
	}
	if o.Provider.AWS.RoleSessionName != "ProwlerAssessmentSession" {
		t.Errorf("default role session name = %q", o.Provider.AWS.RoleSessionName)
	}
}

func TestOnlyLogsHidesBanner(t *testing.T) {
	runner, _, err := run(t, "aws", "--only-logs", "--list-checks")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !runner.opts.Outputs.NoBanner {
		t.Error("--only-logs must imply --no-banner")
	}
}

func TestMutuallyExclusiveSelection(t *testing.T) {
	_, _, err := run(t, "aws", "--check", "s3_one", "--service", "s3")
	if err == nil {
		t.Fatal("--check and --service must be mutually exclusive")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSeverityMayAccompanyService(t *testing.T) {
	if _, _, err := run(t, "aws", "--severity", "high", "--service", "s3", "--list-checks"); err != nil {
		t.Errorf("--severity with --service must be allowed: %v", err)
	}
}

func TestMutuallyExclusiveListing(t *testing.T) {
	_, _, err := run(t, "aws", "--list-checks", "--list-services")
	if err == nil {
		t.Fatal("listing flags must be mutually exclusive")
	}
}

func TestInvalidChoicesAreRejected(t *testing.T) {
	tests := [][]string{
		{"aws", "--status", "BROKEN"},
		{"aws", "--output-formats", "pdf"},
		{"aws", "--log-level", "TRACE"},
		{"aws", "--severity", "catastrophic"},
	}
	for _, args := range tests {
		if _, _, err := run(t, args...); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

func TestFailedChecksExitCode(t *testing.T) {
	runner := &recordingRunner{code: ExitFailedChecks}
	var out bytes.Buffer
	root := Root("5.18.0", runner, &out)
	root.SetArgs([]string{"aws"})
	err := root.Execute()
	if Code(err) != ExitFailedChecks {
		t.Errorf("exit code = %d, want %d", Code(err), ExitFailedChecks)
	}
}

func TestEveryProviderHasACommand(t *testing.T) {
	root := Root("5.18.0", &recordingRunner{}, &bytes.Buffer{})
	for _, provider := range Providers {
		found := false
		for _, cmd := range root.Commands() {
			if cmd.Name() == provider.Name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %s has no subcommand", provider.Name)
		}
	}
}
