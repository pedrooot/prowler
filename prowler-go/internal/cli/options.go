// Package cli defines the prowler command tree and the options its flags fill.
package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
)

// Options is everything the common flags collect, shared by every provider
// subcommand.
type Options struct {
	Outputs     OutputOptions
	Logging     LoggingOptions
	Selection   SelectionOptions
	Listing     ListingOptions
	Mutelist    string
	ConfigFile  string
	FixerConfig string

	CustomChecksMetadataFile string
	Provider                 ProviderOptions
	ThirdParty               ThirdPartyOptions
}

// OutputOptions mirrors the "Outputs" argument group.
type OutputOptions struct {
	Status          []string
	Formats         []string
	Filename        string
	Directory       string
	Verbose         bool
	IgnoreExitCode3 bool
	NoBanner        bool
	NoColor         bool
	UnixTimestamp   bool
}

// LoggingOptions mirrors the "Logging" argument group.
type LoggingOptions struct {
	Level    string
	File     string
	OnlyLogs bool
}

// SelectionOptions mirrors the check selection and exclusion groups.
type SelectionOptions struct {
	Checks               []string
	ChecksFile           string
	Services             []string
	Severities           []string
	ComplianceFrameworks []string
	Categories           []string
	ChecksFolder         string

	ExcludedChecks     []string
	ExcludedChecksFile string
	ExcludedServices   []string
}

// ListingOptions mirrors the "List checks" argument group. The flags are
// mutually exclusive.
type ListingOptions struct {
	Checks                 bool
	ChecksJSON             bool
	Services               bool
	Compliance             bool
	ComplianceRequirements []string
	Categories             bool
	Fixers                 bool
}

// ThirdPartyOptions mirrors the "3rd Party Integrations" group.
type ThirdPartyOptions struct {
	Shodan string
	Slack  bool
}

// AvailableOutputFormats is the set --output-formats accepts.
var AvailableOutputFormats = []string{"csv", "json-asff", "json-ocsf", "html"}

// DefaultOutputFormats is what a run produces when the flag is not given.
var DefaultOutputFormats = []string{"csv", "json-ocsf", "html"}

// AvailableStatuses is the set --status accepts.
var AvailableStatuses = []string{"PASS", "FAIL", "MANUAL", "MUTED"}

// AvailableLogLevels is the set --log-level accepts.
var AvailableLogLevels = []string{"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

// AvailableSeverities is the set --severity accepts.
var AvailableSeverities = []string{"critical", "high", "medium", "low", "informational"}

// registerCommon adds every flag shared by all provider subcommands, in the
// same groups and with the same defaults and aliases as the Python parser.
func registerCommon(fs *pflag.FlagSet, o *Options, defaultOutputDir string) {
	out := &o.Outputs
	fs.StringSliceVar(&out.Status, "status", nil,
		fmt.Sprintf("Filter by the status of the findings %v", AvailableStatuses))
	fs.StringSliceVarP(&out.Formats, "output-formats", "M", DefaultOutputFormats,
		"Output modes, by default csv and json-oscf are saved. When using AWS Security Hub integration, json-asff output is also saved.")
	fs.StringVarP(&out.Filename, "output-filename", "F", "",
		"Custom output report name without the file extension, if not specified will use default output/prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format")
	fs.StringVarP(&out.Directory, "output-directory", "o", defaultOutputDir,
		"Custom output directory, by default the folder where Prowler is stored")
	fs.BoolVar(&out.Verbose, "verbose", false, "Runs showing all checks executed and results")
	fs.BoolVarP(&out.IgnoreExitCode3, "ignore-exit-code-3", "z", false, "Failed checks do not trigger exit code 3")
	fs.BoolVarP(&out.NoBanner, "no-banner", "b", false, "Hide Prowler banner")
	fs.BoolVar(&out.NoColor, "no-color", false, "Disable color codes in output")
	fs.BoolVar(&out.UnixTimestamp, "unix-timestamp", false,
		"Set the output timestamp format as unix timestamps instead of iso format timestamps (default mode).")

	log := &o.Logging
	fs.StringVar(&log.Level, "log-level", "CRITICAL", "Select Log Level")
	fs.StringVar(&log.File, "log-file", "", "Set log file name")
	fs.BoolVar(&log.OnlyLogs, "only-logs", false,
		"Print only Prowler logs by the stdout. This option sets --no-banner.")

	sel := &o.Selection
	fs.StringSliceVarP(&sel.Checks, "check", "c", nil, "List of checks to be executed.")
	fs.StringVarP(&sel.ChecksFile, "checks-file", "C", "",
		"JSON file containing the checks to be executed. See config/checklist_example.json")
	fs.StringSliceVarP(&sel.Services, "service", "s", nil, "List of services to be executed.")
	fs.StringSliceVar(&sel.Severities, "severity", nil,
		fmt.Sprintf("Severities to be executed %v", AvailableSeverities))
	fs.StringSliceVar(&sel.ComplianceFrameworks, "compliance", nil,
		"Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: cis_3.0_aws)")
	fs.StringSliceVar(&sel.Categories, "category", nil, "List of categories to be executed.")
	fs.StringVarP(&sel.ChecksFolder, "checks-folder", "x", "",
		"Specify external directory with custom checks (each check must have a folder with the required files, see more in https://docs.prowler.com/user-guide/cli/tutorials/misc#custom-checks-in-prowler).")

	fs.StringSliceVarP(&sel.ExcludedChecks, "excluded-check", "e", nil, "Checks to exclude")
	fs.StringVar(&sel.ExcludedChecksFile, "excluded-checks-file", "",
		"JSON file containing the checks to be excluded. See config/checklist_example.json")
	fs.StringSliceVar(&sel.ExcludedServices, "excluded-service", nil, "Services to exclude")

	list := &o.Listing
	fs.BoolVarP(&list.Checks, "list-checks", "l", false, "List checks")
	fs.BoolVar(&list.ChecksJSON, "list-checks-json", false,
		"Output a list of checks in json format to use with --checks-file option")
	fs.BoolVar(&list.Services, "list-services", false, "List covered services by given provider")
	fs.BoolVar(&list.Compliance, "list-compliance", false, "List all available compliance frameworks")
	fs.StringSliceVar(&list.ComplianceRequirements, "list-compliance-requirements", nil,
		"List requirements and checks per compliance framework")
	fs.BoolVar(&list.Categories, "list-categories", false, "List the available check's categories")
	fs.BoolVar(&list.Fixers, "list-fixer", false, "List fixers available for the provider")

	fs.StringVarP(&o.Mutelist, "mutelist-file", "w", "",
		"Path for mutelist YAML file. See example prowler/config/<provider>_mutelist.yaml for reference and format. For AWS provider, it also accepts AWS DynamoDB Table, Lambda ARNs or S3 URIs, see more in https://docs.prowler.com/user-guide/cli/tutorials/mutelist")
	fs.StringVar(&o.ConfigFile, "config-file", "", "Set configuration file path")
	fs.StringVar(&o.FixerConfig, "fixer-config", "", "Set configuration fixer file path")
	fs.StringVar(&o.CustomChecksMetadataFile, "custom-checks-metadata-file", "",
		"Path for the custom checks metadata YAML file. See example prowler/config/custom_checks_metadata_example.yaml for reference and format. See more in https://docs.prowler.com/user-guide/cli/tutorials/custom-checks-metadata/")

	fs.StringVarP(&o.ThirdParty.Shodan, "shodan", "N", "",
		"Check if any public IPs in your Cloud environments are exposed in Shodan.")
	fs.BoolVar(&o.ThirdParty.Slack, "slack", false,
		"Send a summary of the execution with a Slack APP in your channel. Environment variables SLACK_API_TOKEN and SLACK_CHANNEL_NAME are required (see more in https://docs.prowler.com/user-guide/cli/tutorials/integrations#configuration-of-the-integration-with-slack/).")

	registerAliases(fs)
}

// flagAliases are the plural and legacy spellings the Python parser accepts
// for the same option.
var flagAliases = map[string]string{
	"checks":            "check",
	"services":          "service",
	"severities":        "severity",
	"categories":        "category",
	"excluded-checks":   "excluded-check",
	"excluded-services": "excluded-service",
	"output-modes":      "output-formats",
	"list-checks-json":  "list-checks-json",
	"list-compliances":  "list-compliance",
	"list-fixers":       "list-fixer",
	"list-remediations": "list-fixer",
	"excluded-check":    "excluded-check",
}

func registerAliases(fs *pflag.FlagSet) {
	fs.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if target, ok := flagAliases[name]; ok {
			return pflag.NormalizedName(target)
		}
		return pflag.NormalizedName(name)
	})
}

// Validate rejects flag combinations the parser cannot honour.
func (o *Options) Validate() error {
	if err := oneOf("--status", o.Outputs.Status, AvailableStatuses, strings.ToUpper); err != nil {
		return err
	}
	if err := oneOf("--output-formats", o.Outputs.Formats, AvailableOutputFormats, strings.ToLower); err != nil {
		return err
	}
	if err := oneOf("--log-level", []string{o.Logging.Level}, AvailableLogLevels, strings.ToUpper); err != nil {
		return err
	}
	if err := oneOf("--severity", o.Selection.Severities, AvailableSeverities, strings.ToLower); err != nil {
		return err
	}
	if err := o.Selection.validateExclusivity(); err != nil {
		return err
	}
	return o.Listing.validateExclusivity()
}

// validateExclusivity enforces the mutually exclusive group around --check.
func (s SelectionOptions) validateExclusivity() error {
	set := map[string]bool{
		"--check":       len(s.Checks) > 0,
		"--checks-file": s.ChecksFile != "",
		"--service":     len(s.Services) > 0,
		"--compliance":  len(s.ComplianceFrameworks) > 0,
		"--category":    len(s.Categories) > 0,
	}
	// --service may accompany --severity, which is why the Python parser
	// keeps severity outside the exclusive group.
	return atMostOne("check selection", set)
}

func (l ListingOptions) validateExclusivity() error {
	return atMostOne("listing", map[string]bool{
		"--list-checks":                  l.Checks,
		"--list-checks-json":             l.ChecksJSON,
		"--list-services":                l.Services,
		"--list-compliance":              l.Compliance,
		"--list-compliance-requirements": len(l.ComplianceRequirements) > 0,
		"--list-categories":              l.Categories,
		"--list-fixer":                   l.Fixers,
	})
}

func atMostOne(group string, flags map[string]bool) error {
	var given []string
	for name, set := range flags {
		if set {
			given = append(given, name)
		}
	}
	if len(given) > 1 {
		return fmt.Errorf("%s: %s are mutually exclusive", group, strings.Join(sorted(given), " and "))
	}
	return nil
}

func oneOf(flag string, values, allowed []string, normalize func(string) string) error {
	for _, value := range values {
		if value == "" {
			continue
		}
		if !containsString(allowed, normalize(value)) {
			return fmt.Errorf("%s: invalid choice %q (choose from %s)", flag, value, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// Severities returns the parsed severities, assuming Validate already ran.
func (s SelectionOptions) ParsedSeverities() []check.Severity {
	out := make([]check.Severity, 0, len(s.Severities))
	for _, value := range s.Severities {
		severity, err := check.ParseSeverity(value)
		if err != nil {
			continue
		}
		out = append(out, severity)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
