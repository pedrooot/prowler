package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Providers are the cloud providers and components the CLI exposes, in the
// order the help epilog lists them.
var Providers = []struct {
	Name        string
	Description string
}{
	{"aws", "AWS Provider"},
	{"azure", "Azure Provider"},
	{"gcp", "GCP Provider"},
	{"kubernetes", "Kubernetes Provider"},
	{"m365", "Microsoft 365 Provider"},
	{"github", "GitHub Provider"},
	{"cloudflare", "Cloudflare Provider"},
	{"oraclecloud", "Oracle Cloud Infrastructure Provider"},
	{"openstack", "OpenStack Provider"},
	{"alibabacloud", "Alibaba Cloud Provider"},
	{"iac", "IaC Provider (Beta)"},
	{"llm", "LLM Provider (Beta)"},
	{"nhn", "NHN Provider (Unofficial)"},
	{"mongodbatlas", "MongoDB Atlas Provider (Beta)"},
}

// providerAliases are the alternative names accepted for a provider.
var providerAliases = map[string]string{
	"microsoft365": "m365",
	"oci":          "oraclecloud",
}

// DefaultProvider is what a bare invocation scans.
const DefaultProvider = "aws"

// Exit codes, kept identical to the Python CLI.
const (
	ExitOK           = 0
	ExitError        = 1
	ExitFailedChecks = 3
)

// Runner executes a resolved scan. It is the seam between the flag layer and
// the engine, so the command tree can be tested without a cloud account.
type Runner interface {
	Run(provider string, opts *Options) (exitCode int, err error)
}

// Root builds the whole command tree.
func Root(version string, runner Runner, out io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "prowler",
		Short:         "Prowler is an open source security tool for cloud security assessments",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.SetOut(out)
	root.SetErr(out)
	root.SetVersionTemplate("{{.Version}}\n")
	root.Flags().BoolP("version", "v", false, "show Prowler version")

	for _, provider := range Providers {
		root.AddCommand(providerCommand(provider.Name, provider.Description, runner))
	}
	root.AddCommand(dashboardCommand())
	root.SetHelpTemplate(helpTemplate())
	return root
}

func providerCommand(name, description string, runner Runner) *cobra.Command {
	opts := &Options{}
	cmd := &cobra.Command{
		Use:           name,
		Short:         description,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			if opts.Logging.OnlyLogs || opts.Listing.ChecksJSON {
				opts.Outputs.NoBanner = true
			}
			code, err := runner.Run(name, opts)
			if err != nil {
				return err
			}
			if code != ExitOK {
				return exitCode(code)
			}
			return nil
		},
	}
	for alias, target := range providerAliases {
		if target == name {
			cmd.Aliases = append(cmd.Aliases, alias)
		}
	}
	registerCommon(cmd.Flags(), opts, defaultOutputDirectory())
	registerProviderFlags(cmd.Flags(), name, opts)
	setProviderHelp(cmd, name, description)
	return cmd
}

func dashboardCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dashboard",
		Short: "Local dashboard",
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("the dashboard is served by the Python component; run `python -m dashboard`")
		},
	}
}

// exitCode carries a non-zero result up to main without turning it into an
// error message.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// Code extracts the process exit code an error should produce.
func Code(err error) int {
	if err == nil {
		return ExitOK
	}
	var code exitCode
	if ok := asExitCode(err, &code); ok {
		return int(code)
	}
	return ExitError
}

func asExitCode(err error, target *exitCode) bool {
	if e, ok := err.(exitCode); ok {
		*target = e
		return true
	}
	return false
}

func defaultOutputDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "output"
	}
	return filepath.Join(home, "output")
}

// InsertDefaultProvider rewrites an argument list that names no provider so
// it targets AWS, and resolves provider aliases, matching how the Python
// parser massages sys.argv.
func InsertDefaultProvider(args []string, known map[string]bool) []string {
	if len(args) == 0 {
		return []string{DefaultProvider}
	}
	first := args[0]
	if first == "-h" || first == "--help" || first == "-v" || first == "--version" {
		return args
	}
	if target, ok := providerAliases[first]; ok {
		return append([]string{target}, args[1:]...)
	}
	if known[first] {
		return args
	}
	return append([]string{DefaultProvider}, args...)
}

// KnownProviders is the lookup InsertDefaultProvider needs.
func KnownProviders() map[string]bool {
	known := make(map[string]bool, len(Providers)+len(providerAliases)+1)
	for _, p := range Providers {
		known[p.Name] = true
	}
	for alias := range providerAliases {
		known[alias] = true
	}
	known["dashboard"] = true
	return known
}

func helpTemplate() string {
	var b strings.Builder
	b.WriteString("{{.Short}}\n\nUsage:\n  prowler [provider|component] [flags]\n\nAvailable Cloud Providers:\n")
	for _, p := range Providers {
		fmt.Fprintf(&b, "    %-18s %s\n", p.Name, p.Description)
	}
	b.WriteString("\nAvailable components:\n    dashboard          Local dashboard\n")
	b.WriteString("\nTo see the different available options on a specific component, run:\n")
	b.WriteString("    prowler {provider|dashboard} -h|--help\n")
	b.WriteString("\nDetailed documentation at https://docs.prowler.com\n")
	return b.String()
}
