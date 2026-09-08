package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// group collects the flags argparse showed under one heading, so the Go help
// reads the same way the Python one does.
type group struct {
	title string
	flags []string
}

// commonGroups lists the shared headings in the order the Python parser
// declares them.
var commonGroups = []group{
	{"Outputs", []string{
		"status", "output-formats", "output-filename", "output-directory",
		"verbose", "ignore-exit-code-3", "no-banner", "no-color", "unix-timestamp",
	}},
	{"Logging", []string{"log-level", "log-file", "only-logs"}},
	{"Specify checks/services to run", []string{
		"check", "checks-file", "service", "severity", "compliance", "category", "checks-folder",
	}},
	{"Exclude checks/services to run", []string{
		"excluded-check", "excluded-checks-file", "excluded-service",
	}},
	{"List checks/services/categories/compliance-framework checks", []string{
		"list-checks", "list-checks-json", "list-services", "list-compliance",
		"list-compliance-requirements", "list-categories", "list-fixer",
	}},
	{"Mutelist", []string{"mutelist-file"}},
	{"Configuration", []string{"config-file", "fixer-config"}},
	{"Custom Checks Metadata", []string{"custom-checks-metadata-file"}},
	{"3rd Party Integrations", []string{"shodan", "slack"}},
}

// setProviderHelp renders a provider subcommand's help with the flags split
// into the same groups as the Python CLI, provider flags first.
func setProviderHelp(cmd *cobra.Command, provider, description string) {
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n\nUsage:\n  prowler %s [flags]\n", description, provider)

		grouped := make(map[string]bool)
		for _, g := range commonGroups {
			for _, name := range g.flags {
				grouped[name] = true
			}
		}

		if providerFlags := collectUngrouped(c.Flags(), grouped); len(providerFlags) > 0 {
			writeGroup(&b, description, providerFlags)
		}
		for _, g := range commonGroups {
			writeGroup(&b, g.title, resolveFlags(c.Flags(), g.flags))
		}

		fmt.Fprint(c.OutOrStdout(), b.String())
	})
}

func collectUngrouped(fs *pflag.FlagSet, grouped map[string]bool) []*pflag.Flag {
	var flags []*pflag.Flag
	fs.VisitAll(func(f *pflag.Flag) {
		if !grouped[f.Name] && f.Name != "help" {
			flags = append(flags, f)
		}
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}

func resolveFlags(fs *pflag.FlagSet, names []string) []*pflag.Flag {
	flags := make([]*pflag.Flag, 0, len(names))
	for _, name := range names {
		if f := fs.Lookup(name); f != nil {
			flags = append(flags, f)
		}
	}
	return flags
}

func writeGroup(b *strings.Builder, title string, flags []*pflag.Flag) {
	if len(flags) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", title)
	for _, f := range flags {
		fmt.Fprintf(b, "%s\n", formatFlag(f))
	}
}

func formatFlag(f *pflag.Flag) string {
	var name strings.Builder
	name.WriteString("  ")
	if f.Shorthand != "" {
		fmt.Fprintf(&name, "-%s, ", f.Shorthand)
	} else {
		name.WriteString("    ")
	}
	fmt.Fprintf(&name, "--%s", f.Name)
	if kind := valueKind(f); kind != "" {
		fmt.Fprintf(&name, " %s", kind)
	}

	line := name.String()
	if len(line) < 34 {
		line += strings.Repeat(" ", 34-len(line))
	} else {
		line += "\n" + strings.Repeat(" ", 34)
	}
	return line + firstLine(f.Usage)
}

func valueKind(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "bool":
		return ""
	case "stringSlice":
		return "strings"
	case "int":
		return "int"
	default:
		return "string"
	}
}

func firstLine(usage string) string {
	if i := strings.IndexByte(usage, '\n'); i >= 0 {
		return usage[:i]
	}
	return usage
}
