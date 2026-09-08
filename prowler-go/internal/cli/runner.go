package cli

import (
	"fmt"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
	"github.com/prowler-cloud/prowler/prowler-go/pkg/compliance"
)

// runner is the default Runner: it resolves the requested checks and, once
// the provider layer lands, hands them to the scan engine.
type runner struct {
	version  string
	registry *check.Registry
}

func NewRunner(version string) Runner {
	return &runner{version: version, registry: check.Global()}
}

func (r *runner) Run(provider string, opts *Options) (int, error) {
	if handled, err := r.list(provider, opts); handled {
		return ExitOK, err
	}
	return ExitError, fmt.Errorf("scanning %s is not wired up yet in the Go build", provider)
}

// list answers the --list-* modes, which need no credentials.
func (r *runner) list(provider string, opts *Options) (bool, error) {
	switch {
	case opts.Listing.Services:
		return true, printLines(r.registry.Services(provider))
	case opts.Listing.Categories:
		return true, printLines(r.registry.Categories(provider))
	case opts.Listing.Checks:
		return true, printLines(r.registry.ForProvider(provider))
	case opts.Listing.Compliance:
		set, err := compliance.ForProvider(provider)
		if err != nil {
			return true, err
		}
		return true, printLines(set.Names())
	case len(opts.Listing.ComplianceRequirements) > 0:
		return true, r.listRequirements(provider, opts.Listing.ComplianceRequirements)
	}
	return false, nil
}

// listRequirements prints each requirement of the named frameworks together
// with the checks that cover it.
func (r *runner) listRequirements(provider string, frameworks []string) error {
	set, err := compliance.ForProvider(provider)
	if err != nil {
		return err
	}
	for _, name := range frameworks {
		framework, ok := set[name]
		if !ok {
			return fmt.Errorf("invalid compliance framework specified: %s", name)
		}
		fmt.Printf("Framework: %s\nVersion: %s\nProvider: %s\n\n", framework.Framework, framework.Version, framework.Provider)
		for _, requirement := range framework.Requirements {
			fmt.Printf("Requirement Id: %s\n", requirement.Id)
			fmt.Printf("Description: %s\n", requirement.Description)
			fmt.Printf("Checks:\n")
			for _, id := range requirement.Checks {
				fmt.Printf("\t- %s\n", id)
			}
			fmt.Println()
		}
	}
	return nil
}

func printLines(values []string) error {
	for _, value := range values {
		if _, err := fmt.Println(value); err != nil {
			return err
		}
	}
	return nil
}
