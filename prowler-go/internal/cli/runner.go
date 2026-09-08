package cli

import (
	"fmt"

	"github.com/prowler-cloud/prowler/prowler-go/pkg/check"
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
	}
	return false, nil
}

func printLines(values []string) error {
	for _, value := range values {
		if _, err := fmt.Println(value); err != nil {
			return err
		}
	}
	return nil
}
