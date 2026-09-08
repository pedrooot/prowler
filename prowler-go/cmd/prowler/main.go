// Command prowler runs cloud security assessments.
package main

import (
	"fmt"
	"os"

	"github.com/prowler-cloud/prowler/prowler-go/internal/cli"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "5.18.0"

func main() {
	os.Args = append(os.Args[:1], cli.InsertDefaultProvider(os.Args[1:], cli.KnownProviders())...)

	root := cli.Root(version, cli.NewRunner(version), os.Stdout)
	if err := root.Execute(); err != nil {
		code := cli.Code(err)
		if code == cli.ExitError {
			fmt.Fprintln(os.Stderr, "prowler:", err)
		}
		os.Exit(code)
	}
}
