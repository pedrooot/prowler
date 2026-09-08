# prowler-go

Go implementation of the Prowler CLI and SDK. See
[`docs/go-migration/PLAN.md`](../docs/go-migration/PLAN.md) for the migration
plan this tree follows.

## Layout

| Path | Purpose |
|---|---|
| `cmd/prowler` | the binary |
| `internal/cli` | command and flag definitions |
| `internal/codegen` | mirrors check metadata into the Go tree |
| `pkg/check` | metadata model, `Check` contract, registry |
| `pkg/finding` | the streamed result of a check |
| `pkg/scan` | selection, planning and the execution engine |
| `pkg/output` | report writers |
| `pkg/provider/<name>` | provider session, services and checks |

## Working on it

```sh
make codegen   # refresh metadata bundles from the Python tree
make build
make test
```

`make codegen` reads the `*.metadata.json` files that live next to the Python
checks, validates every one of them against `pkg/check`, and writes one
embedded bundle per provider. The metadata files stay the single source of
truth shared by both implementations.

## Design notes

Services are collected lazily and reference counted: a service is fetched the
first time a check reads it and dropped as soon as the last check that
declared it in `Requires()` has finished. Findings are streamed to the writers
through a bounded channel and are never accumulated, so the peak memory of a
scan tracks the heaviest service in flight rather than the size of the result.
