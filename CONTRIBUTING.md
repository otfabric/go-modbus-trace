# Contributing to go-modbus-trace

Thank you for your interest in contributing. Read [`AGENTS.md`](AGENTS.md) first: it lists the settled decisions and the hard rules, and points to the requirements and the architecture in [`docs/`](docs/).

## Development Setup

### Prerequisites

- Go 1.23+ (see [go.mod](go.mod)); CI and releases build with the current stable Go
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/) v2 and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the checks
- No privileges, no network and no real traces: the tests build their traces with `trace/tracetest`
- Optional: `tshark` for the oracle test, and the pinned `mbcapctl` and `modbusctl` for the replay test (`make tools`)

### Build & Test

```sh
make check     # format, mod check, lint, vet, vulnerability scan, race tests, cross-builds for every target
make build     # ./bin/mbtracectl
make fuzz      # every fuzz target for FUZZ_TIME (default 30s)
make replay    # trace -> export mbcap -> mbcapctl verify -> modbusctl replay (needs `make tools`)
make bench     # Scan and Analyze throughput
make golden    # regenerate docs/COVERAGE.md, docs/schema/ and testdata/plant.pcapng
```

Run `make` (or `make help`) for the full list of targets. `make interop` compares the decoder with Wireshark's.

## Rules

- **Offline only.** The library never captures live, never opens a socket and never reads the wall clock for anything it outputs. `depguard`, `forbidigo` and `internal/policy` enforce it.
- **Pure Go**, `CGO_ENABLED=0`, on every target in the Makefile's `TARGETS`.
- **Bounded memory** at default limits for any trace size: every table has a cap and a counter (`docs/ARCHITECTURE.md` section 2).
- **Hostile input:** readers and decoders never panic and never allocate beyond their limits; a new parser comes with a fuzz target.
- **No customer traces** in the repository, ever (`testdata/README.md`).
- **Ground truth, not self-comparison:** a new quality condition, reason code or flag comes with a synthetic scenario that produces it (`docs/TESTING.md`).
- **Schemas follow the types:** a change to a JSON type needs `make golden` and a reviewed diff of `docs/schema/`.
- **Docs in the same change:** if a document is wrong, fix it in the same pull request and say so.

## Pull Requests

- Branch from `main`; one open pull request at a time, targeting `main`.
- `make check` passes locally; CI runs it on every supported Go version and builds and tests on every target's native runner.
- Add a `## Unreleased` entry to [`RELEASE.md`](RELEASE.md) for anything a user notices.
