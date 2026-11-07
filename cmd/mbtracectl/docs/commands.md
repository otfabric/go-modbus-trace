# mbtracectl commands

The flags of every command, as `mbtracectl <command> --help` lists them.
`--json` and `-h`/`--help` are accepted by every command.

## Global

| Flag | Meaning |
|---|---|
| `--json` | Write JSON ([JSON output](../../../docs/json-output.md)) instead of text |

## Role flags

`info` and `flows` decide which end of a connection is the client and which
the server:

| Flag | Default | Meaning |
|---|---|---|
| `--client` | | Endpoints that are clients: ip or ip:port |
| `--server` | | Endpoints that are servers: ip or ip:port (overrides every other rule) |
| `--server-port` | `502` | TCP ports taken as Modbus servers when no handshake decides |

## Selection flags

`summary`, `timeline`, `export timeline`, `export mbcap` and (the connection
and time flags only) `extract` select transactions:

| Flag | Default | Meaning |
|---|---|---|
| `--conn` | | Connection IDs (as `flows` lists them) |
| `--client` | | Client addresses |
| `--server` | | Server endpoints: ip or ip:port |
| `--server-port` | `502` | TCP ports taken as Modbus servers when no handshake decides |
| `--unit` | | Unit IDs |
| `--fc` | | Function codes, decimal or 0x hex |
| `--class` | | Classes: `read`, `write`, `other` |
| `--status` | | Statuses: `ok`, `exception`, `unanswered`, `orphan_response`, `ambiguous`, `malformed`, `uncertain` |
| `--flag` | | Quality flags a transaction must have |
| `--no-flag` | | Quality flags a transaction must not have |
| `--range` | | Address range touched: `space:start-end` (`holding:4096-4200`) |
| `--from` | | Start of the time window, as an offset from the first packet (for example `10m`) |
| `--to` | | End of the time window, as an offset from the first packet |
| `--from-time` | | Start of the time window, RFC 3339 |
| `--to-time` | | End of the time window, RFC 3339 |
| `--slow` | `1s` | Latency above which a transaction is flagged slow |

## info

`mbtracectl info TRACE...`: the role flags.

## flows

`mbtracectl flows TRACE...`: the role flags, and:

| Flag | Default | Meaning |
|---|---|---|
| `--all` | `false` | List every TCP flow |
| `--min-score` | `0.5` | Also list flows scoring at least this (0..1) |

By default only flows classed `modbus_tcp`, or scoring at least `--min-score`,
are listed.

## summary

`mbtracectl summary TRACE...`: the selection flags, and:

| Flag | Default | Meaning |
|---|---|---|
| `--top` | `10` | Poll patterns to list in the text output |

## timeline

`mbtracectl timeline TRACE...`: the selection flags, and:

| Flag | Default | Meaning |
|---|---|---|
| `--format` | `text` | `text`, `csv` or `jsonl` |
| `--order` | `time` | `time` (bounded reorder window) or `file` (order of determination) |
| `--window` | `1m0s` | Reorder window of `--order time`, in trace time |

## export timeline

`mbtracectl export timeline TRACE... -o OUT`: the selection flags, `--order`
and `--window` as for `timeline`, and:

| Flag | Default | Meaning |
|---|---|---|
| `-o`, `--output` | | Output file, or `-` for stdout |
| `--format` | from the extension | `csv` or `jsonl` |

## export mbcap

`mbtracectl export mbcap TRACE... -o OUT`: the selection flags, and:

| Flag | Default | Meaning |
|---|---|---|
| `-o`, `--output` | | Output capture, or `-` for JSON Lines on stdout |
| `--format` | from the output name | `mbcap`, `jsonl` or `csv` |
| `--name` | | Label a target: `ip:port/unit=Label` (repeatable) |
| `--no-exceptions` | `false` | Leave exception responses out |
| `--change-only` | `false` | Write a change-only capture (repeated identical responses are dropped) |
| `--report` | | Write the export report (JSON) to this file |
| `--tick-ns` | `1000` | Tick size in nanoseconds (1 to 1e9) |
| `--block-samples` | `256` | Binary: samples per data block |
| `--compression` | `deflate` | Binary data block compression: `deflate` or `none` |
| `--warn-replay-memory` | `1GiB` | Warn when a replay would need more memory than this (`0`: never) |

What is exported and why something is left out:
[docs/MBCAP-EXPORT.md](../../../docs/MBCAP-EXPORT.md).

## extract

`mbtracectl extract TRACE... -o OUT.pcapng`: `--conn`, `--client`, `--server`,
`--server-port`, `--slow` and the time window flags (`--from`, `--to`,
`--from-time`, `--to-time`), and:

| Flag | Default | Meaning |
|---|---|---|
| `-o`, `--output` | | Output pcapng file, or `-` for stdout |

Either end of a connection may match `--server` or `--client`.

## version

`mbtracectl version`: no flags of its own. It prints one line:

```text
mbtracectl 0.7.0 (tag v0.7.0, commit 1802d0f9afe8642d1e278120b76fcdfac967cb9e, built 2026-11-05T15:41:49Z, go-modbus-capture 0.1.0, go1.26.0, linux/amd64)
```

The OT Fabric libraries it is built on follow the build date (not
go-modbus-trace itself, whose version is the version). A build that was not
released (`go build`, `go install`) prints `dev` or the module version of
`go install …@vX.Y.Z`, the VCS revision (with `-dirty` for uncommitted
changes) and leaves out the tag. With `--json` (or `MBTRACECTL_JSON=1`) it writes the same
as one line of JSON ([version-2](../../../docs/schema/version-2.schema.json)).
