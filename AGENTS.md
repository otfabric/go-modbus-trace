# go-modbus-trace: agent handoff

Status (2026-10-15): **L0 to L4 are implemented** (v0.1.0): readers, link/IP/TCP, flows and reassembly, framing and roles, PDU decoding and validation, pairing, the event model, `trace.Scan`, `trace.Analyze`, `File.Frames`, `trace.Walk`, several files as one trace, `selection`, the analyzers, the timeline, MBCAP and sub-trace exports, JSON Schemas for every output, `trace/tracetest`, and every `mbtracectl` command. Open questions are at the end of `docs/DECISIONS.md`. This file is the entry point for Claude Code and other agents. Read it fully, then the documents it points to, before writing code.

## What this is

A pure-Go library and CLI that reads **packet traces** (pcap and pcapng files recorded by tcpdump, Wireshark, dumpcap or tshark), finds the **Modbus/TCP** traffic in them, and turns it into a typed, time-ordered **event stream**: connections, request/response transactions, exceptions, unanswered requests, gaps. On top of that it offers analysis (devices, units, poll patterns, address coverage, latency) and exports:

- **MBCAP** (via [otfabric/go-modbus-capture](https://github.com/otfabric/go-modbus-capture)) so that a *passive* capture of a real installation can be replayed by `modbusctl server replay` as a virtual device;
- a timeline as CSV or JSON Lines;
- a filtered **sub-trace** as pcapng.

It never captures live and never sends anything: the trace is its only input. The desktop application [otfabric/modbus-trace-explorer](https://github.com/otfabric/modbus-trace-explorer) is built on this library; the CLI `mbtracectl` is the headless way to use it on a gateway or in CI.

## Read these, in this order

1. `docs/REQUIREMENTS.md`: what to build, numbered requirements (L1..), acceptance tests (LA1..).
2. `docs/ARCHITECTURE.md`: pipeline, packages, algorithms, event model, API sketch, CLI, milestones.
3. `docs/MBCAP-EXPORT.md`: how events become MBCAP samples, admission rules, the exclusion report, replay caveats.
4. `docs/TESTING.md`: synthetic trace builder, fixtures, oracles, fuzzing, performance.
5. `docs/DECISIONS.md`: the L0 decision record (gopacket versus own code, measurements, framing reconciliation) and the questions still open with the user.
6. In sibling checkouts (read-only inputs, do not modify them): `go-modbus-capture/docs/` (FORMAT.md, concepts.md, library.md, cli.md), `go-modbus/spec/MODBUS-SPEC.md` (Modbus Application Protocol V1.1b), `modbusctl/internal/replay/` and `modbusctl/cmd/server/` (what a replay does with the samples we write).

## Decisions that are settled (do not relitigate without asking the user)

- **Offline only.** The library opens trace files and readers. It never opens a network socket, never captures live, never talks Modbus. Enforced by a lint rule (`forbidigo`/`depguard`): no `net.Dial*`, `net.Listen*`, `net/http`, `os/exec`, `syscall` raw sockets, and no cgo.
- **Pure Go, `CGO_ENABLED=0`**, builds and tests on linux/amd64, linux/arm64, linux/arm (v7), darwin/arm64, darwin/amd64, windows/amd64, windows/arm64. No libpcap, no Npcap.
- **Inputs**: classic pcap (microsecond and nanosecond magic, both byte orders) and pcapng, plain or gzip-compressed, from a file or a stream. tcpdump writes classic pcap; Wireshark and dumpcap write pcapng by default. Support both.
- **Streaming, bounded memory.** Memory use must not grow with trace size. Every table has a limit and a counter for what the limit dropped. A multi-GB trace must work.
- **MBCAP only through go-modbus-capture.** No local codec, no second format, no compatibility layer. Every sample passes the library's own rules (`capture.Checker` / the writers' errors); the exporter additionally validates what the library cannot (request/response consistency). Captures hold reads only: writes, FC23, vendor functions and state-changing diagnostics are never exported (they stay visible in the timeline).
- **The trace is the source of truth.** Events carry *provenance references* (frame numbers, file offsets, payload ranges) instead of copies of the bytes. Exports and detail views re-read the trace through the library. An application index is a disposable cache of pointers.
- **Exports are reproducible.** Same trace, same options, same library version: byte-identical output. No wall-clock time, no random IDs, no export timestamp in any output.
- **Raw values only.** The library never turns register words into engineering units. Raw words, bits and bytes are authoritative; interpretation is a display concern of the applications.
- **The only clock is the trace's timestamps.** `time.Now` is not used in the pipeline (only for CLI progress output).
- **Untrusted input.** Traces come from vendors, customers and the field. Every length is bounded, the decoders are fuzzed, and no input may panic the library or exhaust memory (`docs/TESTING.md`).
- **Dependencies are minimal.** Standard library and go-modbus-capture for the core. A packet-decoding or reassembly dependency (the maintained `gopacket/gopacket` fork) was allowed only if the L0 spike (`docs/ARCHITECTURE.md` section 12) showed it meets the requirements CGO-free on every target. It did not win (`docs/DECISIONS.md` D1-D3): the reader, link parsing, reassembly and pcapng writer are our own, and lint bans gopacket. The CLI may use cobra (as modbusctl does). No SQLite, no database: indexes belong to the application.

## Hard rules

- No Modbus write function code is ever produced, and no sample for one is written to MBCAP (the admission matrix in `docs/MBCAP-EXPORT.md`).
- Never validate TCP or IP checksums: captures taken on the sending host show unverified checksums because of offload. Count them if cheap, never drop on them.
- Never modify an input file. Write outputs to a temporary file next to the destination and rename on success (as `mbcapctl` does); refuse an output that is also an input.
- Never ship customer traces. Fixtures are synthetic (`trace/tracetest`) or captured from OT Fabric's own test rigs, small, and listed with their origin in `testdata/README.md`.
- No `panic` across the public API. A malformed packet is a counted quality event, not an error, unless the file itself is unreadable.
- SPDX header `// SPDX-License-Identifier: MIT` on every Go file; MIT license.
- Pin the exact dependency versions in `go.mod`; record the date they were resolved in `docs/ARCHITECTURE.md`. Recheck the newest compatible releases at the start of the work.
- Do not commit unless the user asks. When committing, follow the user's commit conventions.

## Conventions to copy from sibling repos (go-modbus-capture, modbusctl)

`Makefile` with `make check` (format, vet, golangci-lint, vulnerability scan, race tests, coverage gate), `.golangci.yml`, `codecov.yml`, `CONTRIBUTING.md`, `SECURITY.md`, `RELEASE.md`, GitHub Actions on **native-architecture runners, never under QEMU** (one reusable `build.yml`; releases by the manually started Release workflow with the organisation's conventions: input `bump` = none, patch, minor or major, notes from the `## v<version>` section of `RELEASE.md`). CLI conventions from `modbusctl`: cobra, `MBTRACECTL_*` environment variables, `docs/exitcodes.md`, `docs/json-output.md`. Release artifacts: `mbtracectl` archives per OS and architecture with SHA-256 checksums, as `mbcapctl` does.

## Target repo layout

```
trace/              package trace: Open, File, Scan, Analyze, Options, Sink (the facade the apps use)
trace/tracetest/    synthetic trace builder for tests (also used by the application's tests)
model/              Event, Connection, Transaction, ADU, Status, QualityFlags, Endpoint, Device (JSON tags; schema in docs/schema)
selection/          Selection (device, unit, client, function, status, time, connection) and its predicate
mbtcp/              MBAP framer with resync, PDU decoders and validators, function coverage table
analyze/            streaming, bounded aggregators: overview, devices, patterns, coverage, latency, volatility
export/mbcapexport/ MBCAP exporter and exclusion report (package mbcapexport; avoids the clash with go-modbus-capture's mbcap)
export/timeline/    CSV and JSON Lines writers
export/subtrace/    pcapng sub-trace extractor
internal/pcapio/    pcap and pcapng readers (gzip, stream), pcapng writer, packet record with provenance
internal/link/      link layers, VLAN, IPv4/IPv6, TCP header parsing, IP fragment reassembly
internal/flow/      connection tracking, epochs, per-direction TCP reassembly
internal/pair/      request/response correlation
cmd/mbtracectl/     the CLI
docs/               the four documents above, schema/ (JSON Schemas), COVERAGE.md, REPLAY-WORKFLOW.md
testdata/           small traces + golden event files (README.md lists origins)
```

## Answered by the user

- **No live capture, ever** (2026-10-15): tcpdump and Wireshark do that better. The product analyses traces and exports.
- **MBCAP export is required**, because it is how a passive capture becomes a replayable virtual device.
- **Separate library** (2026-10-15): the engine lives here, not inside the application, so the CLI, the application and possibly modbusctl can share it.
- The gateways that produce traces run Debian 11, 12 and 13 on amd64, arm64 and armv7: `mbtracectl` must run there unchanged (static binary).
- Releases are unsigned (no macOS or Windows signing identity): checksums and CI provenance attestations.

## Open questions

None blocking. L0 settled gopacket versus own code (own) and IPv6 fragments (kept), see `docs/DECISIONS.md`. Answered by the user on 2026-10-15: CLI name `mbtracectl`, armv7 cross-compiled only, foreign frames skipped by length, IPv6 fragments MUST, the guide provided locally. Also answered: a total reassembly budget, ACK-based gaps and the ACK-informed midstream start (Q4), and `--warn-replay-memory` with a 1 GiB default (Q6). Open: Q8–Q10 at the end of `docs/DECISIONS.md` (a real fixture, TID-reuse semantics, decoded views in the JSON Lines timeline); none blocks v0.1.0.

## Milestones (details in docs/ARCHITECTURE.md section 12)

L0 spike and decision record -> L1 reader, link/IP/TCP, flows, reassembly, framing, `info` and `flows` -> L2 PDU decoders, pairing, quality model, `summary` and `timeline` -> L3 MBCAP export, report, replay end-to-end with `mbcapctl` and `modbusctl` -> L4 sub-trace, analyzers complete, schemas, v0.1.0.

## Definition of done for any change

`make check` passes; a change to a type in `model/` is made in `docs/schema/` too; new behavior has a test (synthetic trace first, real fixture second); every new quality condition has a counter, a flag and a documented meaning in `docs/ARCHITECTURE.md`; no new dependency without a recorded reason; fuzz targets still pass their seed corpus.
