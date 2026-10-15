# go-modbus-trace Releases

## v0.1.0

**Date:** 2026-10-15
**Previous release:** none

### Summary

The first release. Read a pcap or pcapng trace, find the Modbus/TCP traffic in it, and get a typed, time-ordered view of every connection and transaction. Analyze devices, poll patterns and address coverage, and export a timeline, a sub-trace for Wireshark, and an MBCAP capture that `modbusctl` replays as a virtual device. Pure Go, offline, bounded memory, deterministic output, one static binary per platform.

### Added

- **Readers:**
  - pcap (µs and ns, both byte orders) and pcapng (several sections, interfaces and link types, `if_tsresol` and `if_tsoffset`, simple packets, interface statistics).
  - gzip and standard input.
  - Several files read as one trace.
  - Frame numbers as Wireshark counts them.
- **Link, IP, TCP:**
  - Ethernet with 802.1Q/QinQ, BSD and OpenBSD loopback, raw IP, Linux SLL and SLL2.
  - IPv4 and IPv6 with fragment reassembly.
  - Connection epochs and midstream starts.
  - Per-direction reassembly with ACK-based gaps and a 64 MiB total budget.
- **Modbus/TCP:**
  - MBAP framing with bounded resync; foreign frames are skipped by their length.
  - Roles decided by handshake, port, structure or override; flows are classed by their traffic, not their port.
  - Decoding and validation of every function in `docs/COVERAGE.md`, with byte ranges.
  - Pairing with statuses (`ok`, `exception`, `unanswered`, `orphan_response`, `ambiguous`, `malformed`, `uncertain`) and quality flags.
  - Provenance down to the packets.
- **Library:**
  - `trace.Open`, `OpenFiles`, `OpenReader`, `Scan`, `Analyze`, `File.Frames`, `Walk`.
  - `model` events (each with `schema_version`) and `EventSemanticsVersion`.
  - `selection`.
  - `analyze`: overview, devices, patterns, coverage.
  - Exports: `export/timeline`, `export/mbcapexport` (`Export`, `Classify`, the report), `export/subtrace`.
  - `trace/tracetest` for synthetic traces with a ground truth.
  - Runnable examples in the godoc.
- **`mbtracectl`:**
  - Commands: `info`, `flows`, `summary`, `timeline`, `export timeline`, `export mbcap`, `extract`, `version`.
  - `--json` output with a JSON Schema per document in `docs/schema/`.
  - `MBTRACECTL_*` environment variables; exit codes 0/1/2.
  - Exports never leave a partial file behind.
- **MBCAP export:**
  - Reads only, matched and valid pairs only; one target per server and unit, one stream per client.
  - Exclusions counted by reason; warnings (`stale_after_write`, `unit_collision`, `gap_in_window`, `replay_memory`, ...) and a replay memory estimate.
  - MBCAP, JSON Lines and long CSV, with deterministic output.
  - Tested end to end against mbcapctl v0.0.2 and modbusctl v3.2.0.
- **Robustness:**
  - Every reader, decoder and the whole pipeline are fuzzed.
  - Hostile-input tests: empty and one-byte held segments, a million tiny fragments.
  - Seeded chaos tests run every consumer on random faulty traffic with corrupted bytes, tight limits and cancellation.
  - Concurrency tests run under the race detector.
  - A 2 GiB soak run checks that memory stays flat.
  - The SHA-256 of every output of the fixture is checked on every platform.
- **Docs:**
  - `docs/REPLAY-WORKFLOW.md`, `docs/json-output.md`, `docs/exitcodes.md`, `docs/API.md` and `docs/COVERAGE.md`.
  - The `testdata/plant.pcapng` fixture and the README walkthrough built on it.

### Measured

On an Apple M1 core with Go 1.27.2, over a generated 32 MiB trace:
- `Scan` runs at about 760 MB/s, SHA-256 included.
- `Analyze` runs at about 207 MB/s.

The live heap stays under 12 MiB on a 5 GiB stream at default limits.

### Compatibility

- **Draft format:** MBCAP is a draft (go-modbus-capture v0.0.x). Readers of version 1.0 will not read the files this release writes, and every export warns about it.
- **Go:** building needs Go 1.23 or later.
- **Builds:** `CGO_ENABLED=0` for Linux (amd64, arm64, armv7), macOS (arm64, amd64) and Windows (amd64, arm64). armv7 is cross-compiled; its tests are not run.

### Known limitations

- The resync rule that matches an outstanding request is not built, and roles can be overridden per endpoint but not per flow (`docs/DECISIONS.md` D13).
- Open questions Q8–Q10 in `docs/DECISIONS.md`: a real-capture fixture, TID-reuse semantics, and decoded views in the JSON Lines timeline.
