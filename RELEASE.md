# go-modbus-trace Releases

## v0.8.7

**Date:** 2026-11-14
**Previous release:** v0.8.6

No API change.

### Changed

- Tests use go-modbus v1.15.3 (was v1.15.2): after a failed `Accept` the server waits before it tries again, a metrics hook that does not return normally is contained, an RTU request longer than a frame is refused before it is sent, and a request whose context ends while the deadline is set is not sent (go-modbus RELEASE.md, v1.15.3); the library does not import it outside tests. The previous release named go-modbus v1.15.2 for these changes; v1.15.2 was tagged without them (it holds go-serial v0.4.0 only), so they arrive with this release.

---

## v0.8.6

**Date:** 2026-11-14
**Previous release:** v0.8.5

No API change.

### Changed

- Tests use go-modbus v1.15.2 (was v1.15.1): after a failed `Accept` the server waits before it tries again, a metrics hook that does not return normally is contained, an RTU request longer than a frame is refused before it is sent, and a request whose context ends while the deadline is set is not sent (go-modbus RELEASE.md, v1.15.2); the library does not import it outside tests.

---

## v0.8.5

**Date:** 2026-11-14
**Previous release:** v0.8.4

No API change.

### Changed

- `export/mbcapexport` is built on go-modbus-capture v0.2.1 (was v0.1.0). The MBCAP library API it uses is unchanged.
- Tests use go-modbus v1.15.1 (was v1.15.0); the library does not import it outside tests.
- `mbtracectl` is built on go-modbus-trace v0.8.4 (was v0.8.2) and go-modbus-capture v0.2.1 (was v0.2.0).
- An MBCAP export names the libraries it was built with in its header, so the hashes of the four export outputs in `testdata/plant.outputs.json` are regenerated (`make golden`). The exported records are identical.
- CI: otfabric/engineering policy 1.6 and the shared workflows v3.8.0. Releases now run the API compatibility gate before tagging.

---

## v0.8.4

**Date:** 2026-11-13
**Previous release:** v0.8.3

### Changed

- Tests use go-modbus v1.15.0 (was v1.14.5; the library does not import it outside tests). Library code and `mbtracectl` are unchanged.

---

## v0.8.3

**Date:** 2026-11-13
**Previous release:** v0.8.2

### Changed

- `mbtracectl` is built on the library v0.8.2 (was v0.8.0): more than 65536 input files are refused instead of renumbered from 0. The golden output hashes of `testdata/plant.outputs.json` change because the mbcap export names the library version. Library code is the same as v0.8.2.

---

## v0.8.2

**Date:** 2026-11-13
**Previous release:** v0.8.1

### Fixed

- A packet limit (`trace.Limits.MaxPacket`) above the largest 32-bit length is treated as that length. Before, it was compared after a conversion that wrapped it, so a limit of 4 GiB refused every packet.
- `trace.OpenFiles` refuses more than 65536 files, the number `FrameRef.Part` (a uint16) can name, instead of numbering later files from 0 again.

### Changed

- Tests use go-modbus v1.14.5 (the library does not import it outside tests). `mbtracectl` moves to this release in v0.8.3.

---

## v0.8.1

**Date:** 2026-11-10
**Previous release:** v0.8.0

### Fixed

- **`mbtracectl` is built on the library v0.8.0** (it was on v0.7.0): a capture taken on the sending host, whose IPv4 packets have a total length of 0 (TCP segmentation offload), keeps its Modbus/TCP payload instead of losing those packets as `bad_header`, and the summary reports them as `tso_segments`. It also brings the library changes of v0.7.1 to v0.7.3 to the command.

### Changed

- The JSON schemas `summary-1`, `file-summary-1` and `info-1` list `tso_segments` (generated from the library the command is built on); `docs/json-output.md` shows it.

---

## v0.8.0

**Date:** 2026-11-10
**Previous release:** v0.7.3

### Fixed

- **Captures taken on the sending host keep their segments.** With TCP segmentation offload, a capture on the host that sends (a SCADA or HMI client capturing its own traffic, typically on Windows) holds IPv4 packets whose total length is 0: the network card fills it in after the capture point. They were dropped as `bad_header`, so the Modbus/TCP payload they carried was lost and the trace showed gaps, unanswered requests or orphan responses that were not on the wire. Such a packet that is not a fragment is now taken at its captured length, as Wireshark does; a fragment with a total length of 0 is still refused. Found by go-mms-trace, which shares this link layer, comparing with Wireshark over public captures of ABB and Siemens IEDs.

### Added

- `FileSummary.TSOSegments` (`tso_segments`): the number of IPv4 packets taken at their captured length because their total length was 0. Not an error. Documented in docs/ARCHITECTURE.md; the JSON schemas, generated from the library that `mbtracectl` pins, gain it with the pin bump.

### Tests

- `TestTSOZeroLength` (`internal/link`) and `TestTSOSegments` (`trace`: a capture whose IPv4 packets all have a total length of 0 yields the same ADUs and counts them; it fails without the fix).

### Known limitations

- `mbtracectl` is a nested module pinned to the library v0.7.0: its binaries of this release still drop these packets. The next release bumps the pin.

---

## v0.7.3

**Date:** 2026-11-08
**Previous release:** v0.7.2

### Changed

- No changes. v0.7.3 was released by mistake from the same commit as v0.7.2, a few seconds later; the library and `mbtracectl` are identical to v0.7.2.

---

## v0.7.2

**Date:** 2026-11-08
**Previous release:** v0.7.1

### Changed

- `mbtracectl` is built with the latest Go 1.26 patch release; v0.7.1 was built with go1.26.0.

---

## v0.7.1

**Date:** 2026-11-07
**Previous release:** v0.7.0

### Changed

- `mbtracectl` is built on v0.7.0 and go-modbus-capture v0.2.0. Library code is the same as v0.7.0.

---

## v0.7.0

**Date:** 2026-11-07
**Previous release:** v0.6.0

### Breaking

- `mbtracectl version --json` writes the organisation's version document on one line: `{"name","version","tag","commit","built","libraries","go","platform"}` in that order (schema [version-2](docs/schema/version-2.schema.json), replacing version-1). `schema_version` and `build_date` are gone; `built` replaces `build_date`. Library code is unchanged.

### Added

- `mbtracectl version` prints one line with the tag, the full commit, the build date, the Go version and the platform: `mbtracectl 0.7.0 (tag v0.7.0, commit <sha>, built <date>, go-modbus-capture 0.1.0, go1.26.0, linux/amd64)`, with the OT Fabric libraries it is built on. A build that was not released reports `dev` (or the module version of `go install ...@vX.Y.Z`) and the VCS revision, with `-dirty` for uncommitted changes, instead of `0.0.0-dev`; `make build` injects the version and tag only when HEAD is on a tag.
- Shell completion for bash, zsh, fish and PowerShell completes the value sets of `--format`, `--order`, `--status`, `--class`, `--flag`, `--no-flag` and `--compression`, trace arguments (`.pcap`, `.pcapng`, `.cap`, `.gz`), and output files by type (`extract -o` pcapng, `export mbcap -o` mbcap/jsonl/csv, `--report` json); flags with free values no longer offer file names. Install: [Shell completion](README.md#shell-completion).

### Changed

- `make build` injects the version without the leading `v` (only on a tag) and the full commit SHA, as the Release workflow does.

---

## v0.6.0

**Date:** 2026-11-07
**Previous release:** v0.5.2

### Breaking

- `mbtracectl` exit codes follow the organisation table (otfabric engineering CLI-001). Old → new: a trace that cannot be opened, is not a trace or is damaged 1 → 3; an output that cannot be written 1 → 10; interrupted (Ctrl-C, now also SIGTERM) 1 → 130; an unknown command 1 → 2 (`mbtracectl export nope` 0 → 2); success 0 and usage 2 are unchanged. 1 is no longer used. Scripts that test for 1 should test for non-zero. Table: [cmd/mbtracectl/docs/exitcodes.md](cmd/mbtracectl/docs/exitcodes.md). Library code is unchanged.

---

## v0.5.2

**Date:** 2026-11-05
**Previous release:** v0.5.1

### Changed

- `mbtracectl` is built on go-modbus-trace v0.5.1, so its MBCAP exports and reports record the library version linked in instead of `go-modbus-trace 0.1.0`. Library code is the same as v0.5.1.

---

## v0.5.1

**Date:** 2026-11-05
**Previous release:** v0.5.0

### Changed

- Moves to go-modbus-capture v0.1.0 (Go 1.26 floor, no change in behaviour); tests use go-modbus v1.11.1.
- `mbtracectl` is built on go-modbus-trace v0.5.0 (was v0.4.5) and go-modbus-capture v0.1.0.

### Fixed

- MBCAP exports and the exclusion report recorded the library as `go-modbus-trace 0.1.0` whatever the version. They now record the version linked in, read from the build information like the go-modbus-capture version (new `mbcapexport.LibraryVersion`); `trace.Version` is the fallback, now `(devel)`. Exports from the same trace, options and library version stay byte-identical.

---

## v0.5.0

**Date:** 2026-11-05
**Previous release:** v0.4.5

### Changed

- Go 1.26 or later is required (was 1.23); CI runs Go 1.26 and 1.27. `go fix` modernised the code; no API changes.
- Tests use go-modbus v1.11.0 (the library does not import it outside tests).
- `mbtracectl` is built on go-modbus-trace v0.4.5 (was v0.4.2).

---

## v0.4.5

**Date:** 2026-11-03
**Previous release:** v0.4.4

### Changed

- Dependency update, no other change. Moves to go-modbus v1.10.6, whose codec count checks compare the full length of a slice.

---

## v0.4.4

**Date:** 2026-11-01
**Previous release:** v0.4.3

### Changed

- Dependency update, no other change. Moves to go-modbus v1.10.5, which has the fix for a response that arrives during `Client.Close`.

---

## v0.4.3

**Date:** 2026-10-31
**Previous release:** v0.4.2

### Changed

- The bundled command-line tools are built on v0.4.2. Library code is the same as v0.4.2.

---

## v0.4.2

**Date:** 2026-10-31
**Previous release:** v0.4.1

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.

---

## v0.4.1

**Date:** 2026-10-31
**Previous release:** v0.4.0

### Fixed

- `mbtracectl` is built on this library's v0.4.0: it was still on v0.2.0, so its binaries lacked the fixes of v0.3.0 and v0.4.0.

---

## v0.4.0

**Date:** 2026-10-30
**Previous release:** v0.3.0

### Fixed

- **A whole segment sent again now marks its transaction.** `model.FlagRetransmitted`
  used to be set only when a retransmitted segment also carried new bytes, so a
  whole Modbus message sent again was counted and marked nothing.
  - A copy of a request before its response, or of the first segments of an ADU
    still being framed, now sets the flag. So does the old part of a partly new
    segment, on the earlier ADU it repeats.
  - A copy of a complete response or of an answered request still only counts:
    its transaction is already emitted and events are not amended.
  - `Quality.Retransmitted` does not change. It counts segments, the flag marks
    transactions, and the two are not expected to line up.
  - A trace with every packet captured twice (capture on `any`, two taps) now has
    the flag on its requests, because the second copy arrives before the response.
    `retransmitted` in the MBCAP export report rises with it; no transaction is
    excluded because of the flag.

### Added

- `tracetest.Conn.Resend` sends the direction's last write again, for scripting
  a copy that arrives late.

---

## v0.3.0

**Date:** 2026-10-30
**Previous release:** v0.2.0

### Dependencies

- `go-modbus` v1.7.2 → v1.10.0. Since v1.9.0 a context deadline no longer extends a request past `Config.Timeout`.

---

## v0.2.0

**Date:** 2026-10-30
**Previous release:** v0.1.1

### Changed

- **`cmd/mbtracectl` is now a nested module** (`github.com/otfabric/go-modbus-trace/cmd/mbtracectl`).
  The library's `go.mod` no longer requires cobra or pflag, so consumers stop
  inheriting them. Library import paths and the exported API are unchanged.
  - Release binaries are published as before.
  - Build from a checkout with `make build`, or `cd cmd/mbtracectl && go build .`.
  - `go install .../cmd/mbtracectl@<version>` works up to v0.1.1 and not after
    it, while the nested module's `replace` is in place.

---

## v0.1.1

**Date:** 2026-10-29
**Previous release:** v0.1.0

### Summary

Dependency update: go-modbus v1.7.2 with go-serial v0.1.8. No API changes.

### Dependencies

- **go-modbus v1.7.1 → v1.7.2.**
- **go-serial v0.1.6 → v0.1.8**, which fixes two POSIX serial I/O bugs:
  - `Write` no longer loses data when the tty output buffer is full. It
    used to return a short count with a nil error (or `n == -1` with
    `EAGAIN`); it now blocks until every byte is written.
  - `Read` works when the port's file descriptor is 1024 or higher. It
    used to return a spurious `io.EOF` at once.

### Other

- The `spike/` prototype directory is removed; security contact is
  security@otfabric.io.

---

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
