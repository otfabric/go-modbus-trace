# go-modbus-trace Releases

## v0.1.0

**Date:** 2026-10-15
**Previous release:** none

### Summary

The first release. Read a pcap or pcapng trace, find the Modbus/TCP traffic in it, and get a typed, time-ordered view of every connection and transaction; analyze devices, poll patterns and address coverage; export a timeline, a sub-trace for Wireshark, and an MBCAP capture that `modbusctl` replays as a virtual device. Pure Go, offline, bounded memory.

### Added

- **Readers:** pcap (µs, ns, both byte orders) and pcapng (several interfaces and link types, `if_tsresol`, simple packets, interface statistics), gzip, standard input; several files as one trace. Frame numbers as Wireshark counts them.
- **Link, IP, TCP:** Ethernet, 802.1Q/QinQ, BSD loopback, raw IP, Linux SLL and SLL2; IPv4 and IPv6 with fragment reassembly; connection epochs, midstream starts, per-direction reassembly with ACK-based gaps and a 64 MiB total budget.
- **Modbus/TCP:** MBAP framing with bounded resync and foreign frames skipped by length; roles by handshake, port, structure or override; decoding and validation of every function in `docs/COVERAGE.md` with byte ranges; pairing with statuses (`ok`, `exception`, `unanswered`, `orphan_response`, `ambiguous`, `malformed`, `uncertain`) and quality flags; provenance to the packets.
- **Library:** `trace.Open`/`OpenFiles`/`OpenReader`, `Scan`, `Analyze`, `File.Frames`, `Walk`; `model` events with `EventSemanticsVersion`; `selection`; `analyze` (overview, devices, patterns, coverage); `export/timeline`, `export/mbcapexport` (`Export`, `Classify`, the report), `export/subtrace`; `trace/tracetest` for synthetic traces with a ground truth.
- **`mbtracectl`:** `info`, `flows`, `summary`, `timeline`, `export timeline`, `export mbcap`, `extract`, `version`; `--json` output with a JSON Schema per document in `docs/schema/`; `MBTRACECTL_*` environment variables; exit codes 0/1/2.
- **MBCAP export:** reads only, matched and valid pairs only, one target per server and unit, one stream per client; exclusions counted by reason; warnings (`stale_after_write`, `unit_collision`, `replay_memory`, ...) and a replay memory estimate; MBCAP, JSON Lines and long CSV; deterministic output. Tested end to end against mbcapctl v0.0.2 and modbusctl v3.2.0.
- **Docs:** `docs/REPLAY-WORKFLOW.md`, `docs/json-output.md`, `docs/exitcodes.md`, `docs/API.md`, `docs/COVERAGE.md`; the `testdata/plant.pcapng` fixture.

### Compatibility

MBCAP is a draft format (go-modbus-capture v0.0.x): readers of version 1.0 will not read the files this release writes, and every export says so. Requires Go 1.23 to build; `CGO_ENABLED=0` builds for Linux (amd64, arm64, armv7), macOS (arm64, amd64) and Windows (amd64, arm64).
