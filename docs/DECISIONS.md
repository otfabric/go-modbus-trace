# Decisions: go-modbus-trace

Decision record of milestone L0 (`ARCHITECTURE.md` section 12). Every record states the question, the evidence (measured, with the command that measured it), the decision and its consequences. Later milestones append records; a record is changed only by a new record that supersedes it.

## Method

| | |
|---|---|
| Date | 2026-10-15 |
| Machine | Apple M1 (8 cores), 16 GiB, macOS 27.0.1, Go 1.27.2 darwin/arm64 |
| Repository | `go-modbus-trace` at `db97366` plus the uncommitted L0 change; the spike is the separate module `spike/l0/` (its own `go.mod`, so nothing it imports reaches the library's `go.mod`) |
| Inputs | Offline only. gopacket `github.com/gopacket/gopacket` v1.7.4 (2026-10-01) from the local module cache. Its own requirements (x/sys v0.45.0, x/net v0.55.0, netlink v1.1.0) are not in the cache, so the spike requires the newest cached versions, all at or above them (x/sys v0.49.0, x/net v0.59.0, netlink v1.3.1, netns v0.0.5). modbusctl v3.2.0 (`c75d367`, the local checkout, built into a scratch directory) and go-modbus-capture v0.0.2 (module cache). tshark 4.6.9 (Homebrew) as the independent reference. |
| Traces | Synthetic only (`spike/l0/synth`): 1,000 client connections polling FC03 (125 registers) over Ethernet/IPv4/TCP, about 1 GiB per file, as classic pcap (µs, little endian, Ethernet) and as pcapng (interface 0 Ethernet with `if_tsresol` 6, interface 1 raw IPv4 with `if_tsresol` 9). Faults are injected at fixed rates: handshake or midstream start (1 connection in 8), request in one-byte segments, identical retransmission, MBAP header split over two segments, out-of-order halves, loss (a never-captured segment), duplicate observation on the second interface, conflicting overlap, two responses coalesced into one segment, sequence wraparound. The generator also returns the ground truth. |
| Reproduce | `cd spike/l0 && go test ./...` (ground truth), then `go run ./cmd/spike gen pcap 1024 1000 big.pcap` and `go run ./cmd/spike own|gp big.pcap` (see `spike/l0/README.md`) |

Throughput is file MiB per wall-clock second with a warm page cache, single goroutine. `mallocs` and `alloc` come from `runtime.MemStats` over the run, peak heap from `runtime/metrics` sampled every 20 ms, and RSS from `/usr/bin/time -l`. Each run was repeated 2 or 3 times; the range is given.

## D1. Trace readers: own `internal/pcapio`, not gopacket's `pcapgo`

**Question.** Read pcap and pcapng with gopacket's `pcapgo` or with our own reader?

**Evidence.**

| Reader only, 1 GiB | Throughput | Allocations | Peak RSS |
|---|---|---|---|
| own, pcap | 3,344-4,089 MiB/s | 66 mallocs, 0 MiB | 12.4-12.7 MiB |
| gopacket `pcapgo.Reader`, pcap | 4,923-4,980 MiB/s | 65 mallocs, 0 MiB | 12.6 MiB |
| own, pcapng | 2,597-3,415 MiB/s | 66 mallocs, 0 MiB | 12.6 MiB |
| gopacket `pcapgo.NgReader`, pcapng | 3,293-3,337 MiB/s | 68 mallocs, 0 MiB | 12.5 MiB |

Both read 5,425,131 (pcap) and 5,156,125 (pcapng) packets, as written. Both are far above the requirement (L23: 200 MB/s for the whole scan), so speed decides nothing here. What decides is fit:

- **File offsets.** `pcapgo` does not report the offset of a record or block. L16 (`File.Frames`) and the provenance model need it. Own reader: the offset of every record and block (254 lines including gzip, both byte orders, µs/ns magic, SHB/IDB/EPB/SPB, `if_tsresol` and `if_tsoffset`).
- **Hostile input** (from the source, not exercised). `pcapgo.Reader` allocates its packet buffer at the snap length from the file header, an untrusted `uint32`, on the first record. A pcapng block that fails to parse ends the read with an error, while L1 requires skipping and counting a corrupt block whose length is still plausible. The own reader caps a record at 256 KiB and a skipped block at 16 MiB.
- **Live capture compiled in.** On Linux, `pcapgo` links its AF_PACKET capture handle, so `golang.org/x/sys/unix` and `golang.org/x/net/bpf` enter the binary (`go list -deps`, linux/amd64, arm64, arm). This collides with the rule "no raw sockets" (AGENTS.md) and with a `depguard` ban on those packages.
- **Mixed link types.** `NgReader` reports a packet's link type through `CaptureInfo.AncillaryData[0]`, an `interface{}` slice.

**Decision.** Own reader in `internal/pcapio`. gopacket is not a dependency.

## D2. Link/IP/TCP parsing and TCP reassembly: own, not gopacket's `layers` and `reassembly`

**Question.** Does the gopacket fork meet L3/L4/L17/L19 CGO-free on all seven targets, and does it beat about 500 lines of our own?

**CGO.** Yes, it is CGO-free for what we would use. The packages `gopacket`, `layers`, `reassembly`, `pcapgo`, `ip4defrag` and `ip6defrag` build with `CGO_ENABLED=0` on linux/amd64, linux/arm64, linux/arm (v7), darwin/arm64, darwin/amd64, windows/amd64 and windows/arm64. None of them has cgo files. Only `pcap` and `pfring` (libpcap, PF_RING) use cgo, and we would not import them.

**Correctness against the ground truth** (`spike own` / `spike gp`, same framing rule in both):

| 1 GiB | Truth | own | gopacket |
|---|---|---|---|
| pcap: ADUs framed | 5,033,313 | 5,033,313 | 5,033,311 |
| pcap: gaps | 25,813 | 25,812 (gap bytes 6,685,308 = 25,812 × 259) | 25,802 |
| pcap: conflicting overlaps | 25,813 | 25,813 | cannot be observed |
| pcap: bytes framed as invalid headers | 0 | 0 | 260 |
| pcapng: ADUs framed | 4,783,529 | 4,783,529 | 4,783,527 |
| pcapng: conflicting overlaps | 24,532 | 24,532 | cannot be observed |

On 4 MiB traces with 1, 9 and 64 connections, both formats, the own candidate equals the truth in every compared field: packets, ADUs, gaps, retransmissions, conflicts, midstream starts and invalid headers (`spike/l0/own/own_test.go`). On 1 GiB it misses 1 of 25,813 gaps. No ADU is affected. It was not investigated in L0; L1 covers it with a test. The gopacket differences have three causes, read in the source and confirmed by the counts:

1. **Overlaps with delivered data are discarded without comparison** (`overlapExisting`). L4's `overlap_conflict` cannot be detected.
2. **Midstream start.** `Stream.Accept` can only force the start at the segment in hand. When the first captured segment of a direction is the second half of an out-of-order pair, the stream starts mid-ADU and the first half is dropped as old data (2 ADUs lost per GiB, 130 bytes of garbage each). The own candidate starts a midstream direction at the peer's last ACK number when that number is just before the segment. This rule recovers the case, and gopacket's API cannot express it.
3. **Gap detection.** gopacket declares a gap only when a page limit is hit or a flush passes (here: segments waiting more than 2 s of trace time). The own candidate also declares a gap as soon as the peer acknowledges bytes that were never captured (the capture lost them, and they will not come again). Gaps are found at once, without buffering up to the limit.

**Performance** (full pipeline: read, parse, reassemble, frame MBAP, with per-ADU frame provenance):

| 1 GiB | own | gopacket |
|---|---|---|
| pcap throughput | 1,049-1,146 MiB/s | 476-499 MiB/s |
| pcapng throughput | 1,055-1,097 MiB/s | 452-502 MiB/s |
| pcap mallocs / allocated | 5.1 M / 100 MiB | 16.3 M / 623 MiB |
| pcap GC cycles | 12 | 62 |
| peak heap / peak RSS | 12.4-12.6 MiB / 27.4-28.2 MiB | 16.1 MiB / 33.0 MiB |
| stripped static binary, linux/arm | 1.77 MB | 3.93 MB |
| code | 723 lines: reader 254, link/IP/TCP 148, reassembly and framer 321 | 201 lines of glue on 52,298 imported lines (`layers` alone 46,970) |

**Other fit issues with gopacket `reassembly`:**

- Importing it registers two global command-line flags (`assembly_debug_log`, `assembly_memuse_log`) in `flag.CommandLine`. That is a side effect on every program that imports the library.
- Its `ScatterGather` has no chunk boundaries. Per-packet provenance needs `CaptureInfo(offset)`, a linear scan per lookup, and the frame number must travel in `CaptureInfo.AncillaryData` (an allocation per packet).
- It knows no epochs (L3) and takes a mutex per connection on every packet.

**Decision.** Own code in `internal/link` and `internal/flow`, carrying forward the spike's two additions: ACK-based gap declaration and an ACK-informed midstream start. They are recorded as proposed changes to `ARCHITECTURE.md` section 6 in Q4 below. gopacket is not imported anywhere. `depguard` and `internal/policy` enforce this.

## D3. pcapng writer: own

**Question.** Use gopacket's `pcapgo.NgWriter` for the sub-trace export, or our own?

**Evidence.** Both writers copied every packet of the two-interface pcapng (40,479 packets) and of the classic pcap (42,586). For both writers, `tshark -T fields -e frame.time_epoch -e frame.interface_id -e frame.len -e frame.cap_len` gives output identical to the input's (same SHA-256 of the field dump), and `capinfos` reads the application and comment options. Differences:

- `NgWriter` always writes `if_tsresol` = 9 and nanosecond timestamps (`ngwrite.go`, "fix resolution to nanoseconds"). The values stay exact, but a source interface's resolution is not preserved: `capinfos -I` shows interface 0 changed from microseconds (6) to nanoseconds (9). The own writer keeps 6 and 9.
- `NgWriter` writes `TimestampOffset` as `if_tsoffset` but still writes absolute `UnixNano` timestamps, so a caller who sets an offset gets shifted times (from the source).
- Throughput, read included, 1 GiB pcapng: own 1,271-1,770 MiB/s, gopacket 646-693 MiB/s.
- The own writer is 77 lines.

**Decision.** Own writer in `internal/pcapio`, used by `export/subtrace`.

## D4. IPv6 fragment reassembly: keep, implement in L1 with IPv4

**Evidence.** One reassembler serves both families: key (source, destination, ID, protocol), first data wins, and a total byte budget with oldest-first eviction. That is 91 lines including the two header helpers. IPv6 adds 4 lines (Fragment header: next header, offset, M flag, 32-bit ID) plus the case in the extension-header walk that `internal/link` has anyway. A test reassembles the same out-of-order 3-fragment datagram as IPv4 and as IPv6 and checks the budget eviction (`spike/l0/own/frag_test.go`).

**Decision.** Keep IPv6 fragment reassembly as SHOULD and implement it in L1 together with IPv4. It costs about 10 lines and one scenario. Promoted to MUST by the user (Q5, 2026-10-15).

## D5. Memory per tracked connection

**Evidence** (`spike conns <n> [full]`, own flow state: map entry, both directions, framer buffer, provenance refs, the 512-byte tail kept for conflict detection):

| Connections | Light state (one request, one partial response) | Steady state (one complete 259-byte response) |
|---|---|---|
| 10,000 | 515 B per connection | 1,059 B per connection |
| 100,000 | 489 B | 1,033 B (98.5 MiB in total) |
| 1,000,000 | 551 B | 1,096 B |

About half of the steady state is the conflict-detection tail. Pairing (outstanding requests) and role buffering (L2) come on top.

**Decision.** Keep the default of 100,000 tracked connections. At about 1.1 KB each, they take about 100 MiB at L1. L2 must keep pairing state small (outstanding requests hold PDU bytes only while unanswered) to stay inside the 300 MB target. The per-direction reassembly buffer, however, makes the worst case unbounded in practice (question Q4).

## D6. modbusctl replay memory per MBCAP sample

**Question.** How much memory does `modbusctl server replay` use per sample (`MBCAP-EXPORT.md` section 5, `estimated_in_memory_bytes`)?

**Evidence.** These are MBCAP files written with go-modbus-capture v0.0.2: FC03, 125 registers, one poll per second, one target and one stream. For each, `modbusctl server replay --input f --listen 127.0.0.1 --port P --before-first absent` ran until it listened, and the peak RSS was read (`spike/l0/cmd/mbcapgen`, `spike/l0/replaymem.sh`). The baseline with one sample is 11.9 MiB.

| Samples | Registers changed per poll | File | Load time | Peak RSS | Per sample (minus baseline) |
|---|---|---|---|---|---|
| 100,000 | 0 of 125 | 0.1 MiB | 0.3 s | 83.0 MiB | 0.74 KB |
| 1,000,000 | 0 of 125 | 0.9 MiB | 3.0 s | 650.1 MiB | 0.67 KB |
| 3,000,000 | 0 of 125 | 2.6 MiB | 8.5 s | 1,654.9 MiB | 0.58 KB |
| 100,000 | 13 of 125 | 0.6 MiB | 0.6 s | 106.9 MiB | 0.99 KB |
| 1,000,000 | 13 of 125 | 6.4 MiB | 3.4 s | 939.5 MiB | 0.97 KB |
| 30,000 | 125 of 125 | 0.2 MiB | 0.3 s | 156.8 MiB | 4.97 KB |
| 100,000 | 125 of 125 | 0.6 MiB | 0.6 s | 437.1 MiB | 4.36 KB |
| 300,000 | 125 of 125 | 1.8 MiB | 1.6 s | 1,288.5 MiB | 4.36 KB |

The cause is visible in the source and in the numbers. `capfile.Load` keeps every sample (request and response slices) for the life of the server. `replay.Build` adds one 16-byte point per address whose value changed, held in per-address slices of a map.

**Decision.** The exporter estimates replay memory as

`estimated_in_memory_bytes = 12 MiB + 750 B × samples + 36 B × changed values`

Here, *changed values* counts, per target, every FC01-04 register or coil whose value differs from that address's previous exported sample, plus, for other functions, the response bytes of every response that differs from the previous response to the same request. The constants are the smallest round numbers that bound every row of the table from above. Against the measurements, the estimate is 1-30% high, never low. The report adds a warning `replay_memory` when the estimate exceeds the threshold set by `--warn-replay-memory` (default 1 GiB; answered Q6). The file size says nothing about replay memory: deflate makes a 1.8 MiB file that needs 1.3 GiB.

## D7. Modbus/TCP framing without the Implementation Guide

**Question.** What do the Modbus/TCP framing rules say, given that the *MODBUS Messaging on TCP/IP Implementation Guide V1.0b* is not available locally (and fetching it is not allowed in this work)?

**Sources available offline, and what each establishes:**

| Source | Established |
|---|---|
| Application Protocol V1.1b (`go-modbus/spec/MODBUS-SPEC.md`) | PDU at most 253 bytes; "TCP MODBUS ADU = 253 bytes + MBAP (7 bytes) = 260 bytes"; function code 0 is invalid, 128-255 are exception responses; reserved port 502. It refers to the Implementation Guide **V1.0a**, not V1.0b. It does not define the MBAP fields. |
| go-modbus v1.7.1 (`internal/adu/mbap.go`, `internal/transport/tcp.go`, `client.go`) | Header 7 bytes; protocol ID must be 0; length 2..254 (unit ID + function code + data). A frame with a non-zero protocol ID but a plausible length is **skipped by its length** and reading continues (up to 10 anomalies). A response with an unexpected transaction ID is skipped the same way. A response whose unit, function or length is inconsistent with its request marks the stream as out of sync. |
| tshark 4.6.9 `mbtcp` dissector, probed with crafted frames (`spike/l0/cmd/framecases`) | Length 0 and 1: not Modbus. Length 2: decoded. Length 254 (ADU 260): decoded. Length 255: decoded with the expert note "Invalid length". Protocol ID 1: decoded with "Invalid protocol ID". Two ADUs in one segment: both decoded. Unit IDs 0 and 255: decoded. A header split 3 + 9 bytes over two segments: **not decoded**. A length longer than the bytes that follow: not decoded. Junk before a valid header: one malformed packet, no resynchronisation. |

**Decision.** The L5 rules stand: header of 7, protocol ID 0, length 2..254, several ADUs per segment, one ADU over several segments, bounded resync. They agree with every local source. Three consequences:

- Our framer must frame headers split across segments. tshark does not, so the oracle test (LA13) will report disagreements there. They are triaged as tshark's limit, not ours.
- Unit IDs 0 and 255 are ordinary on TCP. Only the absence of a response to unit 0 is flagged `broadcast` (ARCHITECTURE section 9).
- A non-zero protocol ID with a plausible length is framed differently by the two references: go-modbus stays in sync and skips the frame; tshark decodes it with a warning. Section 7 currently sends it to byte-scan resync. Which one we adopt is question Q3.

**Still unverified until the guide is read:** the guide's own wording on the MBAP fields, on how many transactions a client may have outstanding per connection, on unit ID conventions (0xFF for a directly addressed server), and on connection management. None of these changes the framing above. They affect documentation and the `broadcast` heuristic only.

## D8. Module, Go version, lint and CI

- `go.mod`: `module github.com/otfabric/go-modbus-trace`, `go 1.23`. This is the lowest version the chosen dependencies allow: go-modbus-capture v0.0.2 declares 1.23, and cobra v1.10.2 declares 1.15. It is below the applications (1.25.0), as the requirement asks. With gopacket and its cached dependencies the floor would have been 1.26.0 (`go mod tidy` in the spike).
- `.golangci.yml`: the go-modbus-capture set, plus `depguard` (no `net/http`, `net/rpc`, `os/exec`, `plugin`, `x/sys/unix`, `x/net/bpf`, gopacket, go-modbus, `math/rand` or `database/sql` outside tests) and `forbidigo` (no `net.Dial*`, `net.Listen*`, `net.Dialer`, `net.Resolver`; no `time.Now`, `time.Since` or `time.Until` outside tests and `cmd/`).
- `internal/policy`: a test over `go list -deps -json` that fails on a forbidden dependency anywhere in the graph (`os/exec` allowed under `cmd/` only) and on any non-standard package with cgo files. Checked by planting a `net/http` import, which both the test and `depguard` reported.
- `Makefile`: the go-modbus-capture targets, plus `mod-check` (no `replace`) and `targets` (`CGO_ENABLED=0 go build ./...` for the seven targets), both in `make check`.
- `.github/workflows/ci.yml`: the organisation's `go-ci.yml@v2`, as go-modbus-capture uses it, plus a job per target on a runner of its own architecture. linux/arm (v7) is cross-compiled on the arm64 runner and not executed (question Q2). `release.yml` follows in L1, when `cmd/mbtracectl` exists to be released.

## D9. L1: what the implementation settled (2026-10-15)

- **Frame numbers follow Wireshark exactly.** tshark 4.6.9 numbers pcapng Custom Blocks (`0x0BAD`, `0x40000BAD`) and systemd Journal Export Blocks as frames; Name Resolution, Decryption Secrets and unknown blocks it does not. The reader counts the same blocks (without returning them), so a frame number in an event is the one Wireshark shows. Checked against tshark in `internal/pcapio` (skipped where tshark is absent).
- **Midstream start uses the peer's first ACK**, not its latest (the spike used the latest): a later ACK may already cover bytes the capture lost, which then disappeared without a gap. Found by the random ground-truth test.
- **The ACK-based gap is declared lazily**: only when data waits behind the hole (held segments, or a later segment arriving). Without data behind it nothing is declared, so a capture where an ACK copy is stamped before its data (two taps, `-i any`) loses nothing.
- **Held data is never a keepalive**: a one-byte copy drained from the out-of-order buffer looked like a probe. **First data wins among held segments** too: a conflicting copy held behind a hole was delivered before the original. Both found by the random ground-truth test.
- **The framer settles before it drops**: at a gap or the end of the stream it decides a pending resync candidate (a cut-off next header counts if its protocol ID bytes are 0 and its length plausible) and a pending foreign-frame decision, and it waits for the function code byte of a split header. Three bugs of this kind were found by the random test and the fuzzer.
- **Snap-length cuts keep framing in sync**: the flow stage reports the cut as an exact gap, so a truncated ADU is reported with what was captured and the next one is framed normally.
- **Types**: `FileSummary` and `Flow` live in package `trace` in L1; `model` starts in L2 with the event types and their JSON Schemas (L22). The framer (`mbtcp.Framer`) is provenance-agnostic: it works on stream positions, and L2 maps them to frames.
- **CLI**: cobra as modbusctl, exit codes 0/1/2 as mbcapctl (REQUIREMENTS L18 names both; the explicit codes win), every flag also from `MBTRACECTL_<FLAG>`, progress on stderr only when it is a terminal. Several input files as one continuous trace moves to L3, where the exports need it.
- **Lint fix**: the L0 `depguard` rule for go-modbus was a prefix and matched this module (`go-modbus-trace`) and go-modbus-capture; it is now exact (`$`) plus go-modbus's subpackages. Checked: go-modbus is refused, go-modbus-capture is allowed.
- **Tests use the standard library only**; testify was not needed.

## D10. L2: what the implementation settled (2026-10-15)

- **Pairing decides gap-swallowed requests early.** A request whose response direction had a gap is `unanswered` and `uncertain` as soon as a request sent after it is answered. Before this, a 5 GiB soak's live heap grew with the trace (91 MiB at 5 GiB, 24 at 1 GiB) because every lost response held its request until the connection ended; after, 11 MiB at 5 GiB.
- **The timeline's reorder buffer is bounded in bytes too** (64 MiB of encoded rows, besides the 60 s window): on a 1 GiB trace with 2.5 M transactions the window alone held about 200,000 events, 1 GiB of memory; now 173 MiB peak.
- **`--server` and `--client`** select in the analysing commands and also feed the role decision (ARCHITECTURE section 11 used the names for both purposes).
- **TID reuse** with a different PDU while the first request is outstanding is `ambiguous` (section 9), not `unanswered` (REQUIREMENTS L8 lists reuse under `unanswered`); the one left outstanding at the end is `unanswered`. Section 9 is followed; L8's wording is read as "the earlier request was never answered".
- **Unknown roles**: such connections are not paired; every ADU is an `uncertain` transaction with the new flag `role_unknown` (section 10's list gained it).
- **Schema now, not at L4**: `docs/schema/event-1.schema.json` exists from L2 because the definition of done ties every `model` change to the schema; tests validate events and check the schema covers every field. The other schemas (summary, flows, analyzers, report, CLI JSON) stay L4 (L22).
- **LA6 without privileges**: a go-modbus v1.7.1 client and server on loopback through a recording proxy (TESTING.md's bridge) give real frames for every function the client supports; the decode equals the client API's values. A tcpdump fixture would need privileges; none is committed.
- **Throughput**: `Analyze` runs at about 140 MiB/s on an M1 core (L23 asks for 100 MB/s); the decoder allocates a field list per ADU, the first place to look at L4.

## D11. L3: what the implementation settled (2026-10-15)

- **The export spools.** A capture header must come first, but `WallStart`, the input hashes and the first and last packet times are known only at the end of the pass. The exporter writes admitted samples to a temporary file (a 14-byte record header plus the two PDUs) and writes the capture after the pass. Memory stays at the target and stream tables; a stream (stdin) gets the same `WallStart` rule as a file, so the earlier "first packet seen" fallback is gone (`outside_window` now means outside the selected time window only) (MBCAP-EXPORT section 2).
- **`Classify` mirrors the library and is tested against it.** The FC01–04 response-size check reproduces `capture.SplitAddresses`; a test runs every function code, FC08 sub-function and MEI type through both `Classify` and `capture.NewChecker` and requires the same verdict. A writer error is returned, never counted as an exclusion.
- **The report's state is bounded per target.** `stale_after_write` needs the writes and the last read per range: the most recent 4,096 writes and the first 65,536 distinct read ranges are kept; past those caps a warning can be missed (the writes are counted as `write_function` either way). The replay estimate keeps the last value per FC01–04 address (bounded by the address spaces) and the hash of the last response to at most 65,536 distinct other requests; past that cap every response counts as changed, so the estimate stays an upper bound.
- **Several input files** are one trace (`trace.OpenFiles`): connection, reassembly and pairing state carry across, `FrameRef.Part` names the file (omitted for the first), `FileSummary.Inputs` lists each. `File.Frames` on a stream is refused up front with `ErrNotSeekable`.
- **Pinned tools.** modbusctl's v3 tags are not Go module versions (its module path has no `/v3`), so `go install ...@v3.2.0` fails; the Makefile pins the pseudo-version of the v3.2.0 commit. mbcapctl is pinned at v0.0.2. The `replay` CI job installs both and runs LA10 with `MBTRACE_REQUIRE_TOOLS=1`.
- **go-modbus-capture** became a direct dependency (it was indirect through go-modbus).

## D12. L4: what the implementation settled (2026-10-15)

- **Analyzer caps drop new keys, not old ones**: a device, pattern or range beyond its cap is counted in `overflow` instead of being folded into an `other` bucket, which would mix unrelated devices (ARCHITECTURE section 2 updated).
- **Schemas are generated** from the Go types by `internal/schemagen` for every CLI document and the file summary (L22): no additional properties, `omitempty` fields optional, nil slices, maps and pointers nullable. A test fails when a committed schema differs and validates the real output of every command against its schema. The event schema stays hand-written, as in L2.
- **Sub-trace selection is per connection.** `extract` takes `--server`, `--client`, `--conn` and a time window; transaction-level flags are refused, because a packet can carry several transactions. Either end may match `--server`/`--client`, since roles are not decided there.
- **Oracle triage** (tshark 4.6.9): tshark does not link exception responses to their requests; the test compares only their exception code (TESTING.md section 4).
- **Throughput** after the L2 note on allocation: `Scan` 768 MB/s and `Analyze` 206 MB/s per M1 core on the 32 MiB benchmark trace (L23: 200 and 100).
- **The `summary` JSON changed** from L2's `devices` list to the four analyzer results (`overview`, `devices`, `patterns`, `coverage`); there has been no release, so `schema_version` stays 1.

## Open questions for the user

- **Q1. CLI name.** Keep `mbtracectl`? **Answered 2026-10-15: yes, `mbtracectl`.**
- **Q2. armv7 tests.** AGENTS.md says the library "builds and tests" on linux/arm (v7), and also "never under QEMU". GitHub has no hosted armv7 runner, so CI can only cross-compile it, as sunspec-explorer does. Accept build-only for armv7? Or run the tests on a gateway or a self-hosted runner? **Answered 2026-10-15: cross-compile only.**
- **Q3. Non-zero protocol ID.** When a header has protocol ID ≠ 0 but a plausible length, and the next header at that length is valid, there are two choices. (a) Stay in sync: skip the frame by its length, as go-modbus does, and count it as `foreign_protocol` (never exported). (b) Byte-scan resync, as section 7 says today. Recommended: (a). It keeps the following ADUs trusted instead of flagging them `resynced`. **Answered 2026-10-15: (a); ARCHITECTURE section 7 updated.**
- **Q4. Memory bound for reassembly.** L17 bounds the reassembly buffer per direction (1 MiB) and the tracked connections (100,000) but not their product: the worst case is about 200 GiB, which contradicts L23's "under 300 MB at default limits for any trace size". Proposed: a total reassembly budget (64 MiB; when it bites, the direction with the most buffered bytes declares its gap). Also proposed: add the two spike rules to section 6, ACK-based gap declaration and the ACK-informed midstream start. **Answered 2026-10-15: yes to all three** (total budget 64 MiB, ACK-based gaps, ACK-informed midstream start); REQUIREMENTS L4/L17 and ARCHITECTURE sections 2 and 6 updated.
- **Q5. IPv6 fragments.** Promote from SHOULD to MUST, since the cost is about 10 lines? **Answered 2026-10-15: yes, MUST (REQUIREMENTS L2).**
- **Q6. Replay memory warning.** Is 1 GiB the right threshold for the `replay_memory` warning, or should it follow the target machine (a flag)? **Answered 2026-10-15: a flag, `--warn-replay-memory` (default 1 GiB; `0` disables the warning).**
- **Q7. The guide.** Can you put a copy of the Implementation Guide (V1.0b, or the V1.0a the specification cites) next to `go-modbus/spec/`, so that L2 can reconcile D7 against it without network access? **Answered 2026-10-15: yes, the user provides it.**
- **Q8. A real fixture.** `testdata/capture-1.pcap` (the capture you tested L2 on) is not committed: AGENTS.md forbids customer traces, and its origin is not recorded here. May it be committed, with its origin in `testdata/README.md`, or should it stay local?
- **Q9. TID reuse.** D10 follows ARCHITECTURE section 9 (`ambiguous`) over REQUIREMENTS L8 (`unanswered`) for a reused transaction ID with a different PDU. Confirm, or say which should win.
- **Q10. Decoded views in the JSON Lines timeline.** Every event carries its decoded request and response views, which makes the file several times larger than the raw PDUs alone. Keep them by default, or omit them unless asked (`--views`)?
