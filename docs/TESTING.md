# Testing go-modbus-trace

The library reads untrusted files and its output is used to build virtual devices, so correctness is tested against ground truth, not against itself. Everything runs without privileges and without network access.

## 1. Ground truth: the synthetic trace builder (`trace/tracetest`)

Build this first (L1); everything else depends on it. It is exported so the application's tests can use it.

- **Frames**: Ethernet (optionally 802.1Q/QinQ), BSD loopback, raw IP, IPv4, IPv6, Linux SLL and SLL2 wrappers around IPv4/IPv6 + TCP. Correct checksums are optional (tests also need wrong ones, as in offload captures).
- **Files**: classic pcap (µs/ns, little/big endian) and pcapng (several interfaces, different link types and `if_tsresol`, Simple Packet Blocks, Interface Statistics Blocks, unknown blocks), optionally gzipped, written to a `[]byte` or a file, streamed so a multi-GB trace can be produced without being stored.
- **TCP scripting**: a connection is a script of `Send(dir, bytes)` steps with a segmentation policy (MSS, one byte at a time, coalesce N writes, random cut points from a seed), and injectable faults: retransmission, duplicate (second interface), reorder, overlap (identical and conflicting), loss (gap), keepalive probe, SYN/SYN-ACK/FIN/RST handshakes, midstream start (drop the handshake), 4-tuple reuse, sequence wraparound, snap-length truncation, clock jump.
- **Modbus scripting**: helpers to emit ADUs for any function (request/response), including malformed ones, and a **bridge to go-modbus**: a `net.Conn` wrapper that records both directions of a real go-modbus client talking to a real go-modbus server (v1.7.1 serves every function) and turns the recorded byte flow into a synthetic trace. This produces genuine frames for every function without privileges and gives the value ground truth (what the client call returned).
- **Ground truth output**: every script also yields the expected transactions (and flags) as a golden JSON, compared field by field.

## 2. Layers of tests

| Layer | What | IDs |
|---|---|---|
| Unit | pcap/pcapng parsing, timestamp scaling, link/IP/TCP parsing, sequence arithmetic, framer, each PDU decoder and validator, pairing rules, selection predicate | LA1-LA4, LA6, LA7 |
| Scenario | the fault scripts above end to end through `Analyze`, compared with the script's ground truth, with quality counters | LA3, LA8 |
| Real fixtures | a few small traces captured with tcpdump on loopback between the go-modbus client and server (and, if available, from OT Fabric's own test rigs) committed under `testdata/` with expected event JSON; `testdata/README.md` lists origin, tool versions and the command used | LA1, LA6 |
| Export | MBCAP admission matrix, property test against `capture.NewChecker`, encodings round trip with `capture.Equal`, report identity | LA9 |
| End to end | `e2e/`: a live go-modbus client and server over loopback, recorded to a trace file, through analysis, MBCAP export, timeline and sub-trace, and the errors of damaged files. Then trace -> `export mbcap` -> pinned `mbcapctl verify` -> pinned `modbusctl server replay/static` -> go-modbus client reads equal the scripted values | LA10 |
| Determinism | double run; `TestGoldenOutputs` hashes every output of `testdata/plant.pcapng` (MBCAP, JSON Lines, CSV, timeline, sub-trace, summary, flows, report) against `testdata/plant.outputs.json` on every target's own runner (cross-OS); `TestCLIEqualsLibrary` | LA11 |
| Chaos | `trace/chaos_test.go`: seeded random traffic (many clients, servers and units, every function class, malformed and vendor PDUs, pipelining, reused and unanswered IDs, orphans, TCP faults, IP fragments, clock steps, tiny limits, corrupted bytes, cancellation) through every consumer, checking invariants that hold for any input: no recovered panic, counts that agree, provenance inside the trace and carrying the ADU, the export identity, a capture that reads back, a sub-trace that re-analyses the same. 150 seeds per run (`MBTRACE_CHAOS_SEEDS`, `MBTRACE_CHAOS_SEED`) | LA3, LA8, LA14 |
| Pairing truth | `TestChaosPairingTruth` (`trace/chaos_test.go`, the same seeds): read polls in which requests and responses are lost to the capture, transaction IDs repeat and some requests are never answered. Every response carries the address of the request it answers, so the test knows the truth: a transaction decided `ok` pairs a response with its own request | LA7 |
| Concurrency | `TestConcurrentUse`: Analyze, Scan, Frames and Export on one `File` from 16 goroutines (run with `-race` in `make test`) give the sequential results; a stream is read by exactly one pass. The contract matrix is section 3b | L16 |
| Budgets | one test per limit that measures the heap or the work behind it against a budget derived from the limit (section 3a); in the normal tier | L17, LA14 |
| Ownership | `TestEventsBelongToTheSink` (a sink that overwrites every field of every event gets the same later events and summary), `TestFramesBelongToTheCaller` | L9, L16 |
| Fuzz | native Go fuzz targets with seed corpora from the fixtures; `make soak` (2 GiB in CI on pull requests) | LA14 |
| Oracle | `tshark` differential test (advisory), `interop/` | LA13 |
| Nightly | `nightly.yml`: fuzz 5 minutes per target, 3000 chaos seeds, 5 GiB soak, and every test on linux/386 (`GOARCH=386 go test ./...`, where `int` has 32 bits; no race detector there) | LA3, LA14 |
| Build | cross-compile matrix, static check, forbidden-import check | LA15 |
| Benchmarks | throughput, allocations, RSS at default limits | LA18 |

## 3. Fuzz targets

`FuzzPcapReader`, `FuzzPcapngReader`, `FuzzLinkIPTCP`, `FuzzFramer`, `FuzzDecodeRequest`, `FuzzDecodeResponse`, `FuzzPipeline` (random bytes wrapped as a pcap with plausible headers so the fuzzer gets past the first parser). Properties: no panic, termination, and for the pipeline: no recovered panic, every connection opened is closed, and every ADU's provenance refers to packets that exist and whose payload bytes are the ADU (checked through `File.Frames`). The two reader targets also read every packet back by its offset through the random-access index and require the same interface, link type, time and bytes as the sequential read gave, and that the interfaces and sections kept stay within their limits. Memory and work bounds are not a fuzzing matter: section 3a. CI runs the seed corpus on every pull request and a time-boxed run (30 s per target) on pull requests; the nightly run gives each target 5 minutes.

## 3a. Limits: budget tests

A limit is there for the memory or the work behind it, so each has a test that feeds input made to grow that state without end and measures the live heap (`runtime.ReadMemStats` after a collection, at the point where the state is largest) or the steps taken (a counter in the structure) against a budget derived from the limit. They run with the unit tests. Where a row names two tests, the first holds the limit's count or error at its boundary (limit − 1, limit, limit + 1), the second the heap or the work.

| Limit (`ARCHITECTURE.md` section 2) | Test | What is measured |
|---|---|---|
| `MaxConns` | `TestMaxConnsHeap` (`trace`) | heap with five times as many open connections as the limit: at most 8 KiB per tracked connection |
| `BufferPerDir`, `BufferTotal` | `TestOverflowAndBudget`, `TestHostileHolding`; `TestBufferBudgetHeap` (`internal/flow`) | heap with one-byte and full-size segments far past each limit: within the limit and a third |
| held segments: work | `TestHoldWork` (`internal/flow`) | steps to hold and to deliver a direction filled in descending order, and to keep the total budget full over 5,000 connections: a multiple of the logarithm of what is held, per segment |
| `FragmentBudget` | `TestDefragHostile`; `TestFragmentBudgetHeap` (`internal/link`) | heap with datagrams that never complete, many times the budget: within the budget and a quarter |
| fragments: work | `TestDefragWork` (`internal/link`) | steps to reassemble a datagram from every 8-byte fragment many times over, in descending order: the fragments' blocks, once each; a datagram is never charged more than its own length |
| `Options.MaxOutstanding` | `TestPairing` ("the outstanding limit"); `TestMaxOutstandingHeap` (`trace`) | heap of one connection with 10,000 requests that get no response |
| `AnalysisBudget` | `TestAnalysisBudget` (boundary, and 15,360 waiting requests against a budget for an eighth of them), `TestAnalysisBudgetUndecidedRoles`, `TestAnalysisBudgetChunks`, `TestChunksOfJunkAreDropped` (`trace`) | heap at the end of the trace: the budget, 8 KiB per connection and the reader's megabyte; the counter equals the requests decided early (the connections evicted) |
| `Analyze` keeps no flow list | `TestAnalyzeKeepsNoFlowList` (`trace`) | heap with 20 times as many short connections as `MaxConns` against twice as many: the same |
| `MaxFlows` | `TestMaxFlows` (`trace`) | flows returned and `flows_dropped` at limit − 1, limit, limit + 1 and 20 times the limit; heap of the result |
| `MaxInterfaces`, `MaxSections`, option text | `TestInterfaceLimit`, `TestSectionLimit`, `TestTextLimit` (boundaries, also at the defaults); `TestMetadataBudget` (`internal/pcapio`); `TestReaderLimits` (`trace`) | heap after reading 4 and 16 times as many named interfaces as the limit: the same, within the limit times 256 bytes and twice the text limit |
| random access | `TestFramesAllocation` (`trace`) | bytes allocated per `Frames` call with 2 and with 20,000 interfaces: the same |
| `MaxPacket`, pcapng block size | `TestSizeLimits` (`internal/pcapio`) | packets and blocks one below, at and one above the limit, and lengths of 2 GiB and 4 GiB: bytes allocated by the read stay under 1 MiB, whatever a length claims |
| `ResyncScan` | `TestJunkIsBounded`, `TestFraming` (`trace`); `TestChunksOfJunkAreDropped` | 2 MiB of bytes that frame as nothing are reported in runs of the limit; the provenance kept for them stays within a framer's window |
| timeline: connections, reorder buffer | `TestConnectionsAreForgotten`, `TestReorderBufferHeap` (`export/timeline`) | nothing is remembered of a closed connection (40,000 of them); heap of the held rows: under three times the buffer |
| analyzer keys, coverage ranges | `TestCaps`, `TestCoverageKeyCap` (`analyze`) | keys kept at the cap and the overflow counters (counts, not heap) |
| time conversion | `TestPcapNGTimestampRange` (`internal/pcapio`) | the first and last time that fit, one before and one after, for decimal and binary resolutions and offsets of either sign |
| payload range of a caller's reference | `TestFramesPayloadRange` (`trace`) | offsets and lengths of −1, 0, the packet length ± 1 and the 32-bit extremes |
| sequence distance of an old segment | `TestOldSegmentDistances` (`internal/flow`) | 1, the tail's length ± 1, 2^31 − 1, 2^31, 2^32 − 1; also on linux/386 every night |

## 3b. Contract test matrix

The lifecycle contract rows of otfabric/engineering `standards/lifecycle.md`, for this library. It is offline: a `File` has no `Close` (each pass opens and closes its inputs), a pass runs on the caller's goroutine and starts none, and nothing is sent.

| Row | Covered by | |
|---|---|---|
| L1 Close twice | `TestFramerCloseTwice` (`mbtcp`): the end-of-stream flush of a framer reports once | n/a for `trace.File`: it has no `Close` |
| L2 Concurrent Close | n/a | no type with `Close` is shared between goroutines |
| L3–L5 Close during read, write or handshake | n/a | offline: no `Close`, no writes to a shared stream, no handshake |
| L6 Cancel a pending operation | `TestChaosCancel` (Analyze cancelled at a random event), `TestWalkStops` (Walk cancelled, and stopped by its callback's error) | |
| L7, L8, L16 Late response, reconnect | n/a | no client |
| L9 Callback calls a public method | `TestCallbacksUseTheFile` (`trace`): a sink reads frames back and runs a scan on the same `File` inside its pass; a `Walk` callback runs another `Walk` | |
| L10 Callback calls Close | n/a | no `Close` |
| L11 Slow callback | n/a | callbacks are synchronous on the caller's goroutine: a slow sink only slows its own pass (documented on `trace.Sink`) |
| L12 Bounded queues at capacity | `TestPairing` ("the outstanding limit"), `TestAnalysisBudget` (boundary), `TestAnalysisBudgetUndecidedRoles` (ADUs held while roles are undecided), `TestCaps`, `TestCoverageKeyCap` (`analyze`), `TestReorderBuffer` (`export/timeline`) | |
| L13 Concurrent sessions | `TestConcurrentUse`: Analyze, Scan, Frames and Export from 16 goroutines on one `File`, with `-race` | |
| L14 Failure during startup | `TestOpenErrors` (`trace`): a pass that cannot open or recognise an input returns the error and closes what it opened | no descriptor count is asserted |
| L15 Shutdown(ctx) | n/a | nothing runs after a pass returns |

## 4. Oracle: Wireshark's dissector

Where `tshark` is installed, `TestTsharkOracle` in `interop/tshark_test.go` (build tag `interop`, `make interop`; an advisory, non-gating CI job on Linux; `MBTRACE_REQUIRE_INTEROP=1` fails it without tshark) runs it over a generated trace and compares per transaction: MBAP transaction ID, unit, function code, reference number, word/bit count, exception code and request/response linking. The field names were checked with `tshark -G fields | grep -i modbus` on tshark 4.6.9 and are mapped in the test. Differences are triaged by hand: tshark is a reference, not the truth (its pairing heuristics are its own); a confirmed bug on either side gets a regression fixture.

Triaged so far (tshark 4.6.9):

- tshark does not link exception responses to their requests (`modbus.request_frame` is empty on them); the test does not compare linking for exceptions.
- tshark does not frame an MBAP header split across segments (DECISIONS D7); the oracle trace sends each ADU in one segment.

## 5. Pinned tools

The Makefile pins `mbcapctl` (`MBCAPCTL_VERSION`, go-modbus-capture v0.0.2) and `modbusctl` (`MODBUSCTL_VERSION`: its v3 tags are not Go module versions, so the pin is the pseudo-version of the v3.2.0 commit), never `@latest`. `make tools` installs both with `go install`; `make replay` runs `TestReplayEndToEnd` (LA10) with `MBTRACE_REQUIRE_TOOLS=1`, so a missing tool fails. The CI job `replay` does both. Locally the test finds the tools through `$MBCAPCTL` and `$MODBUSCTL` or `PATH`, and skips with a message when they are absent.

LA10 scripts a client polling holding registers, coils and a paged FC43 identity, exports MBCAP, JSON Lines and long CSV, checks each with `mbcapctl verify`, then serves the capture with `modbusctl server static --at` and `server replay --speed 1000 --loops 1` and reads it back with a go-modbus client: the values equal the script's. For the replay the test reads until the last values are served, within a deadline of 10 s; it does not wait a fixed time.

## 5a. Fixture and benchmarks

`testdata/plant.pcapng` is built by `plant()` in `trace/fixture_test.go`; `TestFixture` compares it byte for byte and `make golden` rewrites it. `make bench` runs `BenchmarkScan` and `BenchmarkAnalyze` over a 32 MiB generated trace; CI reports them without gating.

## 6. What must stay true

- Fixtures never contain customer data.
- A new quality condition, a new reason code or a new flag comes with a synthetic scenario that produces it.
- Golden files are regenerated only by an explicit `make golden` and reviewed in the diff.
- Benchmarks and numbers in `ARCHITECTURE.md` section 12 name the machine and commit they were measured on.

## When CI runs

| Event | Workflow | What runs |
|---|---|---|
| Pull request | `pr.yml` | `docs.yml` (docsync, otfabric-policy) always; `ci.yml` unless every changed file is documentation; then `OT Fabric Required Checks` |
| Push to a branch | none | nothing; dispatch `ci.yml` to test a branch without a pull request |
| Push to `main` | `docs.yml` | the light checks; the merged commit was tested as the pull request's merge commit |
| Schedule | `nightly.yml` | the scheduled runs, on `main` |
| Release | `release.yml` | the release workflow tests the release commit again |

Documentation means an added or modified `*.md` file outside `.github/`, `testdata/` and `vendor/`, other than `AGENTS.md` and `CLAUDE.md`, and other than `docs/COVERAGE.md`, which code reads. A deleted or renamed document, or any other file, runs everything. `OT Fabric Required Checks` fails unless every job that applies succeeded; its summary lists them.
