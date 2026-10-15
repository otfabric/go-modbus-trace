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
| End to end | trace -> `export mbcap` -> pinned `mbcapctl verify` -> pinned `modbusctl server replay/static` -> go-modbus client reads equal the scripted values | LA10 |
| Determinism | double run; `TestGoldenOutputs` hashes every output of `testdata/plant.pcapng` (MBCAP, JSON Lines, CSV, timeline, sub-trace, summary, flows, report) against `testdata/plant.outputs.json` on every target's own runner (cross-OS); `TestCLIEqualsLibrary` | LA11 |
| Chaos | `trace/chaos_test.go`: seeded random traffic (many clients, servers and units, every function class, malformed and vendor PDUs, pipelining, reused and unanswered IDs, orphans, TCP faults, IP fragments, clock steps, tiny limits, corrupted bytes, cancellation) through every consumer, checking invariants that hold for any input: no recovered panic, counts that agree, provenance inside the trace and carrying the ADU, the export identity, a capture that reads back, a sub-trace that re-analyses the same. 150 seeds per run (`MBTRACE_CHAOS_SEEDS`, `MBTRACE_CHAOS_SEED`) | LA3, LA8, LA14 |
| Concurrency | `TestConcurrentUse`: Analyze, Scan, Frames and Export on one `File` from 16 goroutines (run with `-race` in `make test`) give the sequential results; a stream is read by exactly one pass | L16 |
| Fuzz | native Go fuzz targets with seed corpora from the fixtures; `make soak` (2 GiB in CI on pull requests) | LA14 |
| Oracle | `tshark` differential test (advisory) | LA13 |
| Build | cross-compile matrix, static check, forbidden-import check | LA15 |
| Benchmarks | throughput, allocations, RSS at default limits | LA18 |

## 3. Fuzz targets

`FuzzPcapReader`, `FuzzPcapngReader`, `FuzzLinkIPTCP`, `FuzzFramer`, `FuzzDecodeRequest`, `FuzzDecodeResponse`, `FuzzPipeline` (random bytes wrapped as a pcap with plausible headers so the fuzzer gets past the first parser). Properties: no panic, termination, and for the pipeline: no recovered panic, every connection opened is closed, and every ADU's provenance refers to packets that exist and whose payload bytes are the ADU (checked through `File.Frames`). Memory bounds are tested by the hostile-input tests of `internal/flow` and `internal/link` (empty and one-byte held segments, a million tiny fragments) and by the soak run. CI runs the seed corpus on every push and a time-boxed run (30 s per target) on pull requests; a longer scheduled run is optional.

## 4. Oracle: Wireshark's dissector

Where `tshark` is installed, `TestTsharkOracle` in `trace/oracle_test.go` (run with `MBTRACE_ORACLE=1`; an advisory, non-gating CI job on Linux) runs it over a generated trace and compares per transaction: MBAP transaction ID, unit, function code, reference number, word/bit count, exception code and request/response linking. The field names were checked with `tshark -G fields | grep -i modbus` on tshark 4.6.9 and are mapped in the test. Differences are triaged by hand: tshark is a reference, not the truth (its pairing heuristics are its own); a confirmed bug on either side gets a regression fixture.

Triaged so far (tshark 4.6.9):

- tshark does not link exception responses to their requests (`modbus.request_frame` is empty on them); the test does not compare linking for exceptions.
- tshark does not frame an MBAP header split across segments (DECISIONS D7); the oracle trace sends each ADU in one segment.

## 5. Pinned tools

The Makefile pins `mbcapctl` (`MBCAPCTL_VERSION`, go-modbus-capture v0.0.2) and `modbusctl` (`MODBUSCTL_VERSION`: its v3 tags are not Go module versions, so the pin is the pseudo-version of the v3.2.0 commit), never `@latest`. `make tools` installs both with `go install`; `make replay` runs `TestReplayEndToEnd` (LA10) with `MBTRACE_REQUIRE_TOOLS=1`, so a missing tool fails. The CI job `replay` does both. Locally the test finds the tools through `$MBCAPCTL` and `$MODBUSCTL` or `PATH`, and skips with a message when they are absent.

LA10 scripts a client polling holding registers, coils and a paged FC43 identity, exports MBCAP, JSON Lines and long CSV, checks each with `mbcapctl verify`, then serves the capture with `modbusctl server static --at` and `server replay --speed 1000 --loops 1` and reads it back with a go-modbus client: the values equal the script's.

## 5a. Fixture and benchmarks

`testdata/plant.pcapng` is built by `plant()` in `trace/fixture_test.go`; `TestFixture` compares it byte for byte and `make golden` rewrites it. `make bench` runs `BenchmarkScan` and `BenchmarkAnalyze` over a 32 MiB generated trace; CI reports them without gating.

## 6. What must stay true

- Fixtures never contain customer data.
- A new quality condition, a new reason code or a new flag comes with a synthetic scenario that produces it.
- Golden files are regenerated only by an explicit `make golden` and reviewed in the diff.
- Benchmarks and numbers in `ARCHITECTURE.md` section 12 name the machine and commit they were measured on.
