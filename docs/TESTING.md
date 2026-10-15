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
| Determinism | double run, cross-OS run, CLI equals library | LA11 |
| Fuzz | native Go fuzz targets with seed corpora from the fixtures | LA14 |
| Oracle | `tshark` differential test (advisory) | LA13 |
| Build | cross-compile matrix, static check, forbidden-import check | LA15 |
| Benchmarks | throughput, allocations, RSS at default limits | LA18 |

## 3. Fuzz targets

`FuzzPcapReader`, `FuzzPcapngReader`, `FuzzLinkIPTCP`, `FuzzFramer`, `FuzzDecodeRequest`, `FuzzDecodeResponse`, `FuzzPipeline` (random bytes wrapped as a pcap with plausible headers so the fuzzer gets past the first parser). Properties: no panic, no allocation beyond the configured limits, termination, and for the pipeline: every ADU's provenance refers to packets that exist and whose payload bytes contain the ADU. CI runs the seed corpus on every push and a time-boxed run (30 s per target) on pull requests; a longer scheduled run is optional.

## 4. Oracle: Wireshark's dissector

Where `tshark` is installed (a separate, advisory CI job on Linux), run it over the fixtures and the generated traces and compare per transaction: MBAP transaction ID, unit, function code, reference number, word/bit count, exception code and request/response linking. Field names differ between versions: first check them with `tshark -G fields | grep -i modbus` and write the mapping in `internal/oracle`. Differences are triaged by hand: tshark is a reference, not the truth (its pairing heuristics are its own); a confirmed bug on either side gets a regression fixture.

## 5. Pinned tools

CI installs the pinned releases of `mbcapctl` (go-modbus-capture) and `modbusctl` (v3.2.0 or newer) with `go install ...@<version>` from the versions in `tools.go`/the Makefile, never `@latest`. A test that needs them and finds none fails in CI and skips with an explicit message locally.

## 6. What must stay true

- Fixtures never contain customer data.
- A new quality condition, a new reason code or a new flag comes with a synthetic scenario that produces it.
- Golden files are regenerated only by an explicit `make golden` and reviewed in the diff.
- Benchmarks and numbers in `ARCHITECTURE.md` section 12 name the machine and commit they were measured on.
