# go-modbus-trace

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-modbus-trace.svg)](https://pkg.go.dev/github.com/otfabric/go-modbus-trace)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Status](https://github.com/otfabric/go-modbus-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-modbus-trace/actions/workflows/ci.yml)
[![Code Coverage](https://codecov.io/gh/otfabric/go-modbus-trace/graph/badge.svg)](https://codecov.io/gh/otfabric/go-modbus-trace)
[![Latest Release](https://img.shields.io/github/v/release/otfabric/go-modbus-trace?label=release)](https://github.com/otfabric/go-modbus-trace/releases)

Read a packet trace (pcap or pcapng from tcpdump, Wireshark, dumpcap or tshark), find the Modbus/TCP traffic in it, and get a typed, time-ordered view of what happened: connections, requests and responses, exceptions, unanswered requests. Analyze devices, units and poll patterns, export a timeline, extract a sub-trace, and export an [MBCAP](https://github.com/otfabric/go-modbus-capture) file that [modbusctl](https://github.com/otfabric/modbusctl) can replay as a virtual device.

Offline only: the library never captures live and never sends anything. Pure Go, no cgo, no libpcap.

**Status: v0.1.0.** Every milestone of the plan (L0–L4) is implemented; the requirements carry their status in [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) and the open questions are at the end of [docs/DECISIONS.md](docs/DECISIONS.md). The MBCAP format is still a draft (go-modbus-capture v0.0.x); every export says so.

## mbtracectl

Download a binary from the [releases](https://github.com/otfabric/go-modbus-trace/releases) (Linux amd64, arm64 and armv7, macOS, Windows; static, no libpcap), or:

```sh
go install github.com/otfabric/go-modbus-trace/cmd/mbtracectl@latest
```

| Command | What it tells you |
|---|---|
| `info TRACE...` | format, interfaces and link types, capture drops, snap length, connections, quality counters (per file) |
| `flows TRACE...` | the TCP flows that carry Modbus/TCP: client, server, score, how the roles were decided, gaps |
| `summary TRACE...` | per server and unit: transactions by status and function, clients, latency; poll patterns; addresses read and written |
| `timeline TRACE...` | every transaction in time order, filtered; text, CSV or JSON Lines |
| `export timeline TRACE... -o out.csv\|.jsonl` | the same timeline as a file |
| `extract TRACE... -o out.pcapng` | the packets of chosen connections, for Wireshark |
| `export mbcap TRACE... -o out.mbcap` | a capture that `modbusctl` replays as a virtual device, with a report |
| `version` | version, tag, commit, build date |

Several files are read as one trace (a ring buffer: `summary ring_*.pcapng`), `-` reads standard input, `--json` gives machine output with a JSON Schema per document ([docs/json-output.md](docs/json-output.md)), every flag can be set as `MBTRACECTL_<FLAG>`, and the exit codes are 0, 1 and 2 ([docs/exitcodes.md](docs/exitcodes.md)).

### Recipes

```sh
# Which devices are on this capture, and on which ports? (Modbus on 1502 or 5021 is found by its traffic.)
mbtracectl flows site.pcapng

# Every exception and unanswered request of unit 3, with the request that caused it.
mbtracectl timeline site.pcapng --unit 3 --status exception,unanswered

# Responses slower than 200 ms, as CSV for a spreadsheet.
mbtracectl export timeline site.pcapng --slow 200ms --flag slow -o slow.csv

# Who wrote to holding register 40100 (zero-based 40099), and when?
mbtracectl timeline site.pcapng --class write --range holding:40099-40099

# Ten minutes of one inverter's traffic, as a small pcapng for Wireshark.
mbtracectl extract site.pcapng --server 10.0.0.2:502 --from 10m --to 20m -o inverter.pcapng

# Straight from a gateway, without storing the trace there.
ssh gw 'tcpdump -i eth0 -U -w - port 502' | mbtracectl export mbcap - -o site.mbcap

# The poll patterns as JSON, for a script.
mbtracectl summary site.pcapng --json | jq '.patterns.patterns[] | {client, server, unit, summary, interval: .interval.p50_ns}'
```

### From a trace to a virtual device

[`testdata/plant.pcapng`](testdata/plant.pcapng) is a synthetic minute of a SCADA host polling an inverter and a two-unit gateway.

```text
$ mbtracectl flows testdata/plant.pcapng
ID  CLIENT           SERVER        CLASS       SCORE  ROLE  OPEN  CLOSE  PACKETS  ADUS   GAPS  FIRST
1   10.0.0.10:40100  10.0.0.2:502  modbus_tcp  1.00   syn   syn   fin    129      62/62  0     2026-10-15T08:00:00Z
2   10.0.0.10:40200  10.0.0.3:502  modbus_tcp  1.00   syn   syn   fin    127      61/61  0     2026-10-15T08:00:00.0003Z

$ mbtracectl summary testdata/plant.pcapng
...
poll patterns (6 of 6):
CLIENT     SERVER        UNIT  REQUEST                          COUNT  INTERVAL P50  JITTER   VOLATILITY
10.0.0.10  10.0.0.2:502  1     Read 10 holding registers @ 0    60     1.0002s       1.9ms    1.00
10.0.0.10  10.0.0.3:502  1     Read 4 input registers @ 0       30     2.001s        2.351ms  1.00
...
addresses read (written):
  10.0.0.2:502 unit 1 holding: 0-9 (5)
  10.0.0.3:502 unit 1 input: 0-3
  10.0.0.3:502 unit 2 input: 0-3

$ mbtracectl timeline testdata/plant.pcapng --status exception
TIME                       CONN  CLIENT           SERVER        UNIT  TID   STATUS     LATENCY  SUMMARY
2026-10-15T08:00:10.0054Z  2     10.0.0.10:40200  10.0.0.3:502  2     5000  exception  100µs    Read 1 input register @ 100: exception 2 (illegal data address)

$ mbtracectl export mbcap testdata/plant.pcapng -o plant.mbcap --name 10.0.0.2:502/1=Inverter
123 transactions, 122 samples written
excluded: write_function=1
target 1: Inverter (61 samples, 1 client)
target 2: 10.0.0.3:502 unit 1 (30 samples, 1 client)
target 3: 10.0.0.3:502 unit 2 (31 samples, 1 client)
warning: target 1: unit_collision: another target uses the same unit ID: replay them separately (--target, --port) or remap one with --unit
warning: target 2: unit_collision: another target uses the same unit ID: replay them separately (--target, --port) or remap one with --unit
replay: about 12 MiB in memory

$ modbusctl server replay --input plant.mbcap --target 1 --listen 127.0.0.1 --port 1502 --before-first absent
```

Only reads that were answered and paired with certainty become samples; writes, vendor functions and anything uncertain are counted in the report by reason and never replayed. What a replay can and cannot reproduce is in [docs/REPLAY-WORKFLOW.md](docs/REPLAY-WORKFLOW.md); the rules in [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md).

## Library

```sh
go get github.com/otfabric/go-modbus-trace@latest
```

Every transaction, as it completes ([`trace.Analyze`](trace/example_test.go)):

```go
f, err := trace.Open("site.pcapng") // or trace.OpenFiles(paths...), trace.OpenReader(os.Stdin)
sum, err := trace.Analyze(ctx, f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
	if t := e.Txn; t != nil {
		fmt.Println(t.Time(), t.Server, t.Unit, t.Status, t.Summary)
	}
	return nil
}))
// 2026-10-15 08:00:00.0006 10.0.0.2:502 1 ok Read Device Identification
// ...
fmt.Println(sum.Transactions) // map[exception:1 ok:122]
```

Devices, poll patterns and address coverage in one pass ([`analyze`](analyze/example_test.go)):

```go
dev, pat, cov := analyze.NewDevices(), analyze.NewPatterns(), analyze.NewCoverage()
_, err = trace.Analyze(ctx, f, trace.Options{}, analyze.Tee(dev, pat, cov))
for _, p := range pat.Result().Patterns {
	fmt.Printf("%s polls %q every %v\n", p.Client, p.Summary, time.Duration(p.Interval.P50NS))
}
// 10.0.0.10 polls "Read 10 holding registers @ 0" every 1.0002s
```

The raw bytes of any transaction, read back by reference ([`File.Frames`](trace/example_test.go)):

```go
frames, err := f.Frames(txn.Response.Refs)
fmt.Printf("frame %d: % x\n", frames[0].Ref.Frame, frames[0].Payload)
// frame 56: 13 88 00 00 00 03 02 84 02
```

An MBCAP capture and its report ([`mbcapexport`](export/mbcapexport/example_test.go)), or the decision for one transaction without exporting (`mbcapexport.Classify`):

```go
rep, err := mbcapexport.Export(ctx, f, trace.Options{}, mbcapexport.Options{Producer: "my-app 1.0"},
	func(h capture.Header) (capture.Writer, error) { return mbcap.NewWriter(out, h, nil) })
fmt.Println(rep.SamplesWritten, rep.Excluded["write_function"]) // 122 1
```

A sub-trace for Wireshark ([`subtrace`](export/subtrace/example_test.go)), a timeline as CSV or JSON Lines (`export/timeline`), and the decoder on its own (`mbtcp.Decode`, `mbtcp.Summary`). The map of packages is [docs/API.md](docs/API.md); every function the decoder covers is in [docs/COVERAGE.md](docs/COVERAGE.md).

The library is offline (no sockets, no live capture, no wall clock), bounded in memory for any trace size, deterministic, and safe for concurrent passes over one file. `trace/tracetest` builds synthetic traces with a known ground truth, for this module's tests and for applications built on it.

The desktop application built on this library is [otfabric/modbus-trace-explorer](https://github.com/otfabric/modbus-trace-explorer).

## Documentation

| Document | Contents |
|---|---|
| [docs/REPLAY-WORKFLOW.md](docs/REPLAY-WORKFLOW.md) | from a trace to a virtual device, and what a replay reproduces |
| [docs/json-output.md](docs/json-output.md), [docs/schema/](docs/schema/) | the CLI's JSON output and its JSON Schemas |
| [docs/API.md](docs/API.md) | the packages of the library |
| [docs/COVERAGE.md](docs/COVERAGE.md) | every Modbus function the decoder knows (generated) |
| [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md) | what is exported, the reasons for leaving out, the report |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), [docs/DECISIONS.md](docs/DECISIONS.md) | the design, the requirements with their status, and why |
| [docs/TESTING.md](docs/TESTING.md) | how it is tested: ground truth, chaos, fuzzing, the replay, the tshark oracle |
| [RELEASE.md](RELEASE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) | releases, contributing, reporting a vulnerability |

## License

MIT
