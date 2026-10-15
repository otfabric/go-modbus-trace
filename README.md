# go-modbus-trace

Read a packet trace (pcap or pcapng from tcpdump, Wireshark, dumpcap or tshark), find the Modbus/TCP traffic in it, and get a typed, time-ordered view of what happened: connections, requests and responses, exceptions, unanswered requests. Analyze devices, units and poll patterns, export a timeline, extract a sub-trace, and export an [MBCAP](https://github.com/otfabric/go-modbus-capture) file that [modbusctl](https://github.com/otfabric/modbusctl) can replay as a virtual device.

Offline only: the library never captures live and never sends anything. Pure Go, no cgo, no libpcap.

**Status: v0.1.0, milestones L0–L4 done.** The design is in [AGENTS.md](AGENTS.md), [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md), [docs/TESTING.md](docs/TESTING.md) and [docs/DECISIONS.md](docs/DECISIONS.md). The MBCAP format is still a draft (go-modbus-capture v0.0.x); every export says so.

## mbtracectl

```sh
go install github.com/otfabric/go-modbus-trace/cmd/mbtracectl@latest
```

```sh
mbtracectl info    site.pcapng        # format, interfaces, drops, snap length, connections, quality
mbtracectl flows   site.pcapng        # the Modbus/TCP flows: client, server, score, role, gaps
mbtracectl flows --all --json -       # every TCP flow, as JSON, from standard input
mbtracectl summary site.pcapng        # devices, units, functions, latency, poll patterns, addresses read
mbtracectl timeline site.pcapng --unit 1 --fc 3 --from 10m --to 20m
mbtracectl export timeline site.pcapng -o site.csv --status exception,unanswered
mbtracectl extract site.pcapng --server 10.0.0.2:502 -o inverter.pcapng   # opens in Wireshark
mbtracectl export mbcap site.pcapng -o site.mbcap --report site.report.json
```

Flows are classed by their traffic, not their port, so Modbus on 1502 or 5021 is found too. Several files (a ring buffer, say) are read as one trace: `mbtracectl summary ring_*.pcapng`. Every flag can also be set as `MBTRACECTL_<FLAG>`; exit codes are in [docs/exitcodes.md](docs/exitcodes.md) and the JSON output, with a JSON Schema for each document, in [docs/json-output.md](docs/json-output.md).

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

$ mbtracectl export mbcap testdata/plant.pcapng -o plant.mbcap
123 transactions, 122 samples written
excluded: write_function=1
target 1: 10.0.0.2:502 unit 1 (61 samples, 1 clients)
target 2: 10.0.0.3:502 unit 1 (30 samples, 1 clients)
target 3: 10.0.0.3:502 unit 2 (31 samples, 1 clients)
warning: target 2: unit_collision: another target uses the same unit ID: ...
warning: target 3: unit_collision: another target uses the same unit ID: ...
replay: about 12 MiB in memory

$ modbusctl server replay --input plant.mbcap --target 1 --listen 127.0.0.1 --port 1502 --before-first absent
```

Only reads that were answered and paired with certainty become samples; writes, vendor functions and anything uncertain are counted in the report by reason and never replayed. The rules are in [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md) and the whole workflow in [docs/REPLAY-WORKFLOW.md](docs/REPLAY-WORKFLOW.md).

## Library

```go
f, err := trace.Open("site.pcapng")            // or trace.OpenReader(os.Stdin)
sum, err := trace.Analyze(ctx, f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
	if t := e.Txn; t != nil {
		fmt.Println(t.Time(), t.Server, t.Unit, t.Status, t.Summary) // "Read 62 holding registers @ 4096"
	}
	return nil
}))
```

The analyzers in `analyze` (devices, poll patterns, address coverage), `export/mbcapexport` and `export/subtrace` are sinks and helpers over the same scan. More in [docs/API.md](docs/API.md); every function the decoder covers is in [docs/COVERAGE.md](docs/COVERAGE.md).

`trace/tracetest` builds synthetic traces with a known ground truth, for this module's tests and for applications built on it.

The desktop application built on this library is [otfabric/modbus-trace-explorer](https://github.com/otfabric/modbus-trace-explorer).

## License

MIT
