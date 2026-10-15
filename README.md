# go-modbus-trace

Read a packet trace (pcap or pcapng from tcpdump, Wireshark, dumpcap or tshark), find the Modbus/TCP traffic in it, and get a typed, time-ordered view of what happened: connections, requests and responses, exceptions, unanswered requests. Analyze devices, units and poll patterns, export a timeline, extract a sub-trace, and export an [MBCAP](https://github.com/otfabric/go-modbus-capture) file that [modbusctl](https://github.com/otfabric/modbusctl) can replay as a virtual device.

Offline only: the library never captures live and never sends anything. Pure Go, no cgo, no libpcap.

**Status: in development (milestone L1 of 4).** Reading traces, finding the Modbus/TCP flows and framing them works; decoding, pairing, the timeline and the exports follow. The design is in [AGENTS.md](AGENTS.md), [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md), [docs/TESTING.md](docs/TESTING.md) and [docs/DECISIONS.md](docs/DECISIONS.md).

## mbtracectl

```sh
go install github.com/otfabric/go-modbus-trace/cmd/mbtracectl@latest
```

```sh
mbtracectl info  site.pcapng          # format, interfaces, drops, snap length, connections, quality
mbtracectl flows site.pcapng          # the Modbus/TCP flows: client, server, score, role, gaps
mbtracectl flows --all --json -       # every TCP flow, as JSON, from standard input
```

Flows are classed by their traffic, not their port, so Modbus on 1502 or 5021 is found too. Every flag can also be set as `MBTRACECTL_<FLAG>`; exit codes are in [docs/exitcodes.md](docs/exitcodes.md) and the JSON output in [docs/json-output.md](docs/json-output.md).

The intended workflow once the exports exist (L3):

```sh
mbtracectl flows   site.pcapng
mbtracectl summary site.pcapng
mbtracectl export mbcap site.pcapng -o site.mbcap --report site.report.json
modbusctl server replay --input site.mbcap --listen 127.0.0.1 --port 1502 --before-first absent
```

## Library

```go
f, err := trace.Open("site.pcapng")            // or trace.OpenReader(os.Stdin)
sum, flows, err := trace.Scan(ctx, f, trace.ScanOptions{})
for _, fl := range flows {
	if fl.Class == trace.ClassModbus {
		fmt.Println(fl.A, "->", fl.B, fl.Score)
	}
}
```

`trace/tracetest` builds synthetic traces with a known ground truth, for this module's tests and for applications built on it.

The desktop application built on this library is [otfabric/modbus-trace-explorer](https://github.com/otfabric/modbus-trace-explorer).

## License

MIT
