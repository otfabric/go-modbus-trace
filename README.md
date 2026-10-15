# go-modbus-trace

Read a packet trace (pcap or pcapng from tcpdump, Wireshark, dumpcap or tshark), find the Modbus/TCP traffic in it, and get a typed, time-ordered view of what happened: connections, requests and responses, exceptions, unanswered requests. Analyze devices, units and poll patterns, export a timeline, extract a sub-trace, and export an [MBCAP](https://github.com/otfabric/go-modbus-capture) file that [modbusctl](https://github.com/otfabric/modbusctl) can replay as a virtual device.

Offline only: the library never captures live and never sends anything. Pure Go, no cgo, no libpcap.

**Status: not implemented yet.** This repository starts from its handoff documents. Start with [AGENTS.md](AGENTS.md), then [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md) and [docs/TESTING.md](docs/TESTING.md).

The intended workflow (command names are proposals):

```sh
mbtracectl flows   site.pcapng
mbtracectl summary site.pcapng
mbtracectl export mbcap site.pcapng -o site.mbcap --report site.report.json
modbusctl server replay --input site.mbcap --listen 127.0.0.1 --port 1502 --before-first absent
```

The desktop application built on this library is [otfabric/modbus-trace-explorer](https://github.com/otfabric/modbus-trace-explorer).

## License

MIT
