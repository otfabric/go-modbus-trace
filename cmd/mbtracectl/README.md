# mbtracectl

`mbtracectl` reads packet traces (pcap or pcapng, plain or gzip, from tcpdump,
Wireshark, dumpcap or tshark) and reports the Modbus/TCP traffic in them. It
never captures live and never sends anything: the trace is its only input. It
is a nested module of [go-modbus-trace](../../README.md), so the library does
not depend on cobra.

Download a binary from the
[releases](https://github.com/otfabric/go-modbus-trace/releases), or build it
from a checkout of go-modbus-trace with `make build` (`./bin/mbtracectl`).

| Command | What it does |
|---|---|
| `mbtracectl info TRACE...` | Describe each trace file: format, interfaces, link types, drops, snap length, connections, quality |
| `mbtracectl flows TRACE...` | List the TCP flows with their Modbus score, class and roles |
| `mbtracectl summary TRACE...` | Summarise the Modbus traffic: devices, poll patterns, address coverage, latency, quality |
| `mbtracectl timeline TRACE...` | Write the timeline of events: text, CSV or JSON Lines on stdout |
| `mbtracectl export timeline TRACE... -o OUT` | Write the timeline as CSV or JSON Lines to a file |
| `mbtracectl export mbcap TRACE... -o OUT` | Export the trace's reads as an MBCAP capture that modbusctl can replay as a virtual device |
| `mbtracectl extract TRACE... -o OUT.pcapng` | Write the packets of selected connections, optionally in a time window, as a pcapng file |
| `mbtracectl version` | Print the version |
| `mbtracectl completion bash\|zsh\|fish\|powershell` | Generate the shell completion script |

`mbtracectl export` groups the two exports. A trace argument is a path, or `-`
for standard input; several files given in time order are one trace. The flags
of every command are in [docs/commands.md](docs/commands.md).

`--json` writes one JSON document to stdout instead of text
([JSON output](../../docs/json-output.md), with a JSON Schema per document).
Every flag can also be set by an environment variable: `MBTRACECTL_` and the
flag name in capitals with dashes as underscores (`MBTRACECTL_JSON=1`,
`MBTRACECTL_SERVER_PORT=502,1502`); a flag on the command line wins. The exit
codes are in [docs/exitcodes.md](docs/exitcodes.md).

## Examples

```sh
# Which devices are on this capture, and on which ports?
mbtracectl flows site.pcapng

# Every exception and unanswered request of unit 3.
mbtracectl timeline site.pcapng --unit 3 --status exception,unanswered

# Responses slower than 200 ms, as CSV.
mbtracectl export timeline site.pcapng --slow 200ms --flag slow -o slow.csv

# Ten minutes of one server's traffic, as a pcapng for Wireshark.
mbtracectl extract site.pcapng --server 10.0.0.2:502 --from 10m --to 20m -o inverter.pcapng

# A capture for modbusctl to replay, with a label for one target.
mbtracectl export mbcap site.pcapng -o site.mbcap --name 10.0.0.2:502/1=Inverter

# The version, as JSON.
mbtracectl version --json
```

More recipes, and a walk from a trace to a virtual device, are in the
[go-modbus-trace README](../../README.md#mbtracectl) and
[docs/REPLAY-WORKFLOW.md](../../docs/REPLAY-WORKFLOW.md).
