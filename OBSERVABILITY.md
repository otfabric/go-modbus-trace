# Observability

The library logs nothing and has no metrics hooks: it analyses a file and returns results. The results carry their own quality information, and that is what to read.

| What | Where |
|---|---|
| TCP and framing problems in the trace | `trace.Quality`: retransmissions, out-of-order segments, gaps, reassembly overflow and budget, resyncs, junk bytes, foreign frames, ADUs cut by the snap length |
| Entries dropped at a bounded table | a counter for each limit in `trace.Limits` ([LIMITATIONS.md](LIMITATIONS.md)) |
| What an MBCAP export left out | `mbcapexport.Report`; see [docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md) |
| Capture drops, interfaces, snap length | `mbtracectl info` |

`mbtracectl` reports errors on standard error, shows progress when standard error is a terminal, and gives machine output with `--json`. Its exit codes are in [docs/exitcodes.md](docs/exitcodes.md), its JSON in [docs/json-output.md](docs/json-output.md).
