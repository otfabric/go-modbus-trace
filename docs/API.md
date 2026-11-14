# Library API

The godoc of each package is the reference, with runnable examples (`example_test.go` in `trace`, `analyze`, `export/mbcapexport` and `export/subtrace`, run on `testdata/plant.pcapng` by `go test`); this page is the map.

| Package | Use it to |
|---|---|
| `trace` | `Open(path)`, `OpenFiles(paths...)` (several files as one trace: every frame reference names its `Part`), `OpenReader(r)`; `Scan` (file summary, TCP flows with a Modbus score: one cheap pass); `Analyze` (every event: connections, transactions, gaps, resyncs, notes) into a `Sink`; `File.Frames(refs)` to re-read the packets of an ADU (files only, not streams); `Walk` (every raw packet with its connection ID, for extractors) |
| `model` | the events: `Event`, `Connection`, `Transaction`, `ADU`, `FrameRef`, `Gap`, `Resync`, `Note`; statuses and flags; `EventSemanticsVersion`. JSON Schema: `docs/schema/event-1.schema.json` |
| `mbtcp` | `Decode` a PDU (fields with byte ranges, ranges, class, warnings), `CheckPair`, `ValueAt`, `Summary`, `Coverage`; the MBAP `Framer`; `DecideRole` |
| `selection` | the transaction predicate shared by the CLI, the exporters and applications |
| `analyze` | streaming, bounded sinks, composed with `Tee`: `NewOverview`, `NewDevices` (per server and unit: functions, statuses, clients, latency), `NewPatterns` (poll patterns: interval, jitter, volatility), `NewCoverage` (address ranges read and written); `Histogram` |
| `export/timeline` | the timeline as CSV or JSON Lines |
| `export/mbcapexport` | `Export` an MBCAP capture through any go-modbus-capture writer, with a `Report` (exclusions by reason, targets, warnings, replay memory estimate); `Classify` one transaction |
| `export/subtrace` | `Extract` the packets of selected connections as pcapng |
| `trace/tracetest` | synthetic traces with a ground truth, for tests |

```go
f, err := trace.Open("site.pcapng")
sum, err := trace.Analyze(ctx, f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
	if t := e.Txn; t != nil && t.Status == model.StatusOK {
		fmt.Println(t.Time(), t.Server, t.Unit, t.Summary)
	}
	return nil
}))
frames, err := f.Frames(txn.Response.Refs) // the packets that carried a response

dev := analyze.NewDevices()
pat := analyze.NewPatterns()
_, err = trace.Analyze(ctx, f, trace.Options{}, analyze.Tee(dev, pat))
devices, patterns := dev.Result(), pat.Result()

rep, err := mbcapexport.Export(ctx, f, trace.Options{}, mbcapexport.Options{Producer: "my-app 1.0"},
	func(h capture.Header) (capture.Writer, error) { return mbcap.NewWriter(out, h, nil) })
```

Rules that hold for every function: no network I/O, no wall clock (times are the trace's), the same input
and options give the same events, a malformed packet is counted and never fails the pass, a panic in one
packet (or in the flush at the end) is recovered and counted (`FileSummary.InternalErrorCount`) and reported
as a note. A `File` of paths is safe for concurrent passes and `Frames` calls; a stream `File` is read by one
pass (`ErrConsumed` for the others).

Memory: what a pass holds is bounded by `trace.Limits` (and `Options.MaxOutstanding`) for any trace size: at
most the sum of the limits and the fixed state of the tracked connections (`docs/ARCHITECTURE.md` section 2
has the table, with the reason for each default and its counter). `Analyze` keeps nothing of a connection
that closed. The flow list `Scan` returns is its result and grows with the number of connections, about 450
bytes each, up to `Limits.MaxFlows`.

Callbacks: a `Sink`, a `Walk` function and `Progress` are called synchronously on the goroutine that runs the
pass, one call at a time. An event belongs to the sink that receives it, with everything it points to: the
library neither reads nor changes it afterwards. A `Frame` belongs to the caller of `Frames`; its `Payload`
is a part of its `Data`, not a copy. A `RawPacket`'s `Data` is valid only during the `Walk` callback. A
callback may call `Frames` and start other passes on the same `File`. A `Sink` call that does not return
normally is contained like the decoding of a packet that does not: counted in `InternalErrorCount`, and the
pass goes on without an error; return an error to stop a pass.

Errors to test with `errors.Is`: `trace.ErrFormat`, `trace.ErrCorrupt` (a damaged file: the summary up to the
damage is returned too, and `FileSummary.Error` has the text; the error also wraps its cause, for example
`gzip.ErrChecksum` for a gzip file whose checksum does not match), `trace.ErrNotSeekable`, `trace.ErrConsumed`, `trace.ErrNoInput`, `trace.ErrFrameRef`,
`mbcapexport.ErrOptions`, `mbcapexport.ErrWriter` (the capture library refused something: a bug),
`subtrace.ErrTransactionSelection`, `timeline.ErrUnknownFormat`; a cancelled context gives `ctx.Err()`.
