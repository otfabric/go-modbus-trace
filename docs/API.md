# Library API

The godoc of each package is the reference; this page is the map.

| Package | Use it to |
|---|---|
| `trace` | `Open(path)`, `OpenReader(r)`; `Scan` (file summary, TCP flows with a Modbus score: one cheap pass); `Analyze` (every event: connections, transactions, gaps, resyncs, notes) into a `Sink`; `File.Frames(refs)` to re-read the packets of an ADU |
| `model` | the events: `Event`, `Connection`, `Transaction`, `ADU`, `FrameRef`, `Gap`, `Resync`, `Note`; statuses and flags; `EventSemanticsVersion`. JSON Schema: `docs/schema/event-1.schema.json` |
| `mbtcp` | `Decode` a PDU (fields with byte ranges, ranges, class, warnings), `CheckPair`, `ValueAt`, `Summary`, `Coverage`; the MBAP `Framer`; `DecideRole` |
| `selection` | the transaction predicate shared by the CLI, the exporters and applications |
| `export/timeline` | the timeline as CSV or JSON Lines |
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
```

Rules that hold for every function: no network I/O, no wall clock (times are the trace's), the same input
and options give the same events, a malformed packet is counted and never fails the pass, a panic in one
packet is recovered and reported as a note.
