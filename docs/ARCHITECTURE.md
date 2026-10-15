# Architecture: go-modbus-trace

Status: design to implement. Everything here is *proposed behavior* unless marked *(verified)* against the local checkouts (2026-10-15). Where the text says "L0 decides", the L0 spike (section 12) settles it with evidence and records the result in `docs/DECISIONS.md`, summarised in section 12.

## 1. Principles

1. **The trace is the database.** Events point into the trace (frame numbers, file offsets, payload ranges). Nothing keeps raw bytes that the trace still has. Applications cache pointers, not packets.
2. **Streaming with bounds.** One forward pass, bounded memory, every limit counted when it bites.
3. **Never lose, never invent.** Anything that cannot be decoded, paired or trusted is still an event with a status and flags. Anything guessed carries a confidence. Only trusted, matched reads reach MBCAP.
4. **Offline and deterministic.** No network, no wall clock, stable ordering, reproducible output.
5. **One engine, many front ends.** The CLI, the Wails application and tests call the same `trace` facade.

## 2. Pipeline

```
 file / stdin
     |  pcapio: pcap | pcapng, gzip            Packet{Frame, Offset, Time, Iface, CapLen, OrigLen, Data}
     v
 link: Ethernet/VLAN/SLL/Null/Raw -> IPv4/IPv6 (+fragments) -> TCP segment{Dir, Seq, Flags, Payload}
     v
 flow: connection table (4-tuple + epoch) -> per-direction reassembly -> byte runs + gaps
     v
 mbtcp: MBAP framer (+resync) -> ADU{Unit, TID, PDU, Provenance}
     v
 roles (SYN, port, structure, override) -> request / response orientation
     v
 pair: outstanding-request matching -> Transaction{status, flags, times, provenance}
     v
 Sink.Event(model.Event) -----> analyze/* aggregators, export/*, application index
```

`Scan` runs the first four stages only far enough to classify flows (no pairing), and computes the file summary. `Analyze` runs everything for the selected flows. Both are single forward passes over the file; `Analyze` may skip packets of unselected flows after parsing their headers.

Bounds (defaults; all configurable through `trace.Limits`, all with a counter in the file summary):

| Limit | Default | When exceeded |
|---|---|---|
| Tracked connections | 100,000 | least recently seen is evicted, its open transactions become `unanswered`+`uncertain`; `evicted_connections` |
| Reassembly buffer per direction | 1 MiB | a gap is declared; `reassembly_overflow` |
| Reassembly buffers, total over all connections | 64 MiB | the direction with the most buffered bytes declares its gap; `reassembly_budget` |
| Outstanding requests per connection | 256 | oldest becomes `unanswered`+`uncertain` |
| Resync scan | 64 KiB | the bytes are a `gap` with `resync_failed` |
| IP fragments buffered (total) | 16 MiB | oldest datagram dropped; `fragment_overflow` |
| Patterns / coverage intervals | 10,000 / 4,096 per space | new keys are folded into an `other` bucket; `analyzer_overflow` |
| Timeline reorder window (`--order time`) | 60 s of trace time | later events are emitted out of order; `reorder_late` |

## 3. Packages and dependencies

See the layout in `AGENTS.md`. Dependency policy:

| Need | Decision | Decided at |
|---|---|---|
| pcap/pcapng reading and pcapng writing | own `internal/pcapio`: the readers need file offsets and hostile-input bounds that `pcapgo` lacks, and on Linux `pcapgo` links its AF_PACKET capture code. `pcapgo.NgWriter` forces `if_tsresol` 9 and cannot keep a source interface's resolution (gopacket/gopacket v1.7.4, read and measured locally). | L0: `DECISIONS.md` D1, D3 |
| Link/IP/TCP parsing | own minimal parsers in `internal/link` (headers only, bounds-checked). gopacket `layers` is CGO-free but is 47,000 lines and, with `reassembly`, half the speed of the own candidate. IPv4 and IPv6 fragments share one bounded reassembler. | L0: `DECISIONS.md` D2, D4 |
| TCP reassembly | own `internal/flow`. gopacket `reassembly` cannot detect conflicting overlaps, loses a midstream direction that starts out of order, declares gaps only on limits or time, carries provenance only through `AncillaryData`, and registers global flags on import. The own candidate matched the ground truth exactly at about 1.1 GB/s. | L0: `DECISIONS.md` D2 |
| MBCAP | `github.com/otfabric/go-modbus-capture` (pin the newest release at the start; v0.0.2 on 2026-10-15; the format is draft 0.1, not frozen: record module and format versions in the export header tags, and expect a breaking 1.0) | fixed |
| CLI | `github.com/spf13/cobra` + `pflag` (as modbusctl) | fixed |
| Tests | `testify` as in modbusctl; `github.com/santhosh-tekuri/jsonschema/v6` for schema tests (as Explorer) | fixed |

`go-modbus` is a **test-only** dependency (its client and server generate real Modbus frames for the decoder tests, LA6, LA10). Its `PDUTap` sees only an active client's own exchanges, so it cannot be used for sniffing *(verified)*, and it exports no PDU parsers *(verified: only `ParseFunctionCode`)*: the decoders are ours, validated against the specification (`go-modbus/spec/MODBUS-SPEC.md`, V1.1b) and against go-modbus's behavior.

## 4. Readers (`internal/pcapio`)

- **Detection** by magic: `a1b2c3d4` / `d4c3b2a1` (pcap µs), `a1b23c4d` / `4d3cb2a1` (pcap ns), `0a0d0d0a` (pcapng Section Header), `1f8b` (gzip, then detect again on the decompressed stream). Anything else: a clear error naming the first bytes.
- **Packet record** handed to the pipeline: `Frame` (1-based ordinal over all packet records of the file in file order, as Wireshark numbers frames; Simple and Enhanced Packet Blocks both count), `Offset` (byte offset of the record/block start in the *uncompressed* stream), `Iface` (pcapng interface ID; 0 for pcap), `Time` (`time.Time` UTC with nanoseconds; pcap µs scaled; pcapng by `if_tsresol` and `if_tsoffset`; Simple Packet Blocks have none), `CapLen`, `OrigLen`, `LinkType`, `Data` (valid until the next call).
- **pcapng interface table** keeps link type, snap length, tsresol, tsoffset, name and description per interface; Interface Statistics Blocks (`isb_ifdrop`, `isb_filteraccept`, ...) become `trace.note` events and file-summary counters ("the capture host dropped N packets"). Section Header options (`shb_userappl`, `shb_os`, `shb_hardware`) go to the file summary and into MBCAP header tags.
- **Snap length**: `CapLen < OrigLen` marks the packet truncated; a payload cut by it makes any ADU touching it `snaplen_truncated` and untrusted.
- **Random access** (`Frames(refs)`): seek to `Offset`, read one record/block, re-parse it with the interface table captured during the scan. Needs a seekable, uncompressed file. gzip and stdin inputs return `ErrNotSeekable`; an application that needs random access decompresses to a cache file first.
- **Writer** (`export/subtrace`): pcapng with one Section Header (tool name and version in `shb_userappl`, a comment describing the selection), the interface descriptions of the source with their original link types and resolutions, Enhanced Packet Blocks with the original timestamps. Classic-pcap inputs with nanosecond magic are written with `if_tsresol` 9.

## 5. Link, IP, TCP (`internal/link`)

- Parse by link type (list in L2). VLAN: 0x8100 and 0x88a8, repeated. SLL/SLL2 carry the interface index and the packet direction; keep the interface index in the provenance.
- IPv4: validate IHL and total length against the captured length; fragments keyed by (src, dst, protocol, ID), bounded; IPv6: walk extension headers by the Next Header chain with a bound on the number of headers; the fragment header is reassembled (SHOULD) or the datagram is counted as `ipv6_fragment_unsupported`.
- TCP: ports, sequence/ack numbers, flags (SYN, FIN, RST, ACK, PSH), data offset; payload = IP payload minus header, trimmed to the IP total length (Ethernet padding on short frames must not become data).
- A packet that is not TCP, or is too short for its headers, is counted by reason and never reaches the flow stage. No checksum validation.

## 6. Flows, epochs, reassembly (`internal/flow`)

**Connection table.** Key: sorted (addr, port) pair. Value: the current epoch (ID assigned in order of first packet) and per-direction state. A packet maps to the current epoch unless it starts a new one (rule in L3); a new epoch closes the previous one (`close=superseded`).

**Per direction state:** `next` expected sequence number (32-bit with wraparound arithmetic), a bounded sorted list of out-of-order segments, whether the first byte was seen (a SYN fixes `next = isn+1`; otherwise the connection is `midstream` and the first data segment fixes it, unless the peer's last ACK number lies just before that segment (within the buffer limit): then `next` = that ACK, so a first segment captured out of order is buffered instead of lost; `DECISIONS.md` D2, Q4).

**Segment handling**, for payload bytes at sequence `s` with length `n`:

| Situation | Action |
|---|---|
| `s == next` | deliver, `next += n`, then drain buffered segments that now fit |
| `s + n <= next` | whole segment already delivered: `retransmitted` (count, compare bytes with what was delivered if still known: a mismatch is a flagged `overlap_conflict`) |
| `s < next < s + n` | partially new: deliver the new tail, flag `retransmitted` |
| `s > next` | buffer (bounded); `out_of_order` if it is later filled |
| buffer full, FIN/RST, end of trace, or the new epoch starts | declare a **gap** of `s - next` bytes (when known) and continue at `s`; `gap_adjacent` on transactions touching it |
| the peer acknowledges beyond `next` (ACK > `next`) | those bytes reached the peer but not the capture and will never be retransmitted: declare the **gap** at once up to the ACK (or to the first buffered segment), deliver what is buffered, continue (`DECISIONS.md` D2, Q4) |
| keepalive (`n <= 1`, `s == next-1`) | ignored, counted |

Delivered bytes go to the framer together with the packet provenance of every chunk, so an ADU knows exactly which packets carried it. FIN/RST close a direction/connection and flush buffers. The end of the trace closes everything (`close=end_of_trace`).

**Duplicate observations** (capture on `any`, a bridge and its member, two taps): the second copy of every segment arrives with `s + n <= next` and is dropped as a retransmission. Consequently no transaction is duplicated. Their frames are kept in provenance only when they carried bytes that were delivered.

## 7. Framing, resync, roles (`mbtcp`)

**Framer** per direction, fed with ordered byte runs and gap markers:

1. Need 7 bytes for the MBAP header. Check `pid == 0` and `2 <= length <= 254`. Wait for `6 + length` bytes. Emit `ADU{TID, Unit, PDU}` with the provenance of its bytes.
2. A header whose protocol ID is not 0 but whose length is in 2..254, and which is followed by a valid header at `o + 6 + length` (or by the exact end of the byte run), is a **foreign frame**: it is skipped by its length, counted (`foreign_protocol`) and reported as an opaque ADU with that flag, never paired and never exported; framing stays in sync (as go-modbus does; user decision 2026-10-15, `DECISIONS.md` Q3).
3. A gap marker or any other invalid header enters **resync**: scan forward at most `ResyncLimit` bytes for an offset `o` where (a) a valid header is followed by a second valid header at `o + 6 + length` (or the byte run ends exactly there), or (b) the header's TID/unit/function match an outstanding request (responses) or a plausible request (`func` known, length consistent with the function's fixed/structured size). On success emit a `resync` event (`confidence` = strongest rule that held) and flag the next ADU `resynced`; on failure emit `gap` with `resync_failed`.
4. Over a midstream start, offset 0 is tried first.
5. Truncation by snap length: an ADU whose bytes are only partly captured is emitted `snaplen_truncated` with the available PDU bytes and never trusted.

**Roles.** The flow stage decides per connection, once there is evidence, in this order: user override; SYN (the sender of the first SYN without ACK is the client); a configured server port; structure. *Structure test:* parse the first up to 20 ADUs of both directions under orientation A (direction 1 = requests, direction 2 = responses) and B; score = share of ADUs that decode under their assumed role, plus the share of responses that pair with an earlier request. The better orientation wins if its score is at least 0.2 higher and at least 0.8 in absolute terms; otherwise the role is `unknown`. Request and response PDUs are distinguishable for most functions (a request to FC03 is exactly 5 bytes; its response is `byte count` + data), which is why the structure test is usually decisive. The decision and its source (`override | syn | port | structure`) are stored; `role_guessed` is set when the source is `port` without SYN or `structure`.

Pairing starts after the role is known; ADUs before that are buffered (bounded, 64 per direction) and replayed.

## 8. PDU decoding and validation (`mbtcp`)

- A table-driven decoder per function code for request and response: `Decode(role, pdu) (View, []Warning)`. `View` has the function name, the named fields (address, quantity, values, byte count, sub-function, file records, MEI object IDs, ...) and, for ranges, the **range** (`Space`: coil | discrete | holding | input | file | fifo | other; `Start`; `Count`). Values are kept as raw bytes; helper methods split bits/words.
- `docs/COVERAGE.md` is generated by a test that walks the table: function, name, direction, decoded fields, validation rules, serial-only flag, MBCAP-admissible flag. A function without an entry is opaque; the matrix must list all standardized codes (1-8, 11, 12, 15, 16, 17, 20-24, 43) and the user-defined ranges (65-72, 100-110) as opaque.
- Validation rules come from MODBUS Application Protocol V1.1b (local copy: `go-modbus/spec/MODBUS-SPEC.md`). The ones that matter for trust: quantity limits (FC01/02: 1..2000; FC03/04: 1..125; FC15: 1..1968 with byte count `ceil(q/8)`; FC16: 1..123 with byte count `2q`; FC23: read 1..125, write 1..121), byte count equals data length, fixed lengths (FC05/06 echo; FC07 request 1 byte, response 2 bytes; FC11 response 5 bytes; FC22 7 bytes; FC24 request 3 bytes), FC05 value is `0xFF00` or `0x0000`, FC20 sub-request reference type 6 and length bounds, FC43/14 object structure (`id, len, value`), exception responses exactly 2 bytes with a known code (01-08, 0A, 0B; any other code is decoded and warned as `unknown_exception_code`). A violated rule is a **warning** on the view and sets `invalid_pdu` on the transaction (which keeps it out of MBCAP).
- The decoder is also exported for display use by applications (`mbtcp.Decode`).
- *(partly verified, L0)* The MODBUS Messaging on TCP/IP Implementation Guide V1.0b is not in the local checkouts and was not fetched (the L0 work was offline only). The framing rules above were reconciled with the three local sources: the Application Protocol specification V1.1b (ADU at most 260 bytes; it cites the guide as V1.0a), go-modbus v1.7.1, and tshark 4.6.9's dissector probed with crafted frames. They agree with every local source (`DECISIONS.md` D7). The guide's own wording remains to be checked when a local copy exists.

## 9. Pairing (`internal/pair`)

Per connection, with roles known:

- `outstanding`: ordered list of requests (cap 256) with `(unit, tid, fc, pdu, times, provenance)`.
- On a request ADU: if the list holds an entry with the same `(unit, tid)`:
  - same request PDU bytes: mark both entries `retried` and keep both (the first response pairs with the oldest; the other stays outstanding and ends as `unanswered` unless a second response arrives; the content is identical either way, only the latency differs);
  - different PDU: mark both `ambiguous`.
  Append the request. A request to unit ID 0 may be a broadcast that is never answered (or a gateway that ignores the unit ID and does answer): without a response it is `unanswered` with the flag `broadcast`, with one it pairs normally.
- On a response ADU: find the **oldest** outstanding entry with the same `(unit, tid)` whose `fc` equals the response's function code, or equals it with bit 0x80 cleared (exception). No entry: `orphan_response`. An entry found: remove it, build the `Transaction` (`ok`, or `exception` with the code), compute times and latency, carry `retried`/`ambiguous`/`slow`/`clock_order`/gap flags.
- When the connection ends (FIN/RST, eviction, end of trace) every remaining entry becomes `unanswered`. A transaction touched by a gap or resync on either side is `uncertain`, whatever else it is.
- `malformed` is for an ADU whose PDU fails decoding so badly that no pairing is meaningful (empty PDU, truncated by snaplen); it is reported alone.
- Latency is `response.first_packet_time - request.last_packet_time`; if negative it is reported as 0 with `clock_order`. Durations of the request and the response themselves (first to last packet) are kept, since they show segmentation.

## 10. Event model and provenance (`model`)

Types are Go structs with JSON tags and a published JSON Schema. Sketch (the L2 implementation finalizes names; the schema is authoritative afterwards):

```go
type Endpoint struct { Addr netip.Addr; Port uint16 }

type FrameRef struct {
    Frame   uint64 // 1-based, as Wireshark numbers frames
    Offset  int64  // record/block start in the (decompressed) file
    Iface   uint32
    Time    time.Time
    PayOff  uint16 // payload offset within the packet's Data
    PayLen  uint16
}

type Connection struct {
    ID                 uint32
    Client, Server     Endpoint
    RoleSource         string // override | syn | port | structure | unknown
    First, Last        time.Time
    Open, Close        string // syn | midstream ; fin | rst | end_of_trace | evicted | superseded
    Iface              uint32
    Transactions       uint64
    BytesC2S, BytesS2C uint64
}

type ADU struct {
    TID    uint16
    Unit   uint8
    PDU    []byte      // omitted in JSON unless requested; recoverable through Refs
    View   *mbtcp.View // decoded
    Refs   []FrameRef
    First, Last time.Time
}

type Transaction struct {
    Seq        uint64 // order of determination
    Conn       uint32
    Server     Endpoint
    Unit       uint8
    TID        uint16
    Function   uint8
    Sub        *uint16 // FC08 sub-function, FC43 MEI type
    Request    ADU
    Response   *ADU
    Status     string // ok | exception | unanswered | orphan_response | ambiguous | malformed | uncertain
    Exception  uint8
    Latency    time.Duration
    Flags      []string // quality flags (L9)
    Warnings   []string // validation warnings
}

type Event struct { Kind string; Time time.Time; Conn *Connection; Txn *Transaction; Gap *Gap; Note *Note } // exactly one payload
```

**Quality flags** (each has a counter in the file summary and a documented meaning): `retransmitted`, `out_of_order`, `overlap_conflict`, `gap_adjacent`, `resynced`, `snaplen_truncated`, `midstream`, `role_guessed`, `retried`, `clock_order`, `slow`, `invalid_pdu`, `serial_function_over_tcp`, `unknown_function`, `broadcast`, `foreign_protocol`, `internal_error`.

**Time.** Everything is the capture timestamp (UTC, ns). Files may be out of time order (merged captures, `-i any`): the pipeline processes in file order and never sorts; consumers sort. Negative gaps are flagged. The library never calls `time.Now`.

## 11. Scan, analyzers, API sketch, CLI

**Scan** returns `FileSummary` (format, interfaces/link types, packets, bytes, first/last, snaplen facts, drop counters, unsupported counters, SHA-256, tool metadata) and `[]Flow` (`ID`, endpoints, packets and bytes per direction, first/last, `Class` = `modbus_tcp | tls | other_tcp`, `Score`, `ADUs`, `GuessedServerPort`). It is one pass without pairing, designed to run at close to disk speed.

**Analyzers** implement `Sink` and are composed by the caller (`analyze.Overview`, `.Devices`, `.Patterns`, `.Coverage`); each returns a JSON-able result and reports its overflow counters. Latency uses a fixed log-scale histogram (about 1% relative resolution, no allocation per event). Patterns key on `(client addr, server endpoint, unit, function, request PDU bytes)` and track inter-request gaps with min/max/median (histogram) and jitter (median absolute deviation of the gap); volatility = changed responses / polls (a 64-bit hash of the response PDU, no storage of values).

**API sketch** (proposed; L1/L2 finalize it and write `docs/API.md`):

```go
f, err := trace.Open(path)                                  // detect, read headers; ErrNotSeekable-aware
sum, flows, err := trace.Scan(ctx, f, trace.ScanOptions{})  // pass 1
opts := trace.Options{ServerPorts: []uint16{502, 1502}, Flows: ids, Limits: trace.DefaultLimits}
err = trace.Analyze(ctx, f, opts, sink)                      // pass 2; sink gets model.Event
frames, err := f.Frames(txn.Request.Refs)                    // random access to provenance
view := mbtcp.Decode(mbtcp.Request, pdu)                    // display decoding
rep, err := mbcapexport.Export(ctx, f, opts, sel, mbcapexport.Options{...}, capture.Writer) // re-streams the trace
err = timeline.Write(ctx, f, opts, sel, w, timeline.CSV)
err = subtrace.Extract(ctx, f, sel, w)                       // pcapng
```

A `Sink` returning an error stops the pass. `Analyze` honors `ctx` between packets and reports progress through an optional `Progress(bytesRead, total)` callback (rate-limited by the library).

**CLI** (names and flags proposed; modbusctl conventions):

```
mbtracectl info      <trace>                       file summary, interfaces, link types, drops, snaplen facts
mbtracectl flows     <trace> [--min-score 0.5]     flow table with Modbus score and class
mbtracectl summary   <trace> [--server-port 502,1502] [--server ip[:port]] [--json]
mbtracectl timeline  <trace> [selection flags] [--order time|file] [--format text|csv|jsonl]
mbtracectl export mbcap     <trace>... -o out.mbcap [selection flags] [--change-only] [--no-exceptions]
                            [--tick-ns 1000] [--report report.json] [--name ip:port/unit=Label]
                            [--warn-replay-memory 1GiB]
mbtracectl export timeline  <trace>... -o out.csv|out.jsonl [selection flags]
mbtracectl extract   <trace> -o sub.pcapng [selection flags]
mbtracectl version
selection flags: --server ip[:port]  --unit 1,2  --client ip  --conn 12  --fc 3,4,43  --status ok,exception
                 --from 10m --to 1h (offsets from the first packet) | --from-time/--to-time (RFC 3339)
```

`<trace>` is a path or `-`. Several traces given in time order are one continuous trace (connection state carries across files; this is how rotated tcpdump `-C`/`-G` files are analyzed). A remote one-liner works: `ssh gw 'tcpdump -i eth0 -w - port 502' | mbtracectl export mbcap - -o site.mbcap` (WallStart is then the first packet time and earlier-stamped packets are reported, since the minimum timestamp cannot be known in advance).

## 12. Milestones, the L0 spike, measured numbers

**L0: spike and decision record (first, small).** Deliver `docs/DECISIONS.md` with evidence for each, then proceed:

| Question | Exit criteria |
|---|---|
| Reader and reassembly: gopacket fork parts or own code? | A prototype that reads a 1 GB synthetic pcap and a pcapng with two interfaces, reassembles with gaps, midstream start and overlaps, builds `CGO_ENABLED=0` on all seven targets, with a throughput and allocation measurement. Choose the option that meets L3/L4/L17/L19 with less code and no cgo; if the fork wins, record which packages are imported. |
| pcapng writer: own or fork? | Output opens in Wireshark/tshark (where available) with identical timestamps; measured. |
| IPv6 fragments | Cost in lines of code and tests; keep as SHOULD or drop to a counter. |
| Modbus/TCP guide | Obtain MODBUS Messaging on TCP/IP Implementation Guide V1.0b and reconcile section 7 and L5. |
| Memory per tracked connection | Measured, to calibrate the 100,000 default. |
| Replay memory | Measure modbusctl's memory per MBCAP sample on a large export (`replay.Build` loads the whole capture *(verified)*) and record the ceiling the export report warns about. |
| CLI name | Keep `mbtracectl` or change; ask the user. |

**L1: Reader, link/IP/TCP, flows and reassembly, framing; `info` and `flows`.** Synthetic trace builder (`trace/tracetest`) first, since every other test depends on it. LA1-LA5 (framing and flows part), LA14 (reader/parser fuzz), LA15.

**L2: PDU decoders, roles, pairing, quality model, event model; `summary` and `timeline`; random access.** LA3-LA8, LA16, `docs/COVERAGE.md`, the timeline export (L14). Frames generated by go-modbus for LA6.

**L3: MBCAP export.** `MBCAP-EXPORT.md` implemented; LA9-LA11. The first end-to-end replay with the pinned `mbcapctl` and `modbusctl`.

**L4: Analyzers, sub-trace export, schemas, CLI polish, benchmarks, release.** LA12, LA13 (advisory), LA17, LA18, L22. v0.1.0 tagged; the application pins it.

**L0 outcome** (2026-10-15, details and method in `docs/DECISIONS.md`): no gopacket; own reader, link parsing, reassembly and pcapng writer; IPv6 fragments MUST, built in L1 with IPv4; the L5 framing rules stand, plus foreign frames skipped by length (section 7); CLI `mbtracectl`; every L0 question is answered (`DECISIONS.md`).

**Measured numbers** (filled in by L0 and L4): throughput of `Scan` and `Analyze` per core; resident memory at default limits; pcapng write speed; machine and commit.

| Measured in L0 (spike, Apple M1, Go 1.27.2, `db97366` + L0 change) | Value |
|---|---|
| Reader only, 1 GiB synthetic pcap / pcapng | 3.3-4.1 / 2.6-3.4 GiB/s, 66 allocations per run |
| Read, parse, reassemble and frame MBAP with provenance, 1 GiB, 1,000 connections | 1,049-1,146 MiB/s, peak RSS 27-28 MiB |
| pcapng write (read included), 1 GiB | 1,271-1,770 MiB/s |
| Flow state per tracked connection | about 1.1 KB (100,000 connections: about 100 MiB) |
| modbusctl replay memory per MBCAP sample | 0.58-0.74 KB plus about 31 B per changed register value; estimate `12 MiB + 750 B × samples + 36 B × changed values` |

PDU decoding, roles and pairing are not in the spike; `Scan` and `Analyze` are measured again at L4.

## 13. Dependency resolution log

Resolved on: 2026-10-15, from the local module cache (the L0 work was offline; newer releases on the proxy were not checked and must be at the start of L1). Record each module, version, release date and the reason it is needed.

| Module | Version | Released | Needed for | Added in |
|---|---|---|---|---|
| `github.com/otfabric/go-modbus-capture` | v0.0.2 | 2026-10-15 | MBCAP export (fixed) | L3 |
| `github.com/spf13/cobra` | v1.10.2 | 2025-12-03 | `mbtracectl` (fixed); `go 1.15` | L1 |
| `github.com/stretchr/testify` | v1.12.1 (modbusctl pins v1.11.1) | 2026-08-17 | tests (fixed) | L1 |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | 2026-06-28 | schema tests (fixed) | L4 |
| `github.com/otfabric/go-modbus` | v1.7.1 | | tests only (LA6, LA10) | L2 |
| `github.com/gopacket/gopacket` | v1.7.4 | 2026-10-01 | **not used** (`DECISIONS.md` D1-D3) | |

The `go` directive is `go 1.23`: go-modbus-capture v0.0.2 declares 1.23, cobra 1.15 (`DECISIONS.md` D8).
