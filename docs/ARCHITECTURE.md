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
| IP fragments buffered (total) | 16 MiB | oldest datagram dropped; `fragments.dropped` |
| Captured packet size | 256 KiB | pcap: the read ends with `ErrCorrupt`; pcapng: the block is skipped (`skipped_blocks`) |
| pcapng block size | 16 MiB | the read ends with `ErrCorrupt` (an implausible length) |
| Analyzer keys: devices (server, unit) / clients per device / poll patterns / coverage ranges per server, unit and space | 10,000 / 256 / 10,000 / 4,096 | new keys are not recorded; their transactions (ranges) are counted in the analyzer's `overflow` |
| MBCAP export, per target: writes / read ranges / other requests remembered for the report | 4,096 most recent / 65,536 / 65,536 | a `stale_after_write` warning may be missed; the replay estimate counts every response as changed (still an upper bound) |
| Timeline reorder window (`--order time`) | 60 s of trace time and 64 MiB of encoded rows | later events are emitted out of order; counted (`Stats.Late`) |

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
- **Packet record** handed to the pipeline: `Frame` (1-based ordinal over all packet records of the file in file order, as Wireshark numbers frames; Simple, Enhanced and obsolete Packet Blocks count, and so do Custom Blocks (`0x0BAD`, `0x40000BAD`) and systemd Journal Export Blocks, which are not packets but which Wireshark 4.6 numbers as frames *(verified with tshark 4.6.9, L1)*; Name Resolution, Decryption Secrets and unknown blocks do not), `Offset` (byte offset of the record/block start in the *uncompressed* stream), `Iface` (index into the file's interface list over all sections, so it stays unique when a later section restarts interface IDs at 0; 0 for pcap), `Time` (`time.Time` UTC with nanoseconds; pcap µs scaled; pcapng by `if_tsresol` and `if_tsoffset`; Simple Packet Blocks have none), `CapLen`, `OrigLen`, `LinkType`, `Data` (valid until the next call).
- **pcapng interface table** keeps link type, snap length, tsresol, tsoffset, name and description per interface; Interface Statistics Blocks (`isb_ifdrop`, `isb_filteraccept`, ...) become file-summary counters ("the capture host dropped N packets") and, from L2, `trace.note` events. Timestamps are converted exactly (128-bit intermediate) for any decimal or binary `if_tsresol`; an invalid one is counted (`bad_options`) and read as microseconds.
- **Damage**: a pcapng block whose trailing length disagrees with its leading one, or whose content is inconsistent (an EPB for an undefined interface, a captured length beyond the block), is skipped and counted (`skipped_blocks`); a block length that is not a multiple of 4, below 12 or above the block limit ends the read with `ErrCorrupt` and the results so far. A record or block cut short by the end of the file is tolerated (`truncated_tail`).
- **SHA-256** is computed over the input as stored (the compressed bytes for gzip), while reading; at the end the reader drains what is left so the hash covers the whole file. Section Header options (`shb_userappl`, `shb_os`, `shb_hardware`) go to the file summary and into MBCAP header tags.
- **Snap length**: `CapLen < OrigLen` marks the packet truncated; a payload cut by it makes any ADU touching it `snaplen_truncated` and untrusted.
- **Random access** (`Frames(refs)`): seek to `Offset`, read one record/block, re-parse it with the interface table captured during the scan. Needs a seekable, uncompressed file. gzip and stdin inputs return `ErrNotSeekable`; an application that needs random access decompresses to a cache file first.
- **Writer** (`export/subtrace`): pcapng with one Section Header (tool name and version in `shb_userappl`, a comment describing the selection), the interface descriptions of the source with their original link types and resolutions, Enhanced Packet Blocks with the original timestamps. Classic-pcap inputs with nanosecond magic are written with `if_tsresol` 9.

## 5. Link, IP, TCP (`internal/link`)

- Parse by link type (list in L2). VLAN: 0x8100 and 0x88a8, repeated. SLL/SLL2 carry the interface index and the packet direction; keep the interface index in the provenance.
- IPv4: validate IHL and total length against the captured length; fragments keyed by (src, dst, protocol, ID); IPv6: walk extension headers by the Next Header chain with a bound of 8 headers (`ipv6_ext_headers` beyond); fragments keyed by (src, dst, ID). One reassembler serves both (MUST), with a total byte budget: when it is exceeded the oldest incomplete datagram is dropped (`fragments.dropped`). Overlapping fragments: the lower offset wins. A fragment that cannot belong to a valid datagram (empty, beyond 65,535 bytes, a non-final fragment not a multiple of 8, two different last fragments) is counted `fragment_bad`. A cut fragment cannot be reassembled and counts as `short`.
- Counted reasons (file summary `unsupported`): `link_unsupported`, `not_ip` (ARP, LLDP, ...), `not_tcp` (UDP, ICMP, ...), `tunnel` (IP-in-IP, IPv6-in-IPv4, GRE, VXLAN on UDP 4789), `ipsec` (AH, ESP), `short` (headers cut by the snap length or damaged), `bad_header` (impossible IHL, data offset or version), `ipv6_ext_headers`, `fragment_bad`.
- TCP: ports, sequence/ack numbers, flags (SYN, FIN, RST, ACK, PSH), data offset; payload = IP payload minus header, trimmed to the IP total length (Ethernet padding on short frames must not become data).
- A packet that is not TCP, or is too short for its headers, is counted by reason and never reaches the flow stage. No checksum validation.

## 6. Flows, epochs, reassembly (`internal/flow`)

**Connection table.** Key: sorted (addr, port) pair. Value: the current epoch (ID assigned in order of first packet) and per-direction state. A packet maps to the current epoch unless it starts a new one (rule in L3); a new epoch closes the previous one (`close=superseded`). A SYN without ACK starts a new epoch after FIN or RST closed the old one, or when its sequence number is more than 1 MiB (`EpochWindow`) from the live direction's next byte; a SYN with the same ISN is a retransmission (`syn_retransmits`). The least recently seen connection is evicted at the limit (`evicted`); packets of a closed connection that start no new epoch (final ACKs, late retransmissions) are counted (`packets_after_close`) and ignored.

**Per direction state:** `next` expected sequence number (32-bit with wraparound arithmetic), a bounded sorted list of out-of-order segments, whether the first byte was seen (a SYN fixes `next = isn+1`; otherwise the connection is `midstream` and the first data segment fixes it, unless the peer's **first** ACK number in the capture lies before that segment (within the buffer limit): then `next` = that ACK. That recovers a first segment captured out of order, and makes bytes sent during the capture but never captured before the first captured one a gap instead of a silent start. The first ACK, not the latest, because a later ACK may already cover lost bytes; `DECISIONS.md` D2, Q4, refined in L1).

**Segment handling**, for payload bytes at sequence `s` with length `n`:

| Situation | Action |
|---|---|
| `s == next` | deliver, `next += n`, then drain buffered segments that now fit |
| `s + n <= next` | whole segment already delivered: `retransmitted` (count, compare bytes with what was delivered if still known: a mismatch is a flagged `overlap_conflict`) |
| `s < next < s + n` | partially new: deliver the new tail, flag `retransmitted` |
| `s > next` | buffer (bounded per direction and in total); `out_of_order` if the hole before it is later filled by data (not when it is skipped as a gap). Among held segments with the same start, the first one captured is delivered first (first data wins) |
| buffer full, FIN/RST, end of trace, or the new epoch starts | declare a **gap** of `s - next` bytes (when known) and continue at `s`; `gap_adjacent` on transactions touching it |
| the peer acknowledged beyond `next` (ACK > `next`) | those bytes reached the peer but not the capture and will never be retransmitted. The gap is declared as soon as data waits behind it: when such an ACK arrives while segments are held, or when a later segment of the direction arrives. Without data behind it nothing is declared yet, so a reordered capture (an ACK copy stamped before its data on another interface) loses nothing. Declared up to the ACK (or to the first held segment), what fits is delivered (`DECISIONS.md` D2, Q4) |
| FIN with a sequence number beyond `next` | the bytes before the FIN were lost: a gap |
| keepalive (`n <= 1`, `s == next-1`, arriving, not drained from the buffer) | ignored, counted (`keepalives`). A one-byte retransmission of the last byte is indistinguishable from a probe and is counted as one |
| a TCP payload cut by the snap length (the IP length says more than was captured) | the captured bytes are delivered and the rest is an exact, known-size gap of kind `snaplen` (not counted in `gaps`; `payload_bytes_cut`) |

Delivered bytes go to the framer with their stream position and the packet that carried them (frame, file offset, interface, time, payload offset; `-1` after IP reassembly), so an ADU knows exactly which packets carried it (the mapping from stream positions to frames is built in L2). FIN in both directions closes the connection (`fin`), RST closes it at once (`rst`); buffers are flushed as gaps first. The end of the trace closes everything (`close=end_of_trace`) in connection order. Gap counting: a gap that continues the previous one with nothing delivered in between (a hole declared in two steps) counts once in `gaps`; `gap_bytes` adds up.

**Duplicate observations** (capture on `any`, a bridge and its member, two taps): the second copy of every segment arrives with `s + n <= next` and is dropped as a retransmission. Consequently no transaction is duplicated. Their frames are kept in provenance only when they carried bytes that were delivered.

## 7. Framing, resync, roles (`mbtcp`)

**Framer** per direction, fed with ordered byte runs and gap markers:

1. Need 7 bytes for the MBAP header. Check `pid == 0` and `2 <= length <= 254`. Wait for `6 + length` bytes. Emit `ADU{TID, Unit, PDU}` with the provenance of its bytes.
2. A header whose protocol ID is not 0 but whose length is in 2..254, and which is followed by a valid header at `o + 6 + length` (or by the exact end of the byte run), is a **foreign frame**: it is skipped by its length, counted (`foreign_protocol`) and reported as an opaque ADU with that flag, never paired and never exported; framing stays in sync (as go-modbus does; user decision 2026-10-15, `DECISIONS.md` Q3).
3. A gap marker or any other invalid header enters **resync**: scan forward at most `ResyncLimit` bytes for an offset `o` where (a) a valid header with a plausible function code (not 0, not 0x80) is followed by a second valid header at `o + 6 + length` (`next_header`), or the byte run ends exactly there (`run_end`), or (b) *(L2, needs pairing)* the header's TID/unit/function match an outstanding request (responses) or a plausible request (`func` known, length consistent with the function's fixed/structured size). On success emit a `resync` event (`confidence` = strongest rule that held) and flag the next ADU `resynced`; bytes passed over are reported (`junk_bytes`); on failure (the limit passed) the scanned bytes are reported `resync_failed` and the scan starts again. When a gap or the end of the stream ends a run, what is waiting is decided first: a candidate counts if the bytes after it are a valid start of a header (the protocol ID bytes that are there are 0, and the length, when there, is 2..254), and a pending foreign-frame decision is settled; only then is the rest dropped (`incomplete`). The framer waits for the function code byte rather than skip a header split after its 7th byte.
4. Over a midstream start, offset 0 is tried first.
5. Truncation by snap length: an ADU whose bytes are only partly captured is emitted `snaplen_truncated` with the available PDU bytes (its `Missing` count says how many it lacks) and never trusted. Because the flow stage reports the cut as an exact gap, framing stays in sync when the cut ends inside the ADU: the rest of it is dropped when it arrives and the next ADU is framed normally; a cut that runs past the ADU starts a resync.
6. The framer is provenance-agnostic: it works on stream positions, and its consumer maps them to frames.

**Roles.** The flow stage decides per connection, once there is evidence, in this order: user override; SYN (the sender of the first SYN without ACK is the client); a configured server port; structure. *Structure test:* parse the first up to 20 ADUs of both directions under orientation A (direction 1 = requests, direction 2 = responses) and B; score = the mean of the share of ADUs that have the shape of their assumed role and the share of responses that pair with an earlier request (same TID, unit and function, or the exception form). In L1 the shapes are size and field rules per function (`RequestShape`, `ResponseShape`); L2's decoders replace them. The better orientation wins if its score is at least 0.2 higher and at least 0.8 in absolute terms; otherwise the role is `unknown`. Request and response PDUs are distinguishable for most functions (a request to FC03 is exactly 5 bytes; its response is `byte count` + data), which is why the structure test is usually decisive. The decision and its source (`override | syn | port | structure`) are stored; `role_guessed` is set when the source is `port` without SYN or `structure`.

Pairing starts after the role is known; ADUs before that are buffered (bounded, 64 per direction) and replayed. `Scan` keeps only the first 20 ADU starts per direction (10 PDU bytes each) and decides when the connection closes.

## 8. PDU decoding and validation (`mbtcp`)

- A table-driven decoder per function code for request and response: `Decode(as, pdu) View` (`AsRequest`, `AsResponse`). `View` has the function and its name, `Known`, the exception and its code, the sub-function (FC08) or MEI type (FC43), the **class** (`read`, `write` (FC23 too), `other`), the named **fields** with their **byte range in the ADU** (offset 7 is the function code), the **ranges** (`Space`: coil, discrete, holding, input, file (with the file number), fifo; `Start`; `Count`; `Write`) and the **warnings**. Values stay raw: numbers for scalar fields, hex for data. `CheckPair(req, resp)` adds `response_mismatch` when a response does not fit its request (byte counts, echoes, sub-functions, FC20 record lengths, FC43 codes) and gives a read response its request's range (FC01-04 responses carry no address; FC24's count comes from the response). `ValueAt(req, resp, addr)` returns the raw word or bit at an address; `Summary(req, resp)` the one-line description ("Read 62 holding registers @ 4096: exception 2 (illegal data address)").
- `docs/COVERAGE.md` is generated by a test that walks the table (`make golden`; the test fails when it is stale): function, name, class, serial-only flag, MBCAP admission, decoded fields per direction, FC08 sub-functions. A function without an entry is opaque; the matrix must list all standardized codes (1-8, 11, 12, 15, 16, 17, 20-24, 43) and the user-defined ranges (65-72, 100-110) as opaque.
- Validation rules come from MODBUS Application Protocol V1.1b (local copy: `go-modbus/spec/MODBUS-SPEC.md`). The ones that matter for trust: quantity limits (FC01/02: 1..2000; FC03/04: 1..125; FC15: 1..1968 with byte count `ceil(q/8)`; FC16: 1..123 with byte count `2q`; FC23: read 1..125, write 1..121), byte count equals data length, fixed lengths (FC05/06 echo; FC07 request 1 byte, response 2 bytes; FC11 response 5 bytes; FC22 7 bytes; FC24 request 3 bytes), FC05 value is `0xFF00` or `0x0000`, FC20 sub-request reference type 6 and length bounds, FC43/14 object structure (`id, len, value`), exception responses exactly 2 bytes with a known code (01-08, 0A, 0B; any other code is decoded and warned as `unknown_exception_code`). A violated rule is a **warning** on the view and sets `invalid_pdu` on the transaction (which keeps it out of MBCAP). Warning codes: `empty_pdu`, `truncated`, `length_mismatch`, `quantity_out_of_range`, `byte_count_mismatch`, `coil_value`, `unknown_exception_code`, `reference_type`, `record_structure`, `mei_structure`, `read_device_id_code`, `exception_as_request`, `response_mismatch`.
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
- When the connection ends (FIN/RST, end of trace) every remaining entry becomes `unanswered`; after an eviction, and when the cap pushes the oldest out, `unanswered` and `uncertain`. A transaction touched by a gap or resync on either side is `uncertain`, whatever else it is (an ADU is `gap_adjacent` when it is the first of its direction after a gap; an outstanding request is when a gap hits the response direction while it waits).
- *(L2)* An outstanding request whose response direction had a gap is decided `unanswered` (and `uncertain`) as soon as a request sent after it is answered: its response was in the gap. Without this, every response lost to the capture would hold its request until the connection ends, and memory would grow with the trace (measured: the live heap of a 5 GiB soak went from 91 to 11 MiB).
- *(L2)* A request that repeats the `(unit, tid)` of an outstanding request with a different PDU marks both `ambiguous`, as above; the one left outstanding at the end is `unanswered`. (REQUIREMENTS L8 also lists "the transaction ID was reused" as a reason for `unanswered`; that is the case when the earlier request is never answered.)
- Connections whose roles stay undecided (`unknown`) are not paired: each ADU becomes an `uncertain` transaction with the flag `role_unknown`, the request side for the first sender.
- `malformed` is for an ADU whose PDU fails decoding so badly that no pairing is meaningful (empty PDU, truncated by snaplen, a foreign protocol frame with the flag `foreign_protocol`); it is reported alone.
- Latency is `response.first_packet_time - request.last_packet_time`; if negative it is reported as 0 with `clock_order`. Durations of the request and the response themselves (first to last packet) are kept, since they show segmentation.

## 10. Event model and provenance (`model`)

*(L2: implemented.)* The types are in package `model` with JSON tags; `docs/schema/event-1.schema.json` (draft 2020-12) is their published form, and tests validate real events against it and check by reflection that every JSON field of `model` (and of `mbtcp.View`, `Field`, `Range`) is in the schema. The schema is authoritative; the sketch below is the original design. Differences: endpoints are `netip.AddrPort`; times are `*time.Time` (absent without a timestamp); ADU PDUs are hex in JSON (`Options.OmitPDU` drops them); `FrameRef.PayOff` is `-1` after IP reassembly; connections are client/server with directions `c2s`/`s2c`; `Transaction` carries `Class`, `Ranges` and `Summary`; `EventSemanticsVersion` is 1.

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

**Quality flags** (each has a counter in the file summary and a documented meaning): `retransmitted`, `out_of_order`, `overlap_conflict`, `gap_adjacent`, `resynced`, `snaplen_truncated`, `midstream`, `role_guessed`, `retried`, `clock_order`, `slow`, `invalid_pdu`, `serial_function_over_tcp`, `unknown_function`, `broadcast`, `foreign_protocol`, `role_unknown` (L2: the roles stayed undecided), `internal_error` (a note, not a transaction flag).

**Time.** Everything is the capture timestamp (UTC, ns). Files may be out of time order (merged captures, `-i any`): the pipeline processes in file order and never sorts; consumers sort. Negative gaps are flagged. The library never calls `time.Now`.

## 11. Scan, analyzers, API sketch, CLI

**Scan** returns `FileSummary` (format, interfaces/link types, packets, bytes, first/last, snaplen facts, drop counters, unsupported counters, SHA-256, tool metadata, quality counters) and `[]Flow` (`ID`, endpoints A (client) and B (server) when the role is known, role source and confidence, packets and bytes per direction, first/last, `Class` = `modbus_tcp | tls | other_tcp`, `Score`, `ADUs`, longest run, `ServerPort`, gap and retransmission counts). It is one pass without pairing (L1: about 640 MiB/s on an M1 core, SHA-256 included, 19 MiB resident on 1 GiB). *Score* is the share of framed units (ADUs, foreign frames, junk runs) that are valid Modbus ADUs with a plausible function code, in the better direction; a flow is `modbus_tcp` if either direction has a run of at least 3 such ADUs or a share of at least 0.9. A flow is `tls` when a direction of a flow opened by SYN starts with `16 03` (a TLS record); its bytes are not framed. In L1 these types live in package `trace`; `model` starts in L2 with the event types.

**Counters** (file summary; each has a documented meaning; the per-transaction flags of section 10 follow in L2): `retransmitted`, `out_of_order`, `overlap_conflict`, `keepalives`, `syn_retransmits`, `gaps`, `gap_bytes`, `reassembly_overflow` (a direction's buffer limit declared a gap), `reassembly_budget` (the total budget declared a gap), `resyncs`, `resync_failed`, `junk_bytes` (payload bytes that framed as nothing), `foreign_protocol`, `snaplen_truncated` (ADUs), `snaplen.truncated_packets`, `snaplen.payload_bytes_cut`, `time_backwards` (packets stamped before the previous one), `connections.{total, midstream, evicted, superseded, max_tracked, packets_after_close}`, `reader.{simple_packets, skipped_blocks, unknown_blocks, other_frames, truncated_tail}`, `fragments.{reassembled, dropped, incomplete}`, `unsupported.<reason>` (section 5), `capture_drops` (pcapng `isb_ifdrop`), `internal_errors` (recovered panics with their frame numbers, at most 100 kept).

**Analyzers** implement `Sink` and are composed by the caller (`analyze.Overview`, `.Devices`, `.Patterns`, `.Coverage`); each returns a JSON-able result and reports its overflow counters. Latency uses a fixed log-scale histogram (about 1% relative resolution, no allocation per event). Patterns key on `(client addr, server endpoint, unit, function, request PDU bytes)` and track inter-request gaps with min/max/median (histogram) and jitter (median absolute deviation of the gap); volatility = changed responses / (responses - 1) (a 64-bit FNV hash of the response PDU, no storage of values). Devices count by function and status, keep up to 256 clients and a latency histogram. Coverage keeps, per server, unit and data space, merged inclusive ranges read and written. *(L3)* `mbtracectl summary` runs the four together with `Tee` in one `Analyze` pass.

**API** (implemented; `docs/API.md` and godoc are authoritative):

```go
f, err := trace.Open(path)                                  // detect, read headers; ErrNotSeekable-aware
f, err = trace.OpenFiles(paths...)                          // several files, one trace; FrameRef.Part names the file
sum, flows, err := trace.Scan(ctx, f, trace.ScanOptions{})  // pass 1
opts := trace.Options{ScanOptions: trace.ScanOptions{ServerPorts: []uint16{502, 1502}}, Flows: ids}
sum, err = trace.Analyze(ctx, f, opts, sink)                 // pass 2; sink gets model.Event; sum has the transaction counters
frames, err := f.Frames(txn.Request.Refs)                    // random access to provenance
view := mbtcp.Decode(mbtcp.AsRequest, pdu)                  // display decoding
rep, err := mbcapexport.Export(ctx, f, opts, mbcapexport.Options{Producer: ..., Selection: sel}, open) // open(header) returns a capture.Writer
sum, stats, err := timeline.Write(ctx, f, opts, w, timeline.Options{Format: timeline.CSV, Selection: sel})
stats, err := subtrace.Extract(ctx, f, opts.ScanOptions, subtrace.Options{Selection: sel, Tool: ...}, w) // pcapng
err = trace.Walk(ctx, f, opts.ScanOptions, fn)              // every raw packet with its connection ID
```

A `Sink` returning an error stops the pass. `Analyze` honors `ctx` between packets and reports progress through an optional `Progress(bytesRead, total)` callback (rate-limited by the library).

**CLI** (implemented; modbusctl conventions):

```
mbtracectl info      <trace>                       file summary, interfaces, link types, drops, snaplen facts
mbtracectl flows     <trace> [--min-score 0.5]     flow table with Modbus score and class
mbtracectl summary   <trace> [--server-port 502,1502] [selection flags] [--slow 1s] [--json]
mbtracectl timeline  <trace> [selection flags] [--order time|file] [--format text|csv|jsonl]
mbtracectl export mbcap     <trace>... -o out.mbcap [selection flags] [--change-only] [--no-exceptions]
                            [--tick-ns 1000] [--report report.json] [--name ip:port/unit=Label]
                            [--warn-replay-memory 1GiB]
mbtracectl export timeline  <trace>... -o out.csv|out.jsonl [selection flags]
mbtracectl extract   <trace>... -o sub.pcapng [--server] [--client] [--conn] [--from/--to]
mbtracectl version
selection flags: --server ip[:port]  --unit 1,2  --client ip  --conn 12  --fc 3,4,43  --status ok,exception
                 --class read  --flag midstream  --no-flag uncertain  --range holding:4096-4200
                 --from 10m --to 1h (offsets from the first packet) | --from-time/--to-time (RFC 3339)
```

*(L2)* In the commands that analyse, `--server` and `--client` both select and tell the role decision who the server and the client are (naming a server to look at asserts that it is one); in `flows` they only override the roles. Timeline ordering `--order time` holds encoded rows in a reorder window of 60 s of trace time and at most 64 MiB (`timeline.DefaultBuffer`): when the buffer is full the oldest row is written early; later rows older than the last one written are written out of order and counted (`Stats.Late`).

`<trace>` is a path or `-`. Several traces given in time order are one continuous trace (connection state carries across files; this is how rotated tcpdump `-C`/`-G` files are analyzed). A remote one-liner works: `ssh gw 'tcpdump -i eth0 -w - port 502' | mbtracectl export mbcap - -o site.mbcap` (*L3*: the exporter spools samples to a temporary file and writes the header after the pass, so WallStart is the earliest timestamp for a stream too).

*(L3)* Several files: `trace.OpenFiles` reads them in the order given as one trace; connection, reassembly and pairing state carry across, every `FrameRef` names its file by `Part` (omitted for the first), and `FileSummary.Inputs` lists each file. `File.Frames` needs files (`ErrNotSeekable` for a stream). `extract` selects connections and a time window only: transaction-level flags (`--unit`, `--fc`, ...) do not apply to packets and are refused; either end of a connection may match `--server` or `--client`, since roles are not decided there; interfaces are written as their packets first appear, binary or sub-nanosecond `if_tsresol` as nanoseconds.

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

**L1 outcome** (2026-10-15): readers, link/IP/TCP with IPv4 and IPv6 fragments, flows and reassembly, framing and roles, `trace.Scan`, `trace/tracetest`, `mbtracectl info`, `flows`, `version`. Verified against the builder's ground truth on every link type and format, every LA3/LA4/LA5 scenario and 3,000 random fault scripts; five fuzz targets; a 5 GiB stream with flat memory. Several input files as one trace (L18) moves to L3, where the exports need it.

**L2 outcome** (2026-10-15): PDU decoders and validation for every function of the coverage matrix (`docs/COVERAGE.md`), pairing, the event model (`model`, schema `docs/schema/event-1.schema.json`, validated by tests), `trace.Analyze`, `File.Frames`, `selection`, `export/timeline` (CSV, JSON Lines), `mbtracectl summary`, `timeline`, `export timeline`. LA6 with frames from a real go-modbus v1.7.1 client and server over loopback (every function the client supports, FC08 sub-functions, an exception, a paged FC43/14), LA7, LA8, LA16. A real tcpdump fixture (TESTING.md) is not committed: capturing needs privileges the tests do not have; the go-modbus bridge gives the same frames.

**L3 outcome** (2026-10-15): `export/mbcapexport` (admission, targets and streams, header tags and provenance, report with every warning, the replay estimate), `mbtracectl export mbcap` to the three encodings, several input files as one trace. LA9 (the admission matrix, the classifier against `capture.NewChecker` for every function code, sub-function and MEI type, the three encodings equal under `capture.Diff`, the report identity), LA10 (`TestReplayEndToEnd` against the pinned `mbcapctl` v0.0.2 and `modbusctl` v3.2.0: values read back through `server static` and `server replay` equal the script; a CI job), LA11.

**L4 outcome** (2026-10-15): `analyze` (overview, devices, patterns, coverage), `summary` on them, `export/subtrace` and `mbtracectl extract` (LA12: tshark reads the sub-trace with the same frames and times), the tshark oracle (LA13, advisory, triaged in TESTING.md), JSON Schemas for every CLI document generated from the Go types and validated against real output (L22), the `testdata/plant.pcapng` fixture, benchmarks (LA18), release files, v0.1.0.

**Measured numbers** (filled in by L0 and L4): throughput of `Scan` and `Analyze` per core; resident memory at default limits; pcapng write speed; machine and commit.

| Measured in L0 (spike, Apple M1, Go 1.27.2, `db97366` + L0 change) | Value |
|---|---|
| Reader only, 1 GiB synthetic pcap / pcapng | 3.3-4.1 / 2.6-3.4 GiB/s, 66 allocations per run |
| Read, parse, reassemble and frame MBAP with provenance, 1 GiB, 1,000 connections | 1,049-1,146 MiB/s, peak RSS 27-28 MiB |
| pcapng write (read included), 1 GiB | 1,271-1,770 MiB/s |
| Flow state per tracked connection | about 1.1 KB (100,000 connections: about 100 MiB) |
| modbusctl replay memory per MBCAP sample | 0.58-0.74 KB plus about 31 B per changed register value; estimate `12 MiB + 750 B × samples + 36 B × changed values` |

| `mbtracectl info` (L1 `Scan`), 1 GiB synthetic pcap / pcapng, 1,000 connections | 1.56-1.61 s / 1.62-1.68 s (about 640 MiB/s, SHA-256 included); peak RSS 19 MiB |
| `Scan` of a 5 GiB generated stream (24.1 M packets, 1,000 connections, faults) | heap in use at most 12 MiB (L1) |
| `Analyze` (L2: decode, pair, provenance) of the same 5 GiB stream, 12.2 M events | live heap at most 11 MiB (`make soak`) |
| `mbtracectl summary` (`Analyze`), 1 GiB synthetic pcap, 2.5 M transactions | 7.4-7.6 s (about 140 MiB/s), peak RSS 26-27 MiB |
| `mbtracectl export timeline` to JSON Lines, same file | 26 s, 6.3 GB written, peak RSS 173 MiB (64 MiB reorder buffer) |

PDU decoding, roles and pairing are not in the spike; `Scan` and `Analyze` are measured again at L4:

| Measured in L4 (Apple M1, Go 1.27.2, branch `feat/l3-l4` on `26fde34`, `make bench`) | Value |
|---|---|
| `BenchmarkScan`, 32 MiB generated trace, 100 connections, losses and reordering | 768 MB/s per core (SHA-256 included) |
| `BenchmarkAnalyze`, same trace (decode, pair, provenance, events counted) | 206 MB/s per core (L23 asks for 100 MB/s) |

## 13. Dependency resolution log

Resolved on: 2026-10-15, from the local module cache (the L0 work was offline; newer releases on the proxy were not checked and must be at the start of L1). Record each module, version, release date and the reason it is needed.

| Module | Version | Released | Needed for | Added in |
|---|---|---|---|---|
| `github.com/otfabric/go-modbus-capture` | v0.0.2 | 2026-10-15 | MBCAP export (fixed) | L3 |
| `github.com/spf13/cobra` | v1.10.2 | 2025-12-03 | `mbtracectl` (fixed); `go 1.15` | L1 (added) |
| `github.com/spf13/pflag` | v1.0.9 | 2025-09-01 | cobra's flags | L1 (added) |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | | cobra, on Windows only | L1 (added, indirect) |
| `github.com/stretchr/testify` | v1.12.1 (modbusctl pins v1.11.1) | 2026-08-17 | tests (fixed) | not added: L1's tests use the standard library only |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | 2026-06-28 | schema tests (fixed) | L4 |
| `github.com/otfabric/go-modbus` | v1.7.1 | | tests only (LA6, LA10) | L2 |
| `github.com/gopacket/gopacket` | v1.7.4 | 2026-10-01 | **not used** (`DECISIONS.md` D1-D3) | |

The `go` directive is `go 1.23`: go-modbus-capture v0.0.2 declares 1.23, cobra 1.15 (`DECISIONS.md` D8).
