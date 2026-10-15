# MBCAP export

How events from a passive trace become an MBCAP file that `modbusctl server replay` can host as a virtual device. Package: `export/mbcapexport`. CLI: `mbtracectl export mbcap`. Facts marked *(verified)* were checked in go-modbus-capture v0.0.2 (`capture/check.go`, `capture/capture.go`, `docs/concepts.md`, `docs/library.md`), modbusctl v3.2.0 (`internal/replay`, `cmd/server`, `internal/config/types.go`) and go-modbus v1.7.1 on 2026-10-15.

## 1. Boundary

- MBCAP is the **replay data** format and nothing else. It stores raw request and response PDUs and one time per sample; it does not hold MBAP headers, writes, vendor functions, packet data or anything not read *(verified)*. The full traffic stays in the trace and in the timeline export.
- Use `github.com/otfabric/go-modbus-capture` directly: `capture`, `mbcap` (binary), `jsonl`, `mbcsv` (long CSV), `edit.WithProvenance`. No local codec, no widening of its read-only contract, no tags used to smuggle other data.
- The format is **draft 0.1**: implemented and pinned by golden files, not frozen; 1.0 readers will not read today's files *(verified: `docs/FORMAT.md`)*. Record the library versions in header tags, test against the pinned `mbcapctl` and `modbusctl`, and follow upstream; do not invent migration support.

## 2. Mapping

| MBCAP | Content |
|---|---|
| `Header.TickNS` | `capture.DefaultTickNS` (1000 ns). `--tick-ns` may lower it (down to 1) for nanosecond traces. A time is `floor((t - WallStart) / TickNS)`. |
| `Header.WallStart` | The earliest packet timestamp of the trace (of every input, for several files), or the start of the selected time window when one is given; when that time is before 1970 (a damaged clock), the earliest exported sample. Never `time.Now`. The header is written after the pass (below), so streamed input (stdin) gets the same rule. |
| `Header.Exceptions` | `true` by default (writers drop exception responses otherwise *(verified)*). `--no-exceptions` turns it off. |
| `Header.ChangeOnly` | `false` by default: repeated identical responses are kept, so the poll cadence survives. `--change-only` is an explicit derived export; the writer then drops repeated responses and the report counts them (`change_only_dropped`). |
| `Header.Producer` | e.g. `modbus-trace-explorer 0.1.0 (go-modbus-trace 0.1.0)` or `mbtracectl 0.1.0`, passed in by the caller. |
| `Header.Tags` | `trace.file` (base names only, no paths), `trace.sha256` (per input, in order), `trace.format` (`pcap`/`pcapng`), `trace.first_packet`, `trace.last_packet` (RFC 3339 with nanoseconds), `trace.link_types`, `trace.tool` (pcapng `shb_userappl`/`shb_os` when present), `trace.clock` = `packet timestamps`, `export.selection` (canonical string of the selection), `export.admission` = `reads-only/1`, `export.library` and `export.capture_library` (versions). The reserved key `provenance` is set with `edit.WithProvenance(header, "go-modbus-trace <ver> export mbcap")` (the library convention: command and flags, no file names). The reserved key `source` is not used. |
| `Target` | One per **(server IP, server port, unit ID)**. `ID` = 1, 2, 3, ... in order of the first exported transaction. `Transport = TransportTCP`, `Host` = the server address as `netip.Addr.String()`, `Port`, `Unit`. `Label` = `--name ip:port/unit=Label` if given, else `<ip>:<port> unit <unit>`. Target tags: `trace.role_source` (`override|syn|port|structure`). A server seen on two interfaces is one target; the endpoint is advisory and a replayer may override it *(verified: concepts.md)*. |
| `Stream` | One per **(target, client IP address)**. `ID` in order of first use, `Role = "passive"` (free label; the conventional ones are poll, scan, identity, snapshot, other), `Label = "client <ip>"`. A client that reconnects, or uses several ports, stays in one stream; connection epochs, client ports and MBAP transaction IDs live in the trace, not in MBCAP. Why not one stream per connection: modbusctl hosts all streams of a target merged by time and has no stream-selection flag *(verified: `ReplayServerConfig` has none; `replay.Options.Streams` is internal)*, so finer streams buy nothing and cost index size. |
| `Sample` | `Stream`; `At` = ticks of the time the **last packet of the response ADU** was observed (the instant the response was fully received); `Request` and `Response` = the raw PDUs including the function code byte (never the MBAP header). |

**One pass, then the file.** A capture header must be written first, but its `WallStart` and tags are known only at the end of the pass. The exporter therefore spools the admitted samples to a temporary file during the pass (14 bytes of stream, time and lengths, then the two PDUs; nothing else is kept in memory but the target and stream tables), builds the header from the pass's summary, and then writes every sample through `capture.Checker` and the caller's writer. The temporary file is removed on return, also on error.

Sample order is the order of determination (response completion), which follows file order. MBCAP tolerates slightly out-of-order times across streams *(verified)*; the exporter does not sort. A trace that is badly out of time order is reported (`time_disorder`) but exported as is.

## 3. Admission matrix

The exporter classifies every transaction. Only a row marked **yes** is written; everything else is counted under its reason code in the report. The writer must never see an inadmissible sample: every header, target, stream and sample goes through `capture.Checker` first, and a refusal is a bug that fails the export with `ErrWriter` (never folded into an exclusion counter). An error of the writer itself (a full disk) fails the export as an I/O error. Either way the writer is left unfinished, and its output must be discarded (the CLI's temporary file is removed).

| Observed | MBCAP | Reason code if not |
|---|---|---|
| FC01, 02, 03, 04, status `ok`, valid, response consistent with the request | **yes** | |
| FC07, 11, 12, 17, 20, 24, status `ok`, valid | **yes** | |
| FC08 with sub-function 0x0000, 0x0002 or 0x000B-0x0012 | **yes** | |
| FC08 with any other sub-function (they change device state) | no | `fc08_state_changing` |
| FC43 with MEI type 14 (Read Device Identification) | **yes** | |
| FC43 with another MEI type | no | `mei_not_14` |
| Exception response to an admissible read (exactly `fc|0x80`, one code byte) | **yes**, if `Header.Exceptions` | `exceptions_disabled` |
| FC05, 06, 15, 16, 21, 22 | no | `write_function` |
| FC23 (Read/Write Multiple Registers) | no; its read part is **not** turned into an FC03 sample and no write echo becomes a read sample | `fc23` |
| Unknown, vendor or user-defined function code | no | `unsupported_function` |
| Status `unanswered`, `orphan_response`, `ambiguous`, `malformed`, `uncertain` | no | `unanswered`, `orphan_response`, `ambiguous_pair`, `malformed`, `uncertain` |
| Flag `invalid_pdu` (a validation rule failed), or FC01-04 whose response size does not match the request (`capture.SplitAddresses` returns false) | no | `invalid_pdu`, `response_mismatch` |
| Flag `snaplen_truncated`, `resynced` on either ADU | no | `snaplen_truncated`, `resynced` |
| Flag `clock_order` (response stamped before its request) | no | `clock_order` |
| Connection role `unknown` | no | `role_unknown` |
| Outside the selection or the time window | no | `not_selected`, `outside_window` |
| Response without a timestamp (pcapng simple packets), or stamped before 1970 (MBCAP cannot hold it) | no | `invalid_time` |

Notes. Flags `retried`, `slow`, `retransmitted`, `out_of_order`, `midstream` and `role_guessed` do **not** exclude a transaction (the content is intact); they are counted in the report's `quality` (`retried`, `slow`, `retransmitted`, `out_of_order`, `midstream`, `role_guessed`) so a user can judge. Library acceptance is not proof of a correct transaction: the structural checks come from `mbtcp` (`ARCHITECTURE.md` section 8), and the FC08/MEI/PDU-length rules are reproduced from the library's rules. A property test generates every (function code, sub-function, MEI type) combination and requires the exporter's decision to equal `capture.NewChecker`'s verdict (LA9), so a future change of the library's rules shows up as a failing test.

## 4. Determinism and IDs

Same trace(s), same selection and options, same library versions: byte-identical file. Target and stream IDs follow first use in determination order; JSON maps are written with sorted keys; tags are fixed; no export time anywhere. The binary writer's options are fixed per export (`mbcap.Options` defaults: deflate, 256 samples per block; `--compression none` and `--block-samples` mirror `mbcapctl`).

## 5. Report

Written next to the capture on request (`--report report.json`) and returned by the library. JSON Schema in `docs/schema/export-report-1.schema.json`.

```json
{
  "schema_version": 1,
  "library": "go-modbus-trace 0.1.0",
  "capture_library": "go-modbus-capture 0.0.2",
  "format": "MBCAP draft 0.1",
  "inputs": [{"file": "site.pcapng", "sha256": "...", "packets": 1830211, "first": "...", "last": "..."}],
  "selection": "unit=1,2; from=0s",
  "tick_ns": 1000,
  "wall_start": "2026-10-15T08:00:00Z",
  "transactions_seen": 912340,
  "samples_written": 880101,
  "change_only_dropped": 0,
  "excluded": {"write_function": 120, "fc23": 3, "unsupported_function": 17, "unanswered": 9, "orphan_response": 4, "ambiguous_pair": 0, "invalid_pdu": 2, "not_selected": 31000, "...": 0},
  "targets": [{"id": 1, "server": "10.0.3.21:502", "unit": 1, "label": "10.0.3.21:502 unit 1", "role_source": "syn",
               "streams": [{"id": 1, "client": "10.0.3.5", "samples": 440000}],
               "samples": 440000, "exceptions": 12, "by_function": {"3": 430000, "4": 9988, "43": 12},
               "first": "...", "last": "..."}],
  "quality": {"retransmitted": 41, "out_of_order": 3, "retried": 0, "slow": 2, "midstream": 0, "role_guessed": 0,
              "gaps": 0, "resyncs": 0, "snaplen_truncated": 0, "capture_drops": 0},
  "warnings": [{"code": "format_draft", "text": "..."},
               {"code": "stale_after_write", "target": 1, "space": "holding", "start": 4096, "count": 2, "write_time": "...", "last_read_time": "...", "text": "..."}],
  "replay": {"samples": 880101, "changed_values": 1520331, "estimated_in_memory_bytes": 727390578}
}
```

`excluded` lists every reason code, with 0 for those that did not occur. `first` and `last` of an input are given for a single input. The identity `transactions_seen = samples_written + change_only_dropped + sum(excluded)` holds exactly and is tested (LA9). Timeline events that are not transactions (connection events, gaps) are not counted in `transactions_seen`.

Warning codes (constants `mbcapexport.Warn*`): `stale_after_write` (a write to a range after the last exported read of that range: the replay will keep the pre-write value), `capture_drops` (the pcapng interface statistics report drops), `gap_in_window` (selected transactions, inside the exported window, flagged `gap_adjacent` or `resynced`: values near them are missing; `count` says how many), `unit_collision` (two targets with the same unit ID: they need separate replay instances, section 6), `role_guessed` (a target whose role came from structure only), `single_sample_target`, `time_disorder`, `format_draft`, `replay_memory` (the estimate below exceeds `--warn-replay-memory`, default 1 GiB, `0` disables it; `DECISIONS.md` Q6). `estimated_in_memory_bytes` is `12 MiB + 750 B × samples + 36 B × changed values`, where changed values counts, per target, every FC01-04 register or coil whose value differs from that address's previous exported sample, plus the bytes of every other response that differs from the previous response to the same request *(verified, L0: modbusctl v3.2.0 keeps every sample and one 16-byte point per changed address; the formula bounds every measurement, 1-30% high, `DECISIONS.md` D6)*. The file size says nothing about it: deflate made a 1.8 MiB file that needs 1.3 GiB to replay.

## 6. Replay workflow (source for `docs/REPLAY-WORKFLOW.md`)

```sh
mbtracectl flows   site.pcapng                                    # which flows look like Modbus/TCP, on which ports
mbtracectl summary site.pcapng --server-port 502,1502             # devices, units, poll patterns, addresses read
mbtracectl export mbcap site.pcapng -o site.mbcap --report site.report.json
mbcapctl verify site.mbcap && mbcapctl info site.mbcap
modbusctl server replay --input site.mbcap --listen 127.0.0.1 --port 1502 \
        --speed 1 --loops 0 --before-first absent --missing exception
modbusctl server static --input site.mbcap --listen 127.0.0.1 --port 1502 \
        --target 2 --unit 1 --at 10m
```

Flags verified against `ReplayServerConfig` and `StaticServerConfig` *(verified)*: `--listen`, `--port`, `--unit`, `--target`, `--speed`, `--loops` (0 = forever; afterwards the last values stay), `--from`, `--missing exception|zero|silence` (default exception), `--before-first hold|absent` (default **hold**), `--max-clients`, `--input`; `static` has `--at` instead of speed/loops/from. modbusctl's `--listen` defaults to every interface: recommend `127.0.0.1`.

What a replay does and does not give you:

1. **Sample and hold.** A value holds from its sample until the next sample of the same address (FC01-04, per address, so a new client may read any range whose addresses were all recorded), of the same request PDU (FC07/08/11/12/17/20/24), or per identity object (FC43/14). Nothing is interpolated; between two reads the truth is unknown *(verified: concepts.md, replay.go)*.
2. **Only what was read exists.** A passive capture holds exactly what the observed clients asked for. Everything else answers per `--missing`; prefer `exception` so absent data is visible.
3. **Writes are not replayed.** A device value changed by a write shows up only at its next read. The report's `stale_after_write` warning names the ranges where a write came after the last read.
4. **Recorded exceptions are not hosted** as device state; modbusctl ignores them *(verified: `replay.go` skips `IsException()`)*.
5. **Strict temporal fidelity** needs `--before-first absent`; the default `hold` serves the first sample from tick 0.
6. **Unit collisions.** Two servers that both use unit 1 are two targets; one listener rejects the collision. Run one replay per target with `--target N --port P`, or remap with `--unit`.
7. **Timing** is the capture point's observation of response completion, not a device timestamp; captured on the client host it includes network and stack delay. Latency itself is not replayed (a product decision: only the data and the time between samples matter).
8. **Several clients** of one device are several streams of one target; modbusctl merges them by time, so conflicting values at nearby times resolve to the later sample.
9. **Memory.** modbusctl loads the whole capture. For long traces export a time window (`--from/--to`) instead of the whole trace. A window does not carry in the values read before it; they are absent until first read inside the window (carry-in is not part of v0.1).
10. **Change-only** (`--change-only`) shrinks files for rarely changing devices and keeps the replay identical under sample and hold; it loses only the poll cadence.

## 7. Tests

LA9 (admission matrix row by row, property test against `capture.NewChecker`, verify across encodings with `capture.Diff`, report identity), LA10 (end-to-end replay against the pinned modbusctl, `replay_test.go`, TESTING.md section 5), LA11 (determinism: two exports are byte-identical). The tests build their traces with `trace/tracetest` and compare in memory; no expected capture is stored.
