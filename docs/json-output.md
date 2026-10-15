# JSON output

`--json` (or `MBTRACECTL_JSON=1`) makes `mbtracectl` write one indented JSON document to stdout. Every
document carries `schema_version` (1). Field names are snake_case and stable; a change is called out in the
release notes. Times are RFC 3339 with nanoseconds, UTC. Endpoints are `ip:port` (IPv6 in brackets).
JSON Schemas follow in L4 (`docs/schema/`).

## `info`

```json
{
  "schema_version": 1,
  "traces": [{
    "summary": {
      "file": "site.pcapng", "format": "pcapng", "gzip": false, "input_bytes": 8399124, "sha256": "...",
      "packets": 40479, "bytes": 7044024, "first": "2026-10-15T08:00:00.000137Z", "last": "...",
      "interfaces": [{"id": 0, "section": 0, "link_type": 1, "link": "ethernet", "snaplen": 65535, "tsresol": 6, "packets": 20257}],
      "snaplen": {"max": 65535, "truncated_packets": 0, "payload_bytes_cut": 0},
      "unsupported": {},
      "fragments": {"reassembled": 0, "dropped": 0, "incomplete": 0},
      "reader": {"simple_packets": 0, "skipped_blocks": 0, "unknown_blocks": 0, "other_frames": 0, "truncated_tail": false},
      "connections": {"total": 64, "midstream": 8, "evicted": 0, "superseded": 0, "max_tracked": 64, "packets_after_close": 0},
      "quality": {"retransmitted": 575, "out_of_order": 192, "overlap_conflict": 192, "keepalives": 0, "syn_retransmits": 0,
                  "gaps": 192, "gap_bytes": 49728, "reassembly_overflow": 0, "reassembly_budget": 0, "resyncs": 192,
                  "resync_failed": 0, "junk_bytes": 0, "foreign_protocol": 0, "snaplen_truncated": 0},
      "time_backwards": 0
    },
    "flows": {"tcp": 64, "modbus_tcp": 64, "tls": 0}
  }]
}
```

Optional fields: `first`, `last` (absent without timestamps), `sections`, `capture_drops`, per-interface
`name`, `description` and `drops`, `internal_errors`, and `error` (the read ended early on a damaged file).
The meaning of every counter is in `ARCHITECTURE.md` sections 4 to 7 and 11.

## `flows`

```json
{
  "schema_version": 1,
  "flows": [{
    "id": 1, "a": "10.0.0.1:40000", "b": "10.0.0.2:502",
    "role_source": "syn", "role_guessed": false, "role_confidence": 1,
    "open": "syn", "close": "fin", "first": "...", "last": "...",
    "interface": 0, "multiple_interfaces": false,
    "packets": [334, 332], "bytes": [3708, 80268],
    "class": "modbus_tcp", "score": 1, "adus": [309, 306], "max_run": [309, 306],
    "foreign_protocol": 0, "resyncs": 3, "junk_bytes": 0, "server_port": 502,
    "gaps": 3, "gap_bytes": 777, "retransmitted": 9, "out_of_order": 3, "overlap_conflict": 3
  }]
}
```

`a` is the client and `b` the server when `role_source` is not `unknown`; pairs (`packets`, `bytes`,
`adus`, `max_run`) are A to B, then B to A. `role_source` is `override`, `syn`, `port`, `structure` or
`unknown`; `class` is `modbus_tcp`, `tls` or `other_tcp`; `close` is `fin`, `rst`, `end_of_trace`,
`evicted` or `superseded`.

## `version`

```json
{"build_date": "...", "commit": "...", "tag": "v0.1.0", "version": "0.1.0"}
```

## `summary`

```json
{
  "schema_version": 1,
  "selection": "fc=3",
  "summary": {"...": "as in info, plus:", "transactions": {"ok": 1325, "orphan_response": 1, "unanswered": 1},
              "transaction_flags": {"midstream": 1327, "role_guessed": 1327}},
  "devices": [{
    "server": "10.0.0.2:502", "unit": 1, "transactions": 4934,
    "statuses": {"ok": 4834, "uncertain": 100}, "functions": {"3": 4934},
    "clients": ["10.0.0.0", "10.0.0.4"], "first": "...", "last": "...", "max_latency_ns": 274000
  }]
}
```

`selection` is the canonical form of the selection flags (absent when everything is selected). `devices`
are the server endpoints and units with at least one selected transaction, ordered by server and unit;
`functions` counts by function code (decimal, as a string key).

## `timeline --format jsonl`, `export timeline` to `.jsonl`

One event per line, exactly as `trace.Analyze` produces it: the JSON Schema is
[`schema/event-1.schema.json`](schema/event-1.schema.json). `--json` on `timeline` selects this format.
The CSV form has one row per event with the columns of `timeline.Columns`: `kind`, `seq`, `time`, `conn`,
`client`, `server`, `unit`, `tid`, `function`, `sub`, `class`, `status`, `exception`, `latency_ns`, `flags`
and `warnings` (`|`-separated), `summary`, `ranges` (`space:start+count`, `:w` for writes, `;`-separated),
`request_pdu`, `response_pdu` (hex), `request_frames`, `response_frames` (frame numbers, `;`-separated),
`request_first`, `request_last`, `response_first`, `response_last`, `role_source`, `open`, `close` (connection
events), `dir`, `pos`, `bytes`, `reason` (gaps and resyncs: `bytes` is the resync's skipped count and
`reason` its confidence), `note`.
