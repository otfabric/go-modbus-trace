# Errors

The sentinels this module exports. Test them with `errors.Is`. A malformed packet is a counted quality event, not an error, unless the file itself is unreadable.

| Error | Package | Meaning |
|---|---|---|
| `ErrFormat` | `trace` | The input is not a pcap or pcapng file. |
| `ErrCorrupt` | `trace` | Damage ended the read. What was read before it is reported, and `FileSummary.Error` has the text. Damage is a record or block length that cannot be, a gzip input that does not decompress as stored (the error also wraps the cause, for example `gzip.ErrChecksum`), a read of the input that fails, or a pcapng file with more sections than `Limits.MaxSections`. A file that merely stops early is not an error: `reader.truncated_tail`. |
| `ErrConsumed` | `trace` | A second pass over a stream input. |
| `ErrNoInput` | `trace` | `OpenFiles` was called without a path. |
| `ErrNotSeekable` | `trace` | Random access needs an uncompressed trace file. |
| `ErrFrameRef` | `trace` | A frame reference points to a file that is not in this trace. |
| `ErrWriter` | `export/mbcapexport` | The capture library's checker refused the header, a target, a stream or a sample. This is a bug: the exporter only writes admissible samples. |
| `ErrOptions` | `export/mbcapexport` | The export options are invalid. |
| `ErrTransactionSelection` | `export/subtrace` | A sub-trace selects connections and a time window, not transactions. |
| `ErrUnknownFormat` | `export/timeline` | The timeline format is unknown. |

`trace.InternalError` is not an error value: it is a record in the summary of a panic recovered while decoding one packet. This is a bug, so please report it. A call of the caller's `Sink` that does not return normally is recorded the same way; that one is the sink's.

`mbtracectl` exit codes: [cmd/mbtracectl/docs/exitcodes.md](cmd/mbtracectl/docs/exitcodes.md).
