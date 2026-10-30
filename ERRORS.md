# Errors

The sentinels this module exports. Test them with `errors.Is`. A malformed packet is a counted quality event, not an error, unless the file itself is unreadable.

| Error | Package | Meaning |
|---|---|---|
| `ErrFormat` | `trace` | The input is not a pcap or pcapng file. |
| `ErrCorrupt` | `trace` | Damage ended the read. What was read before it is reported. |
| `ErrConsumed` | `trace` | A second pass over a stream input. |
| `ErrNoInput` | `trace` | `OpenFiles` was called without a path. |
| `ErrNotSeekable` | `trace` | Random access needs an uncompressed trace file. |
| `ErrFrameRef` | `trace` | A frame reference points to a file that is not in this trace. |
| `ErrWriter` | `export/mbcapexport` | The capture library's checker refused the header, a target, a stream or a sample. This is a bug: the exporter only writes admissible samples. |
| `ErrOptions` | `export/mbcapexport` | The export options are invalid. |
| `ErrTransactionSelection` | `export/subtrace` | A sub-trace selects connections and a time window, not transactions. |
| `ErrUnknownFormat` | `export/timeline` | The timeline format is unknown. |

`trace.InternalError` is not an error value: it is a record in the summary of a panic recovered while decoding one packet. This is a bug, so please report it.

`mbtracectl` exit codes: [docs/exitcodes.md](docs/exitcodes.md).
