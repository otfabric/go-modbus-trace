# Exit codes

`mbtracectl` uses the organisation exit-code table (otfabric engineering, `standards/api-design.md`, CLI-001). It reads files only, so it has no transport, timeout, protocol, permission or safety codes, and no command completes with a result that reports problems, so 1 (findings) is not used:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 2 | Usage: an unknown command or flag, a wrong number of arguments, a bad flag value (also from an `MBTRACECTL_*` variable), standard input combined with other inputs, an output that is also an input. |
| 3 | Invalid input: a trace that cannot be opened, is not a pcap or pcapng file, or is damaged. For a damaged trace, `info`, `flows`, `summary` and `timeline` (to stdout) print what was read up to the damage, then the error goes to stderr. |
| 10 | Output or internal error: an output that cannot be written (a closed pipe, a full disk, a directory that does not exist), or a bug such as a refusal by the capture library's checker. |
| 130 | Interrupted: Ctrl-C (SIGINT) or SIGTERM stops a command between packets. |

The exports (`export mbcap`, `export timeline -o`, `extract`) write to a temporary file that is renamed only on success, so a failure or an interruption leaves no output file. Errors go to stderr as text, also with `--json`.

## Changes in v0.6.0

Until v0.5.2, `mbtracectl` used 0, 1 and 2 (as `mbcapctl`). From v0.6.0:

| Before | Now | When |
|---|---|---|
| 0 | 0 | Success. |
| 1 | 3 | A trace that cannot be opened, is not a trace, or is damaged. |
| 1 | 10 | An output that cannot be written. |
| 1 | 130 | Interrupted (Ctrl-C, now also SIGTERM). |
| 1 | 2 | An unknown command (`mbtracectl nope`); the documentation already said 2. `mbtracectl export nope` printed the help and exited 0; it is now 2 as well. |
| 2 | 2 | Usage. |
