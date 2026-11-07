# Exit codes

`mbtracectl` uses the exit codes of `mbcapctl`, its sibling file tool:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failure: a file that cannot be opened or is not a trace, a damaged trace, an output that cannot be written. For a damaged trace, `info`, `flows`, `summary` and `timeline` (to stdout) print what was read up to the damage, then the error goes to stderr; the exports (`export mbcap`, `export timeline -o`, `extract`) write to a temporary file that is renamed only on success, so a failure leaves no output file. |
| 2 | Usage: an unknown command or flag, a wrong number of arguments, a bad flag value (also from an `MBTRACECTL_*` variable). |

Errors go to stderr as text, also with `--json`. Ctrl-C stops a command between packets with code 1.
