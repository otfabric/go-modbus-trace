# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in go-modbus-trace or `mbtracectl`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-modbus-trace/security) tab → **Advisories** → **Report a vulnerability**), with:

- A description of the vulnerability
- Steps to reproduce the issue (a synthetic trace if you can; never send a customer's capture)
- The affected version(s) (`mbtracectl version` output)
- Any potential impact you've identified

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Security Considerations

### Traces are hostile input

A packet trace can come from anywhere, so every reader and decoder treats it as hostile: lengths and counts are capped, a malformed packet is counted and never fails the pass, a panic in one packet is recovered and reported, and what a pass holds is bounded by its limits for any trace size. The limits, their defaults, the reason for each value and what happens when one is reached are in one table (`docs/ARCHITECTURE.md` section 2): packet and block sizes; the interfaces, the sections and their text kept per file; tracked connections; reassembly buffers; IP fragments; the requests and the other state the analysis holds over all connections; the flows `Scan` returns. A pass holds at most the sum of them and the fixed state of the tracked connections. The work is bounded with the memory: reassembling fragments and holding out-of-order segments cost steps in proportion to the bytes, or to the logarithm of what is held, in whatever order they arrive. Each limit has a test that measures the heap or the work behind it against a budget (`docs/TESTING.md` section 3a), separate from the fuzzing. The readers, the link parser, the framer, the PDU decoders and the whole pipeline are fuzzed, and the fuzz target of the pcapng reader also reads every packet back by its offset and compares.

What is not bounded by a limit: the number of input files of one trace is the caller's (each adds its own interfaces and sections to the summary), and a `Sink` keeps what it chooses to keep.

### Offline only

The library never captures live, never opens a socket and never runs another program. `mbtracectl` reads files or standard input and writes files or standard output; nothing else.

### Traces contain sensitive data

A trace of an industrial network reveals its devices, addresses and process values. The exports copy what you select: a sub-trace copies packets verbatim, and an MBCAP capture holds the read values. Header tags record input file base names and SHA-256 hashes, never paths. Handle the outputs like the trace.
