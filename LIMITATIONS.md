# Limitations

What go-modbus-trace does not do, or what its results cannot show. Non-goals in full: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md). What a replay can reproduce: [docs/REPLAY-WORKFLOW.md](docs/REPLAY-WORKFLOW.md).

## Scope not implemented

- **Live capture and network I/O.** The trace is the only input. Nothing is sent, and there is no TCP packet replay.
- **Other Modbus transports.** Modbus/TCP only. Modbus Security (TLS), RTU over TCP, Modbus/UDP and serial RTU/ASCII are not decoded.
- **Decryption and tunnels.** GRE, VXLAN and IPsec are counted, not opened.
- **Register values.** Raw words, bits and bytes are never turned into engineering units.
- **User-defined, vendor and unknown function codes** are kept opaque: function code and data bytes ([docs/COVERAGE.md](docs/COVERAGE.md)).
- **MBCAP export** holds reads only. Writes, FC23, vendor functions and anything uncertain are counted in the report, not exported ([docs/MBCAP-EXPORT.md](docs/MBCAP-EXPORT.md)).
- **Checksums.** TCP and IP checksums are not validated, because captures taken on the sending host show unverified checksums.

## What a trace cannot show

Results describe what the capture saw. Bounded tables can drop entries, and each limit has a counter for what it dropped, so read the quality counters along with the results. The limits and their defaults: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 2.

- **A response is certain only when every request before it was captured.** When the request direction has a hole (a lost packet, or a request the capture never saw), a response that pairs with a request from before the hole is `uncertain`: it may answer a request that is not in the trace. Such transactions are in the timeline and are not exported to MBCAP.
- **Times outside 1677 to 2262** cannot be held as nanoseconds: a pcapng packet stamped outside that range is read without a time (`reader.bad_timestamps`).
- **`Scan` returns at most `Limits.MaxFlows` flows** (1,000,000), those of the connections that closed first; the others are counted (`connections.flows_dropped`). `Analyze` reports every connection as events.
- **`File.Frames` reads with the default interface and section limits.** A pass run with larger `Limits.MaxInterfaces` or `Limits.MaxSections` can report packets on interfaces that `Frames` does not know; reading those back gives `ErrCorrupt`.

## Verification

- `tshark` is a reference in an advisory CI job, which never fails the run ([docs/TESTING.md](docs/TESTING.md) section 4). It is not a conformance test.
- The MBCAP replay path runs end to end against pinned `mbcapctl` and `modbusctl` builds, which are OT Fabric tools, not independent implementations.
- Fixtures are synthetic or small. Whether a real fixture may be committed is open ([docs/DECISIONS.md](docs/DECISIONS.md) Q8), as are the semantics of a reused transaction ID (Q9).
- Certification: none.

## Platforms

| Platform | Tested in CI |
|---|---|
| linux/amd64, linux/arm64, darwin/arm64, darwin/amd64, windows/amd64, windows/arm64 | yes, natively |
| linux/arm (v7) | cross-compiled only, not executed |
| linux/386 | the tests run every night (`nightly.yml`), without the race detector: the 32-bit run for linux/arm, whose `int` has the same width |
