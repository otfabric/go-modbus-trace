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

Results describe what the capture saw. Bounded tables can drop entries, and each limit has a counter for what it dropped, so read the quality counters along with the results.

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
