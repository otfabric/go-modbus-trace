# Interoperability

go-modbus-trace is passive: it reads files, so nothing exchanges traffic with it. Interoperability here means that files from other tools read correctly, and that its decoding agrees with an independent decoder. Nothing is certified, and none of this is a conformance test.

| Peer | Independent | What is compared | How to reproduce | In CI |
|---|---|---|---|---|
| `tshark`, Wireshark's dissector (triaged with 4.6.9) | yes | per transaction: transaction ID, unit, function, reference number, count, exception code, request and response linking | `make interop` | advisory: `continue-on-error`, never fails the run |
| go-modbus client and server | OT Fabric | a recorded real go-modbus conversation, through `trace/tracetest` | `make test` | yes |
| Pinned `mbcapctl` and `modbusctl` | no, OT Fabric tools | the MBCAP replay path | `make tools`, then `make e2e` | yes, the `replay` job |

The pins are `MBCAPCTL_VERSION` and `MODBUSCTL_VERSION` in the [Makefile](Makefile).

Known differences with tshark, and how they were triaged, are in [docs/TESTING.md](docs/TESTING.md) section 4. The trace formats read are listed in [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md).
