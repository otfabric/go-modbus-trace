# Test data

No trace in this repository comes from a customer, and none may.

- **Synthetic traces** are built in the tests by `trace/tracetest`, with their ground truth; none is stored.
- **Fuzz corpora** (`*/testdata/fuzz/`) are inputs the Go fuzzer found interesting or that once failed; they
  are kept as regression seeds and run with every `go test`.
- **Real fixtures** (from L2) are captured with tcpdump on loopback between the go-modbus client and server,
  or on OT Fabric's own test rigs. Each is listed here with its origin, the tool versions and the command
  that made it. None yet.
