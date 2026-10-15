# Test data

No trace in this repository comes from a customer, and none may.

- **Synthetic traces** are built in the tests by `trace/tracetest`, with their ground truth; none is stored.
- **Fuzz corpora** (`*/testdata/fuzz/`) are inputs the Go fuzzer found interesting or that once failed; they
  are kept as regression seeds and run with every `go test`.
- **`plant.pcapng`** is synthetic too, but stored, so that the README's commands have a file to run on: a
  minute of a SCADA host (10.0.0.10) polling an inverter (10.0.0.2:502, unit 1: FC03 0–9 every second, one
  FC43 identification, one FC06 setpoint at 30 s) and a gateway (10.0.0.3:502, units 1 and 2: FC04 0–3 every
  2 s, one exception). `plant()` in `trace/fixture_test.go` builds it; `TestFixture` fails when the file
  differs and `make golden` rewrites it. `plant.outputs.json` holds the SHA-256 of every output the CLI writes
  for it; `TestGoldenOutputs` checks them on every CI runner (cross-platform determinism).
- **Real fixtures** are captured with tcpdump on loopback between the go-modbus client and server,
  or on OT Fabric's own test rigs. Each is listed here with its origin, the tool versions and the command
  that made it. None yet: whether a real capture may be committed is an open question (docs/DECISIONS.md).
