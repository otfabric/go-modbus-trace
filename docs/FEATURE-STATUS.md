# Support and feature matrix

What go-modbus-trace supports and how it is tested. Status: v0.2.0. Function by function: [COVERAGE.md](COVERAGE.md). Out of scope: [LIMITATIONS.md](../LIMITATIONS.md). Evidence: [TESTING.md](TESTING.md) and [INTEROPERABILITY.md](../INTEROPERABILITY.md).

None of this is a conformance claim: nothing is certified.

## 1. Versions

| go-modbus-trace | Go | go-modbus-capture | Supported |
|---|---|---|---|
| **v0.2.0** | 1.23 or later (CI: 1.23 to 1.27) | v0.0.2 | **yes** |

## 2. Platforms

| Platform | Tested in CI |
|---|---|
| linux/amd64, linux/arm64, darwin/arm64, darwin/amd64, windows/amd64, windows/arm64 | yes, natively, `CGO_ENABLED=0` |
| linux/arm (v7) | cross-compiled only, not executed |

## 3. Feature support

✅ supported · ◐ partly (see the notes) · — not implemented. **Independent**: compared with `tshark` in the advisory oracle job.

| Feature | Library | mbtracectl | Own tests | Independent |
|---|:---:|:---:|---|---|
| Classic pcap (µs, ns, either endianness), pcapng, gzip | ✅ | ✅ | ✅ builder, fuzz | read by `tshark` in the oracle |
| Link types: Ethernet, 802.1Q and QinQ, BSD loopback, raw IP, Linux SLL and SLL2 | ✅ | ✅ | ✅ builder | the link type of the oracle trace only |
| TCP reassembly with faults (retransmission, reordering, gaps) | ✅ | ✅ | ✅ scenarios, chaos | no: the oracle sends each ADU in one segment |
| Modbus/TCP decode and pairing | ✅ | ✅ | ✅ ground truth, fuzz | ✅ `tshark` |
| Vendor, user-defined and unknown function codes | ◐ kept opaque | ◐ | ✅ | no |
| Timeline, sub-trace, summary, flows | ✅ | ✅ | ✅ golden hashes | no |
| MBCAP export | ◐ reads only | ✅ | ✅ replay with pinned OT Fabric tools | no |
| Modbus Security, RTU over TCP, Modbus/UDP, serial | — | — | n/a | n/a |
| GRE, VXLAN, IPsec | ◐ counted, not opened | ◐ | ✅ | no |
| Live capture | — | — | n/a | n/a |
