# L0 spike

Throwaway measurement code for milestone L0. The findings and decisions are in
[`docs/DECISIONS.md`](../../docs/DECISIONS.md). This is a separate module, so
nothing here (gopacket in particular) reaches the library's `go.mod`. L1
rewrites the parts that were kept, with tests, in `internal/`; this directory
can be deleted once L1 has landed.

| Path | What |
|---|---|
| `synth/` | streaming synthetic trace writer (pcap, pcapng) with injected TCP faults and the ground truth |
| `own/` | the own candidate: reader, link/IP/TCP, reassembly and MBAP framing, pcapng writer, IP defragmenter |
| `gp/` | the gopacket v1.7.4 candidate: `pcapgo`, `DecodingLayerParser`, `reassembly` |
| `depcheck/` | imports the gopacket packages so that `go list -deps` and cross-builds show what they pull in |
| `cmd/spike/` | `gen`, `own`, `gp`, `read`, `conns`, `ngw`: the measurements |
| `cmd/mbcapgen/`, `replaymem.sh` | MBCAP files of n samples and modbusctl's replay memory |
| `cmd/framecases/` | a pcap of MBAP framing edge cases for tshark |
| `cmd/sizeown/`, `cmd/sizegp/` | binary size of each candidate |

Offline: the module resolves from the local module cache (`GOPROXY=off GOFLAGS=-mod=mod`).

```sh
go test ./...                                      # own candidate equals the ground truth
go build -o /tmp/spike ./cmd/spike
/tmp/spike gen pcap 1024 1000 /tmp/big.pcap        # 1 GiB, 1,000 connections; prints the truth
/tmp/spike gen pcapng 1024 1000 /tmp/big.pcapng
/tmp/spike own /tmp/big.pcap                       # throughput, allocations, peak heap, counts
/tmp/spike gp  /tmp/big.pcap
/tmp/spike read own /tmp/big.pcapng                # reader only
/tmp/spike conns 100000 full                       # heap per tracked connection
/tmp/spike ngw own /tmp/big.pcapng /tmp/out.pcapng # pcapng writer
go run ./cmd/framecases > /tmp/cases.pcap && tshark -r /tmp/cases.pcap -Y 'tcp.len>0' \
    -T fields -e tcp.srcport -e mbtcp.prot_id -e mbtcp.len -e _ws.expert.message
MBCAPGEN=/tmp/mbcapgen MODBUSCTL=/tmp/modbusctl ./replaymem.sh 100000 changing 15021
```

Wrap any of them in `/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux) for peak RSS.
