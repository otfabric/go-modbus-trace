// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-modbus-trace/internal/flow"
	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

var (
	client  = netip.MustParseAddrPort("10.0.0.1:40000")
	server  = netip.MustParseAddrPort("10.0.0.2:502")
	client6 = netip.MustParseAddrPort("[fd00::1]:40000")
	server6 = netip.MustParseAddrPort("[fd00::2]:502")
)

// got is a framed ADU in the shape of tracetest.ADU.
type got struct {
	Conn      uint32
	Dir       tracetest.Dir
	TID       uint16
	Unit      uint8
	PDU       string
	Truncated bool
	Resynced  bool
}

func (g got) String() string {
	return fmt.Sprintf("c%d/%d tid=%d u=%d %s trunc=%v resync=%v", g.Conn, g.Dir, g.TID, g.Unit, g.PDU, g.Truncated, g.Resynced)
}

type result struct {
	sum   *FileSummary
	flows []Flow
	adus  []got
}

// build runs a script against a Builder and returns the trace and truth.
func build(t *testing.T, o tracetest.Options, script func(b *tracetest.Builder)) ([]byte, *tracetest.Truth) {
	t.Helper()
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, o)
	if err != nil {
		t.Fatal(err)
	}
	script(b)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), b.Truth()
}

// run scans a trace; ADUs sent by a server endpoint are ToClient.
func run(t *testing.T, data []byte, o ScanOptions, servers ...netip.AddrPort) result {
	t.Helper()
	if len(servers) == 0 {
		servers = []netip.AddrPort{server, server6}
	}
	var r result
	hook := func(c *flow.Conn, d int, a *mbtcp.ADU) {
		dir := tracetest.ToServer
		for _, s := range servers {
			if c.Endpoints[d] == s {
				dir = tracetest.ToClient
			}
		}
		r.adus = append(r.adus, got{Conn: c.ID, Dir: dir, TID: a.TID, Unit: a.Unit, PDU: hex.EncodeToString(a.PDU),
			Truncated: a.Flags&mbtcp.Truncated != 0, Resynced: a.Flags&mbtcp.Resynced != 0})
	}
	var err error
	r.sum, r.flows, err = scan(context.Background(), OpenReader(bytes.NewReader(data)), o, hook, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// want turns the truth into the ADUs a framer must produce. Truncated
// ADUs carry only their captured PDU bytes, which the caller checks apart.
func want(tr *tracetest.Truth) []got {
	var out []got
	for _, a := range tr.Delivered() {
		out = append(out, got{Conn: a.Conn, Dir: a.Dir, TID: a.TID, Unit: a.Unit, PDU: hex.EncodeToString(a.PDU),
			Truncated: a.Truncated, Resynced: a.Resynced})
	}
	return out
}

// byStream groups ADUs per connection and direction, keeping their order.
func byStream(xs []got) map[string][]string {
	m := map[string][]string{}
	for _, x := range xs {
		k := fmt.Sprintf("c%d/%d", x.Conn, x.Dir)
		m[k] = append(m[k], x.String())
	}
	return m
}

func checkADUs(t *testing.T, r result, tr *tracetest.Truth) {
	t.Helper()
	g, w := byStream(r.adus), byStream(want(tr))
	if !reflect.DeepEqual(g, w) {
		t.Errorf("ADUs differ:\n%s", diff(g, w))
	}
}

// diff shows the first differing line of each stream.
func diff(g, w map[string][]string) string {
	var b strings.Builder
	for c := uint32(1); c < 64; c++ {
		for d := 0; d < 2; d++ {
			k := fmt.Sprintf("c%d/%d", c, d)
			x, y := g[k], w[k]
			for i := 0; i < max(len(x), len(y)); i++ {
				var a, e string
				if i < len(x) {
					a = x[i]
				}
				if i < len(y) {
					e = y[i]
				}
				if a != e {
					fmt.Fprintf(&b, "  %s #%d (got %d, want %d ADUs)\n    got:  %s\n    want: %s\n", k, i, len(x), len(y), a, e)
					break
				}
			}
		}
	}
	return b.String()
}

func flat(m map[string][]string) []string {
	var out []string
	for c := uint32(1); c < 64; c++ {
		for d := 0; d < 2; d++ {
			out = append(out, m[fmt.Sprintf("c%d/%d", c, d)]...)
		}
	}
	return out
}

func checkCounters(t *testing.T, r result, tr *tracetest.Truth) {
	t.Helper()
	q := r.sum.Quality
	type pair struct {
		name      string
		got, want uint64
	}
	for _, p := range []pair{
		{"packets", r.sum.Packets, tr.Packets},
		{"connections", r.sum.Connections.Total, uint64(tr.Conns)},
		{"midstream", r.sum.Connections.Midstream, tr.Midstream},
		{"gaps", q.Gaps, tr.Gaps},
		{"gap bytes", q.GapBytes, tr.GapBytes},
		{"retransmitted", q.Retransmitted, tr.Retransmits},
		{"overlap_conflict", q.OverlapConflicts, tr.Conflicts},
		{"out_of_order", q.OutOfOrder, tr.OutOfOrder},
		{"keepalives", q.Keepalives, tr.Keepalives},
	} {
		if p.got != p.want {
			t.Errorf("%s: got %d, want %d", p.name, p.got, p.want)
		}
	}
}

// poll writes n FC03 request/response pairs on a connection.
func poll(c *tracetest.Conn, first uint16, n int) {
	for i := range n {
		tid := first + uint16(i)
		c.Request(tid, 1, tracetest.ReadRequest(3, 0x1000, 4))
		c.Response(tid, 1, tracetest.RegistersResponse(3, tid, 2, 3, 4))
	}
}

// TestLinkTypes is LA2: every link type and file format carries the same
// conversation and yields the same ADUs.
func TestLinkTypes(t *testing.T) {
	links := []tracetest.Link{tracetest.Ethernet, tracetest.EthernetVLAN, tracetest.EthernetQinQ, tracetest.Null,
		tracetest.Loop, tracetest.Raw, tracetest.IPv4Link, tracetest.IPv6Link, tracetest.SLL, tracetest.SLL2}
	formats := []tracetest.Format{tracetest.Pcap, tracetest.PcapNano, tracetest.PcapBE, tracetest.PcapNG, tracetest.PcapNGBE}
	var reference []got
	for _, l := range links {
		for _, f := range formats {
			for _, v6 := range []bool{false, true} {
				if (l == tracetest.IPv4Link && v6) || (l == tracetest.IPv6Link && !v6) {
					continue
				}
				name := fmt.Sprintf("link%d/format%d/v6=%v", l, f, v6)
				t.Run(name, func(t *testing.T) {
					cl, sv := client, server
					if v6 {
						cl, sv = client6, server6
					}
					data, tr := build(t, tracetest.Options{Format: f, Interfaces: []tracetest.Iface{{Link: l, TSResol: 9}}},
						func(b *tracetest.Builder) {
							c := b.Conn(tracetest.ConnOptions{Client: cl, Server: sv})
							poll(c, 1, 5)
							c.Close()
						})
					r := run(t, data, ScanOptions{})
					checkADUs(t, r, tr)
					checkCounters(t, r, tr)
					if len(r.flows) != 1 || r.flows[0].Class != ClassModbus || r.flows[0].Role != "syn" || r.flows[0].B != sv {
						t.Errorf("flows %+v", r.flows)
					}
					if len(r.sum.Unsupported) != 0 {
						t.Errorf("unsupported %v", r.sum.Unsupported)
					}
					if reference == nil {
						reference = r.adus
					} else if fmt.Sprint(r.adus) != fmt.Sprint(reference) {
						t.Errorf("ADUs differ from the first link type")
					}
				})
			}
		}
	}
}

// TestUnsupported counts what is not TCP by reason.
func TestUnsupported(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		b.ARP(0)
		b.UDP(0, client, server, []byte("modbus over udp"))
		b.UDP(0, client, netip.MustParseAddrPort("10.0.0.2:4789"), []byte("vxlan"))
		b.IPProto(0, client.Addr(), server.Addr(), 47, []byte("gre"))
		b.IPProto(0, client.Addr(), server.Addr(), 50, []byte("esp payload"))
		b.IPProto(0, client.Addr(), server.Addr(), 1, []byte("icmp"))
		b.Packet(0, []byte{1, 2, 3})
	})
	r := run(t, data, ScanOptions{})
	w := map[string]uint64{"not_ip": 1, "not_tcp": 2, "tunnel": 2, "ipsec": 1, "short": 1}
	if !reflect.DeepEqual(r.sum.Unsupported, w) {
		t.Errorf("unsupported %v, want %v", r.sum.Unsupported, w)
	}
}

// TestReassembly is LA3: the reassembly scenarios against the ground truth.
func TestReassembly(t *testing.T) {
	adu := func(tid uint16) tracetest.Frame {
		return tracetest.Frame{TID: tid, Unit: 1, PDU: tracetest.RegistersResponse(3, tid, 7, 7, 7, 7, 7)}
	}
	req := func(tid uint16) tracetest.Frame {
		return tracetest.Frame{TID: tid, Unit: 1, PDU: tracetest.ReadRequest(3, 0x1000, 5)}
	}
	const size = 7 + 2 + 12 // one response ADU (six registers)
	cases := []struct {
		name   string
		opts   tracetest.Options
		conn   tracetest.ConnOptions
		script func(b *tracetest.Builder, c *tracetest.Conn)
		check  func(t *testing.T, r result)
	}{
		{name: "header split over segments", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{Seg: []int{3}}, req(1))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{6, 1}}, adu(1))
		}},
		{name: "several ADUs in one segment", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{}, req(1), req(2), req(3))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(1), adu(2), adu(3))
		}},
		{name: "one-byte segments", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{OneByte: true}, req(1), req(2))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{OneByte: true}, adu(1), adu(2))
		}},
		{name: "retransmission", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{Retransmit: []int{0}}, req(1))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{size}, Retransmit: []int{0, 1}}, adu(1), adu(2))
		}},
		{name: "out of order", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{5, 10, 3, size}, Reverse: true}, adu(1), adu(2))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(3))
		}},
		{name: "conflicting overlap", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Conflict: []int{0}}, adu(1))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(2))
		}},
		{name: "loss leaves a gap, the next ADU is resynced", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, tracetest.ReadRequest(3, 0, 5))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{size, size, size}, Lose: []int{1}}, adu(1), adu(2), adu(3))
			c.Request(2, 1, tracetest.ReadRequest(3, 0, 5))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(4))
		}},
		{name: "loss inside an ADU", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{size + 4, 4}, Lose: []int{1}}, adu(1), adu(2), adu(3))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(4))
		}},
		{name: "loss acknowledged before later data", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, adu(1))
			c.Request(2, 1, tracetest.ReadRequest(3, 0, 5)) // acknowledges the lost response
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(2))
		}},
		{name: "midstream start", conn: tracetest.ConnOptions{Midstream: true}, script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			poll(c, 1, 3)
		}},
		{name: "midstream start, first response captured out of order", conn: tracetest.ConnOptions{Midstream: true},
			script: func(_ *tracetest.Builder, c *tracetest.Conn) {
				c.Request(1, 1, tracetest.ReadRequest(3, 0, 5))
				c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{9}, Reverse: true}, adu(1))
				poll(c, 2, 2)
			}},
		{name: "duplicates from a second interface", opts: tracetest.Options{Format: tracetest.PcapNG,
			Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet}, {Link: tracetest.SLL2, TSResol: 9}}},
			script: func(_ *tracetest.Builder, c *tracetest.Conn) {
				c.Write(tracetest.ToServer, tracetest.WriteOpts{Duplicate: []int{0}, DupIface: 1}, req(1))
				c.Write(tracetest.ToClient, tracetest.WriteOpts{Duplicate: []int{0}, DupIface: 1}, adu(1))
			}, check: func(t *testing.T, r result) {
				if !r.flows[0].MultiIface || r.sum.Interfaces[1].Packets != 2 {
					t.Errorf("flow %+v interfaces %+v", r.flows[0], r.sum.Interfaces)
				}
			}},
		{name: "SYN retransmission", conn: tracetest.ConnOptions{SYNRetransmit: true}, script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			poll(c, 1, 1)
		}, check: func(t *testing.T, r result) {
			if r.sum.Quality.SYNRetransmits != 1 || r.sum.Connections.Total != 1 {
				t.Errorf("quality %+v connections %+v", r.sum.Quality, r.sum.Connections)
			}
		}},
		{name: "keepalive probes", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			poll(c, 1, 1)
			c.Keepalive(tracetest.ToServer)
			c.Keepalive(tracetest.ToClient)
			poll(c, 2, 1)
		}},
		{name: "sequence wraparound", conn: tracetest.ConnOptions{ServerISN: 0xFFFFFFF0, ClientISN: 0xFFFFFFFE},
			script: func(_ *tracetest.Builder, c *tracetest.Conn) {
				poll(c, 1, 4)
				c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{4, 8}, Reverse: true}, adu(9))
			}},
		{name: "RST", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			poll(c, 1, 2)
			c.Reset(tracetest.ToClient)
		}, check: func(t *testing.T, r result) {
			if r.flows[0].Close != "rst" {
				t.Errorf("close %q", r.flows[0].Close)
			}
		}},
		{name: "4-tuple reuse: two epochs", script: func(b *tracetest.Builder, c *tracetest.Conn) {
			poll(c, 1, 2)
			c.Close()
			c2 := b.Conn(tracetest.ConnOptions{})
			poll(c2, 1, 2)
		}, check: func(t *testing.T, r result) {
			if len(r.flows) != 2 || r.flows[0].Close != "fin" || r.flows[1].ID != 2 {
				t.Errorf("flows %+v", r.flows)
			}
		}},
		{name: "IP fragments", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Fragment: 16}, adu(1), adu(2))
		}, check: func(t *testing.T, r result) {
			if r.sum.Fragments.Reassembled != 1 {
				t.Errorf("fragments %+v", r.sum.Fragments)
			}
		}},
		{name: "IPv6 fragments", conn: tracetest.ConnOptions{Client: client6, Server: server6},
			script: func(_ *tracetest.Builder, c *tracetest.Conn) {
				c.Write(tracetest.ToClient, tracetest.WriteOpts{Fragment: 24}, adu(1), adu(2))
			}, check: func(t *testing.T, r result) {
				if r.sum.Fragments.Reassembled != 1 {
					t.Errorf("fragments %+v", r.sum.Fragments)
				}
			}},
		{name: "snap length cuts an ADU, framing stays in sync", script: func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Snap: 12}, adu(1))
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, adu(2))
		}, check: func(t *testing.T, r result) {
			if r.sum.Quality.SnaplenTruncated != 1 || r.sum.Snaplen.PayloadBytesCut != size-12 || r.sum.Snaplen.TruncatedPackets != 1 {
				t.Errorf("snaplen %+v quality %+v", r.sum.Snaplen, r.sum.Quality)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, tr := build(t, tc.opts, func(b *tracetest.Builder) {
				c := b.Conn(tc.conn)
				tc.script(b, c)
				c.Close()
			})
			r := run(t, data, ScanOptions{}, server, server6)
			w := want(tr)
			// A truncated ADU carries only its captured bytes.
			for i := range r.adus {
				if r.adus[i].Truncated {
					for j := range w {
						if w[j].Truncated && strings.HasPrefix(w[j].PDU, r.adus[i].PDU) {
							w[j].PDU = r.adus[i].PDU
						}
					}
				}
			}
			if g, ww := byStream(r.adus), byStream(w); !reflect.DeepEqual(g, ww) {
				t.Errorf("ADUs differ\n got:  %s\n want: %s", strings.Join(flat(g), "\n       "), strings.Join(flat(ww), "\n       "))
			}
			checkCounters(t, r, tr)
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

// TestFraming is LA4.
func TestFraming(t *testing.T) {
	mb := tracetest.MBAP
	withProto := func(b []byte, pid uint16) []byte {
		b = append([]byte(nil), b...)
		b[2], b[3] = byte(pid>>8), byte(pid)
		return b
	}
	withLen := func(b []byte, n uint16) []byte {
		b = append([]byte(nil), b...)
		b[4], b[5] = byte(n>>8), byte(n)
		return b
	}
	good := func(tid uint16) []byte { return mb(tid, 1, tracetest.ReadRequest(3, 0, 1)) }
	raw := func(bs ...[]byte) tracetest.Frame { return tracetest.Frame{Raw: bytes.Join(bs, nil)} }
	cases := []struct {
		name    string
		frames  []tracetest.Frame
		adus    int    // valid Modbus ADUs framed
		resync  uint64 // resyncs
		foreign uint64
		junk    uint64
		failed  uint64
	}{
		{name: "bad protocol ID with a plausible length stays in sync",
			frames: []tracetest.Frame{raw(good(1), withProto(good(2), 7), good(3))}, adus: 2, foreign: 1},
		{name: "length 0", frames: []tracetest.Frame{raw(good(1), withLen(good(2), 0), good(3))}, adus: 2, resync: 1, junk: 12},
		{name: "length 1", frames: []tracetest.Frame{raw(good(1), withLen(good(2), 1), good(3))}, adus: 2, resync: 1, junk: 12},
		{name: "length 255", frames: []tracetest.Frame{raw(good(1), withLen(good(2), 255), good(3))}, adus: 2, resync: 1, junk: 12},
		{name: "junk then valid", frames: []tracetest.Frame{raw([]byte{0xde, 0xad, 0xbe, 0xef, 0}, good(1), good(2))}, adus: 2, resync: 1, junk: 5},
		{name: "start in the middle of an ADU", frames: []tracetest.Frame{raw(good(1)[5:], good(2), good(3))}, adus: 2, resync: 1, junk: 7},
		{name: "resync fails within the scan limit", frames: []tracetest.Frame{raw(bytes.Repeat([]byte{0xff}, 3000))},
			junk: 3000, failed: 3}, // two at the scan limit, one at the end of the stream
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
				c := b.Conn(tracetest.ConnOptions{})
				c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tc.frames...)
				c.Close()
			})
			r := run(t, data, ScanOptions{Limits: Limits{ResyncScan: 1024}})
			q := r.sum.Quality
			if r.flows[0].ADUs[0] != uint64(tc.adus) || q.Resyncs != tc.resync || q.ForeignFrames != tc.foreign ||
				q.JunkBytes != tc.junk || q.ResyncFailed != tc.failed {
				t.Errorf("adus %d resyncs %d foreign %d junk %d failed %d", r.flows[0].ADUs[0], q.Resyncs, q.ForeignFrames, q.JunkBytes, q.ResyncFailed)
			}
		})
	}
}

// TestJunkIsBounded: 2 MiB of junk costs bounded work and is reported.
func TestJunkIsBounded(t *testing.T) {
	junk := make([]byte, 2<<20)
	for i := range junk {
		junk[i] = byte(i*131 + i>>8)
	}
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: junk})
		poll(c, 1, 3)
		c.Close()
	})
	r := run(t, data, ScanOptions{})
	if r.sum.Quality.ResyncFailed < 30 || r.flows[0].ADUs[1] != 3 {
		t.Errorf("quality %+v flow %+v", r.sum.Quality, r.flows[0])
	}
}

// TestRoles is LA5.
func TestRoles(t *testing.T) {
	odd := netip.MustParseAddrPort("10.0.0.9:1502")
	cases := []struct {
		name   string
		conn   tracetest.ConnOptions
		opts   ScanOptions
		script func(c *tracetest.Conn)
		role   string
		server netip.AddrPort
		class  string
	}{
		{"by SYN", tracetest.ConnOptions{}, ScanOptions{}, nil, "syn", server, ClassModbus},
		{"by SYN on a non-standard port", tracetest.ConnOptions{Server: odd}, ScanOptions{}, nil, "syn", odd, ClassModbus},
		{"by port", tracetest.ConnOptions{Midstream: true}, ScanOptions{}, nil, "port", server, ClassModbus},
		{"by structure", tracetest.ConnOptions{Midstream: true, Server: odd}, ScanOptions{}, nil, "structure", odd, ClassModbus},
		{"by override", tracetest.ConnOptions{Midstream: true, Server: odd}, ScanOptions{Servers: []netip.AddrPort{netip.AddrPortFrom(odd.Addr(), 0)}},
			nil, "override", odd, ClassModbus},
		{"by configured port", tracetest.ConnOptions{Midstream: true, Server: odd}, ScanOptions{ServerPorts: []uint16{1502}},
			nil, "port", odd, ClassModbus},
		{"undecidable", tracetest.ConnOptions{Midstream: true, Server: odd}, ScanOptions{}, func(c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{TID: 1, Unit: 1, PDU: []byte{0x41, 1, 2}})
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: 9, Unit: 1, PDU: []byte{0x41, 3, 4}})
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: 8, Unit: 1, PDU: []byte{0x41, 3, 4}})
			c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{TID: 2, Unit: 1, PDU: []byte{0x41, 1, 2}})
		}, "unknown", netip.AddrPort{}, ClassModbus},
		{"TLS", tracetest.ConnOptions{Server: netip.MustParseAddrPort("10.0.0.2:802")}, ScanOptions{}, func(c *tracetest.Conn) {
			c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: append([]byte{0x16, 0x03, 0x01, 0x00, 0x40}, make([]byte, 64)...)})
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{Raw: append([]byte{0x16, 0x03, 0x03, 0x00, 0x40}, make([]byte, 64)...)})
		}, "syn", netip.MustParseAddrPort("10.0.0.2:802"), ClassTLS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
				c := b.Conn(tc.conn)
				if tc.script != nil {
					tc.script(c)
				} else {
					poll(c, 1, 4)
				}
			})
			r := run(t, data, tc.opts)
			f := r.flows[0]
			if f.Role != tc.role || f.Class != tc.class || (tc.server.IsValid() && f.B != tc.server) {
				t.Errorf("flow %+v", f)
			}
			if guessed := tc.role == "structure" || (tc.role == "port" && tc.conn.Midstream); f.RoleGuess != guessed {
				t.Errorf("role_guessed %v", f.RoleGuess)
			}
		})
	}
}

// TestNotModbus: other TCP traffic is classed other_tcp.
func TestNotModbus(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{Server: netip.MustParseAddrPort("10.0.0.2:80")})
		c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
		c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")})
		c.Close()
	})
	r := run(t, data, ScanOptions{})
	if r.flows[0].Class != ClassOther {
		t.Errorf("flow %+v", r.flows[0])
	}
}
