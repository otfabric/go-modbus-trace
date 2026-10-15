// SPDX-License-Identifier: MIT

// Package gp is the spike's candidate built on github.com/gopacket/gopacket
// v1.7.4: pcapgo readers, layers.DecodingLayerParser and reassembly.Assembler,
// feeding the same MBAP framing rule as the own candidate.
package gp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"
)

// Stats mirror own.Stats where gopacket can tell.
type Stats struct {
	Packets, Bytes int64
	Undecoded      int64
	Conns          int64
	ADUs           int64
	Gaps           int64
	GapBytes       int64
	GapUnknown     int64
	OverlapPackets int64
	Resyncs        int64
	BadHeaders     int64
	ReadErr        string
}

type source interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type ctx struct {
	ci gopacket.CaptureInfo
}

func (c *ctx) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

type framer struct {
	buf    []byte
	resync bool
}

type stream struct {
	st   *Stats
	dirs [2]framer
}

func (s *stream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	if nextSeq == -1 { // midstream: start at the first segment seen
		*start = true
	}
	return true
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	avail, _ := sg.Lengths()
	f := &s.dirs[0]
	if dir == reassembly.TCPDirServerToClient {
		f = &s.dirs[1]
	}
	switch {
	case skip > 0:
		s.st.Gaps++
		s.st.GapBytes += int64(skip)
		f.buf, f.resync = f.buf[:0], true
	case skip < 0:
		s.st.GapUnknown++
		f.buf, f.resync = f.buf[:0], true
	}
	st := sg.Stats()
	s.st.OverlapPackets += int64(st.OverlapPackets)
	if avail == 0 {
		return
	}
	data := sg.Fetch(avail)
	// Provenance: the first and last packet of this chunk. ScatterGather
	// has no chunk boundaries, only a lookup by offset (a linear scan).
	first := sg.CaptureInfo(0)
	last := sg.CaptureInfo(avail - 1)
	_, _ = first, last
	f.buf = append(f.buf, data...)
	off := 0
	for len(f.buf)-off >= 7 {
		b := f.buf[off:]
		n := 6 + (int(b[4])<<8 | int(b[5]))
		ok := b[2] == 0 && b[3] == 0 && n >= 8 && n <= 260
		if ok && f.resync {
			switch {
			case len(b) == n:
			case len(b) >= n+7:
				m := 6 + (int(b[n+4])<<8 | int(b[n+5]))
				ok = b[n+2] == 0 && b[n+3] == 0 && m >= 8 && m <= 260
			default:
				goto wait
			}
		}
		if !ok {
			s.st.BadHeaders++
			off++
			f.resync = true
			continue
		}
		if len(b) < n {
			break
		}
		if f.resync {
			s.st.Resyncs++
			f.resync = false
		}
		s.st.ADUs++
		off += n
	}
wait:
	f.buf = append(f.buf[:0], f.buf[off:]...)
}

func (s *stream) ReassemblyComplete(_ reassembly.AssemblerContext) bool { return true }

type factory struct{ st *Stats }

func (f *factory) New(_, _ gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	f.st.Conns++
	return &stream{st: f.st}
}

// Run reads r through gopacket and returns the stats.
func Run(r io.Reader, pagesPerConn int) (*Stats, error) {
	st := &Stats{}
	br := bufio.NewReaderSize(r, 256<<10)
	head, err := br.Peek(4)
	if err != nil {
		return nil, err
	}
	var src source
	var fixed layers.LinkType
	ng := binary.LittleEndian.Uint32(head) == 0x0A0D0D0A
	if ng {
		nr, err := pcapgo.NewNgReader(br, pcapgo.NgReaderOptions{WantMixedLinkType: true})
		if err != nil {
			return nil, err
		}
		src = nr
	} else {
		pr, err := pcapgo.NewReader(br)
		if err != nil {
			return nil, err
		}
		src, fixed = pr, pr.LinkType()
	}

	var (
		eth  layers.Ethernet
		dot  layers.Dot1Q
		ip4  layers.IPv4
		ip6  layers.IPv6
		tcp  layers.TCP
		pay  gopacket.Payload
		decs []gopacket.LayerType
	)
	ethP := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot, &ip4, &ip6, &tcp, &pay)
	rawP := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &ip6, &tcp, &pay)
	ethP.IgnoreUnsupported, rawP.IgnoreUnsupported = true, true

	pool := reassembly.NewStreamPool(&factory{st: st})
	asm := reassembly.NewAssembler(pool)
	asm.MaxBufferedPagesPerConnection = pagesPerConn
	var frame uint64
	var lastFlush time.Time
	for {
		data, ci, err := src.ZeroCopyReadPacketData()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				st.ReadErr = err.Error()
			}
			break
		}
		frame++
		st.Packets++
		st.Bytes += int64(len(data))
		lt := fixed
		if ng {
			lt = ci.AncillaryData[0].(layers.LinkType)
		}
		p := ethP
		if lt == layers.LinkTypeRaw || lt == layers.LinkTypeIPv4 || lt == 101 {
			p = rawP
		}
		if err := p.DecodeLayers(data, &decs); err != nil && len(decs) == 0 {
			st.Undecoded++
			continue
		}
		hasTCP := false
		var nf gopacket.Flow
		for _, l := range decs {
			switch l {
			case layers.LayerTypeTCP:
				hasTCP = true
			case layers.LayerTypeIPv4:
				nf = ip4.NetworkFlow()
			case layers.LayerTypeIPv6:
				nf = ip6.NetworkFlow()
			}
		}
		if !hasTCP {
			st.Undecoded++
			continue
		}
		// Provenance needs the frame number at every offset: the only
		// carrier through reassembly is CaptureInfo.AncillaryData.
		ci.AncillaryData = []any{frame}
		asm.AssembleWithContext(nf, &tcp, &ctx{ci: ci})
		// gopacket declares a gap only when a page limit is hit or on a
		// flush: flush segments waiting longer than 2 s of trace time.
		if ci.Timestamp.Sub(lastFlush) > time.Second {
			asm.FlushWithOptions(reassembly.FlushOptions{T: ci.Timestamp.Add(-2 * time.Second)})
			lastFlush = ci.Timestamp
		}
	}
	asm.FlushAll()
	return st, nil
}
