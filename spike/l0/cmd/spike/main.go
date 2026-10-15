// SPDX-License-Identifier: MIT

// Command spike runs the L0 measurements:
//
//	spike gen   pcap|pcapng <MiB> <conns> <out>   write a synthetic trace, print its truth
//	spike own   <trace>                           own reader + reassembly + framer
//	spike gp    <trace>                           gopacket reader + reassembly + framer
//	spike read  own|gp <trace>                    reader only
//	spike conns <n> [full]                        memory per tracked connection (own)
//	spike ngw   own|gp <in> <out>                 copy every packet through a pcapng writer
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/otfabric/go-modbus-trace/spike/l0/gp"
	"github.com/otfabric/go-modbus-trace/spike/l0/own"
	"github.com/otfabric/go-modbus-trace/spike/l0/synth"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spike gen|own|gp|read|conns ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = gen(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case "own", "gp":
		err = measure(os.Args[1], os.Args[2], false)
	case "read":
		err = measure(os.Args[2], os.Args[3], true)
	case "conns":
		err = conns(os.Args[2], len(os.Args) > 3 && os.Args[3] == "full")
	case "ngw":
		err = ngw(os.Args[2], os.Args[3], os.Args[4])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "spike:", err)
		os.Exit(1)
	}
}

func gen(format, mib, nconns, out string) error {
	m, _ := strconv.Atoi(mib)
	n, _ := strconv.Atoi(nconns)
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	opts := synth.Options{Conns: n, TargetLen: int64(m) << 20, Faults: true}
	if format == "pcapng" {
		opts.Format = synth.PcapNG
	}
	t, err := synth.Write(f, opts)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(t)
}

// peakHeap samples live heap bytes every 20 ms.
func peakHeap(stop <-chan struct{}, peak *atomic.Uint64) {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		metrics.Read(s)
		if v := s[0].Value.Uint64(); v > peak.Load() {
			peak.Store(v)
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

func measure(which, path string, readOnly bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, _ := f.Stat()
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	var peak atomic.Uint64
	stop := make(chan struct{})
	go peakHeap(stop, &peak)
	start := time.Now()
	var result any
	switch {
	case which == "own" && readOnly:
		r, err := own.NewReader(f)
		if err != nil {
			return err
		}
		var p own.Packet
		n := 0
		for r.Next(&p) == nil {
			n++
		}
		result = map[string]int{"packets": n}
	case which == "gp" && readOnly:
		br := bufio.NewReaderSize(f, 256<<10)
		head, _ := br.Peek(4)
		n := 0
		if head[0] == 0x0A {
			r, err := pcapgo.NewNgReader(br, pcapgo.NgReaderOptions{WantMixedLinkType: true})
			if err != nil {
				return err
			}
			for {
				if _, _, err := r.ZeroCopyReadPacketData(); err != nil {
					break
				}
				n++
			}
		} else {
			r, err := pcapgo.NewReader(br)
			if err != nil {
				return err
			}
			for {
				if _, _, err := r.ZeroCopyReadPacketData(); err != nil {
					break
				}
				n++
			}
		}
		result = map[string]int{"packets": n}
	case which == "own":
		r, err := own.NewReader(f)
		if err != nil {
			return err
		}
		p := own.NewPipeline(own.DefaultLimits)
		var pk own.Packet
		for {
			if err := r.Next(&pk); err != nil {
				if err != io.EOF {
					return err
				}
				break
			}
			p.Packet(&pk)
		}
		p.Finish()
		result = p.S
	case which == "gp":
		// 1 MiB per direction at gopacket's 1900-byte pages, both directions.
		st, err := gp.Run(f, 2*(1<<20)/1900)
		if err != nil {
			return err
		}
		result = st
	default:
		return fmt.Errorf("unknown pipeline %q", which)
	}
	el := time.Since(start)
	close(stop)
	runtime.ReadMemStats(&m1)
	mb := float64(fi.Size()) / (1 << 20)
	out := map[string]any{
		"pipeline":      which,
		"read_only":     readOnly,
		"file_mib":      mb,
		"seconds":       el.Seconds(),
		"mib_per_s":     mb / el.Seconds(),
		"mallocs":       m1.Mallocs - m0.Mallocs,
		"alloc_mib":     float64(m1.TotalAlloc-m0.TotalAlloc) / (1 << 20),
		"peak_heap_mib": float64(peak.Load()) / (1 << 20),
		"gc_cycles":     m1.NumGC - m0.NumGC,
		"result":        result,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// conns measures the heap per tracked connection: n midstream connections
// with one request and one partial response each (state in both directions).
func conns(arg string, full bool) error {
	n, _ := strconv.Atoi(arg)
	p := own.NewPipeline(own.DefaultLimits)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	pkt := make([]byte, 0, 128)
	for i := range n {
		for dir := range 2 {
			pkt = pkt[:0]
			pkt = append(pkt, 0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0)
			c := []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
			s := []byte{10, 255, 0, 1}
			sp, dp := []byte{0x9c, 0x40}, []byte{0x01, 0xf6}
			payload := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0x10, 0, 0, 125}
			if dir == 1 {
				c, s = s, c
				sp, dp = dp, sp
				payload = []byte{0, 1, 0, 0, 0, 253, 1, 3, 250, 0, 1, 0, 2} // header + first bytes only
				if full {                                                   // a complete 259-byte response: steady state between polls
					payload = append(payload, make([]byte, 246)...)
				}
			}
			pkt = append(pkt, c...)
			pkt = append(pkt, s...)
			pkt = append(pkt, sp...)
			pkt = append(pkt, dp...)
			pkt = append(pkt, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0)
			pkt = append(pkt, payload...)
			pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
			p.Packet(&own.Packet{Link: 101, Data: pkt, Frame: uint64(2*i + dir + 1)})
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	per := float64(m1.HeapAlloc-m0.HeapAlloc) / float64(n)
	runtime.KeepAlive(p)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"conns": p.Tracked(), "heap_bytes_per_conn": per,
		"heap_mib_at_100k": per * 100000 / (1 << 20)})
}

// ngw copies every packet of in to a pcapng file through the chosen writer,
// keeping each interface's link type and (where the writer can) resolution.
func ngw(which, in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := own.NewReader(f)
	if err != nil {
		return err
	}
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()
	var pk own.Packet
	// pcapng interfaces are known once the first packet is read.
	if err := r.Next(&pk); err != nil {
		return err
	}
	ifs := r.Interfaces()
	start := time.Now()
	n := 0
	switch which {
	case "own":
		w, err := own.NewNgWriter(o, "spike l0", "selection: all", ifs)
		if err != nil {
			return err
		}
		for {
			if err := w.WritePacket(pk.Iface, pk.TimeNS, pk.OrigLen, pk.Data); err != nil {
				return err
			}
			n++
			if r.Next(&pk) != nil {
				break
			}
		}
		err = w.Flush()
	case "gp":
		mk := func(f own.Iface) pcapgo.NgInterface {
			return pcapgo.NgInterface{LinkType: layers.LinkType(f.Link), SnapLength: f.Snap, TimestampResolution: pcapgo.NgResolution(f.TSResol)}
		}
		w, err := pcapgo.NewNgWriterInterface(o, mk(ifs[0]), pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "spike l0", Comment: "selection: all"}})
		if err != nil {
			return err
		}
		for _, f := range ifs[1:] {
			if _, err := w.AddInterface(mk(f)); err != nil {
				return err
			}
		}
		for {
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(0, pk.TimeNS).UTC(), CaptureLength: len(pk.Data), Length: int(pk.OrigLen), InterfaceIndex: int(pk.Iface)}
			if err := w.WritePacket(ci, pk.Data); err != nil {
				return err
			}
			n++
			if r.Next(&pk) != nil {
				break
			}
		}
		err = w.Flush()
	}
	el := time.Since(start)
	fi, _ := o.Stat()
	fmt.Printf("%s: %d packets, %.0f MiB/s written\n", which, n, float64(fi.Size())/(1<<20)/el.Seconds())
	return err
}
