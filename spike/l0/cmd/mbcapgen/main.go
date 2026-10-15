// SPDX-License-Identifier: MIT

// Command mbcapgen writes an MBCAP file of n FC03 samples (125 registers, one
// poll per second, one target, one stream) through go-modbus-capture, to
// measure what modbusctl's replay holds in memory per sample.
//
//	mbcapgen <n> changing|constant|tenth <out.mbcap>
//
// changing: every register changes at every poll (worst case for replay).
// constant: no register ever changes (the capture still holds every sample).
// tenth:    13 of the 125 registers change at every poll.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/mbcap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mbcapgen:", err)
		os.Exit(1)
	}
}

func run() error {
	n, _ := strconv.Atoi(os.Args[1])
	profile := os.Args[2]
	f, err := os.Create(os.Args[3])
	if err != nil {
		return err
	}
	defer f.Close()
	h := capture.Header{TickNS: capture.DefaultTickNS, WallStart: time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC), Producer: "spike l0 mbcapgen"}
	w, err := mbcap.NewWriter(f, h, nil)
	if err != nil {
		return err
	}
	if err := w.WriteTarget(capture.Target{ID: 1, Transport: capture.TransportTCP, Host: "10.0.3.21", Port: 502, Unit: 1}); err != nil {
		return err
	}
	if err := w.WriteStream(capture.Stream{ID: 1, Target: 1, Role: capture.RolePoll}); err != nil {
		return err
	}
	const regs = 125
	req := []byte{0x03, 0x10, 0x00, 0x00, regs}
	resp := make([]byte, 2+2*regs)
	resp[0], resp[1] = 0x03, 2*regs
	for i := range n {
		for r := range regs {
			v := uint16(r)
			switch {
			case profile == "changing", profile == "tenth" && r%10 == 0:
				v = uint16(i + r)
			}
			resp[2+2*r], resp[3+2*r] = byte(v>>8), byte(v)
		}
		at := h.Ticks(time.Duration(i) * time.Second)
		if err := w.WriteSample(capture.Sample{Stream: 1, At: at, Request: req, Response: resp}); err != nil {
			return err
		}
	}
	return w.Close(capture.End{Known: true, At: h.Ticks(time.Duration(n) * time.Second)})
}
