// SPDX-License-Identifier: MIT

package own_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/otfabric/go-modbus-trace/spike/l0/own"
	"github.com/otfabric/go-modbus-trace/spike/l0/synth"
)

// TestGroundTruth runs the own candidate over synthetic traces with every
// fault the generator injects and compares with the generator's truth.
func TestGroundTruth(t *testing.T) {
	for _, f := range []synth.Format{synth.Pcap, synth.PcapNG} {
		for _, conns := range []int{1, 9, 64} {
			var buf bytes.Buffer
			truth, err := synth.Write(&buf, synth.Options{Format: f, Conns: conns, TargetLen: 4 << 20, Faults: true})
			if err != nil {
				t.Fatal(err)
			}
			r, err := own.NewReader(&buf)
			if err != nil {
				t.Fatal(err)
			}
			p := own.NewPipeline(own.DefaultLimits)
			var pk own.Packet
			for {
				if err := r.Next(&pk); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				p.Packet(&pk)
			}
			p.Finish()
			s := p.S
			if s.Packets != truth.Packets || s.ADUs != truth.ADUsSent-truth.ADUsLost || s.Gaps != truth.Gaps ||
				s.Retransmits != truth.Retransmits || s.Conflicts != truth.Conflicts || s.Midstream != truth.Midstream || s.BadHeaders != 0 {
				t.Errorf("format %d, %d conns:\n got  %+v\n want %+v", f, conns, s, truth)
			}
		}
	}
}
