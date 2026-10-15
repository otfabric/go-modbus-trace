// SPDX-License-Identifier: MIT

package trace_test

import (
	"context"
	"fmt"
	"log"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
)

// Every transaction of a trace, as it completes.
func ExampleAnalyze() {
	f, err := trace.Open("../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	n := 0
	sum, err := trace.Analyze(context.Background(), f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if t := e.Txn; t != nil && n < 3 {
			n++
			fmt.Println(t.Time().Format("15:04:05.000"), t.Server, t.Unit, t.Status, t.Summary)
		}
		return nil
	}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sum.Transactions)
	// Output:
	// 08:00:00.000 10.0.0.2:502 1 ok Read Device Identification
	// 08:00:00.000 10.0.0.2:502 1 ok Read 10 holding registers @ 0
	// 08:00:00.001 10.0.0.3:502 1 ok Read 4 input registers @ 0
	// map[exception:1 ok:122]
}

// The Modbus/TCP flows of a trace, found by their traffic in one cheap pass.
func ExampleScan() {
	f, err := trace.Open("../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	_, flows, err := trace.Scan(context.Background(), f, trace.ScanOptions{})
	if err != nil {
		log.Fatal(err)
	}
	for _, fl := range flows {
		fmt.Println(fl.ID, fl.A, "->", fl.B, fl.Class, fl.Role, fl.ADUs)
	}
	// Output:
	// 1 10.0.0.10:40100 -> 10.0.0.2:502 modbus_tcp syn [62 62]
	// 2 10.0.0.10:40200 -> 10.0.0.3:502 modbus_tcp syn [61 61]
}

// The packets that carried a response, read back by reference: an
// application keeps the references, not the bytes.
func ExampleFile_Frames() {
	f, err := trace.Open("../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	var refs []model.FrameRef
	_, err = trace.Analyze(context.Background(), f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if t := e.Txn; t != nil && t.Status == model.StatusException {
			refs = t.Response.Refs
		}
		return nil
	}))
	if err != nil {
		log.Fatal(err)
	}
	frames, err := f.Frames(refs)
	if err != nil {
		log.Fatal(err)
	}
	for _, fr := range frames {
		fmt.Printf("frame %d: % x\n", fr.Ref.Frame, fr.Payload) // MBAP header, then the PDU
	}
	// Output:
	// frame 56: 13 88 00 00 00 03 02 84 02
}
