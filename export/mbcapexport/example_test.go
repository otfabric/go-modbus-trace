// SPDX-License-Identifier: MIT

package mbcapexport_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/mbcap"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
)

// A trace becomes an MBCAP capture that modbusctl serves as a virtual
// device; the report says what was left out and why.
func ExampleExport() {
	f, err := trace.Open("../../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out, err := os.Create(filepath.Join(dir, "plant.mbcap"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	rep, err := mbcapexport.Export(context.Background(), f, trace.Options{},
		mbcapexport.Options{Producer: "example 1.0", Names: map[string]string{"10.0.0.2:502/1": "Inverter"}},
		func(h capture.Header) (capture.Writer, error) { return mbcap.NewWriter(out, h, nil) })
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rep.TransactionsSeen, "transactions,", rep.SamplesWritten, "samples, writes left out:", rep.Excluded["write_function"])
	for _, t := range rep.Targets {
		fmt.Printf("target %d %q: %d samples\n", t.ID, t.Label, t.Samples)
	}
	for _, w := range rep.Warnings {
		if w.Code != mbcapexport.WarnFormatDraft {
			fmt.Println("warning:", w.Code, "target", w.Target)
		}
	}
	// Output:
	// 123 transactions, 122 samples, writes left out: 1
	// target 1 "Inverter": 61 samples
	// target 2 "10.0.0.3:502 unit 1": 30 samples
	// target 3 "10.0.0.3:502 unit 2": 31 samples
	// warning: unit_collision target 1
	// warning: unit_collision target 2
}

// Classify says whether one transaction would be exported, and if not why,
// without running an export.
func ExampleClassify() {
	f, err := trace.Open("../../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	reasons := map[string]int{}
	_, err = trace.Analyze(context.Background(), f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if e.Txn != nil {
			r := mbcapexport.Classify(e.Txn)
			if r == mbcapexport.Admit {
				r = "admit"
			}
			reasons[string(r)]++
		}
		return nil
	}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(reasons)
	// Output:
	// map[admit:122 write_function:1]
}
