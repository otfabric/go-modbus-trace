// SPDX-License-Identifier: MIT

package analyze_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-modbus-trace/analyze"
	"github.com/otfabric/go-modbus-trace/trace"
)

// Devices, poll patterns and address coverage in one pass.
func Example() {
	f, err := trace.Open("../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	dev, pat, cov := analyze.NewDevices(), analyze.NewPatterns(), analyze.NewCoverage()
	if _, err := trace.Analyze(context.Background(), f, trace.Options{}, analyze.Tee(dev, pat, cov)); err != nil {
		log.Fatal(err)
	}
	for _, d := range dev.Result().Devices {
		fmt.Printf("%s unit %d: %d transactions %v, p99 latency %v\n", d.Server, d.Unit, d.Transactions, d.ByStatus, time.Duration(d.Latency.P99NS))
	}
	for _, p := range pat.Result().Patterns[:2] {
		fmt.Printf("%s polls %q every %v (jitter %v)\n", p.Client, p.Summary, time.Duration(p.Interval.P50NS).Round(time.Millisecond), time.Duration(p.JitterNS).Round(time.Millisecond))
	}
	for _, c := range cov.Result() {
		fmt.Printf("%s unit %d %s read %d-%d, %d ranges written\n", c.Server, c.Unit, c.Space, c.Read[0].Start, c.Read[0].End, len(c.Written))
	}
	// Output:
	// 10.0.0.2:502 unit 1: 62 transactions map[ok:62], p99 latency 100µs
	// 10.0.0.3:502 unit 1: 30 transactions map[ok:30], p99 latency 100µs
	// 10.0.0.3:502 unit 2: 31 transactions map[exception:1 ok:30], p99 latency 100µs
	// 10.0.0.10 polls "Read 10 holding registers @ 0" every 1s (jitter 2ms)
	// 10.0.0.10 polls "Read 4 input registers @ 0" every 2.001s (jitter 2ms)
	// 10.0.0.2:502 unit 1 holding read 0-9, 1 ranges written
	// 10.0.0.3:502 unit 1 input read 0-3, 0 ranges written
	// 10.0.0.3:502 unit 2 input read 0-3, 0 ranges written
}
