// SPDX-License-Identifier: MIT

// Package analyze holds streaming, bounded aggregators over a trace's
// events (REQUIREMENTS.md L11): Overview, Devices, Patterns and Coverage.
// Each is a trace.Sink, composed with Tee, keeps a documented cap and counts
// what the cap left out, and returns a JSON-able result.
package analyze

import (
	"math"
	"sort"
	"time"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
)

// Caps (ARCHITECTURE.md section 2).
const (
	MaxDevices          = 10_000
	MaxClientsPerDevice = 256
	MaxPatterns         = 10_000
	MaxIntervals        = 4_096  // per server, unit and data space
	MaxCoverageSpaces   = 40_000 // (server, unit, data space) keys of Coverage
)

// Tee sends every event to every sink, in order; the first error stops.
func Tee(sinks ...trace.Sink) trace.Sink {
	return trace.SinkFunc(func(e *model.Event) error {
		for _, s := range sinks {
			if err := s.Event(e); err != nil {
				return err
			}
		}
		return nil
	})
}

// Histogram is a log-scale histogram of durations: buckets 1% apart, no
// allocation per value beyond a sparse bucket map.
type Histogram struct {
	n       uint64
	min     int64
	max     int64
	buckets map[int32]uint64
}

const histBase = 1.01

func bucketOf(ns int64) int32 {
	if ns < 1 {
		return 0
	}
	return int32(math.Log(float64(ns)) / math.Log(histBase))
}

func bucketValue(b int32) int64 { return int64(math.Pow(histBase, float64(b)+0.5)) }

// Add records a duration.
func (h *Histogram) Add(d time.Duration) { h.addN(d, 1) }

func (h *Histogram) addN(d time.Duration, n uint64) {
	ns := int64(d)
	if h.buckets == nil {
		h.buckets = map[int32]uint64{}
		h.min = ns
	}
	h.n += n
	h.min, h.max = min(h.min, ns), max(h.max, ns)
	h.buckets[bucketOf(ns)] += n
}

// Quantile returns the q-quantile (0..1), within about 1%.
func (h *Histogram) Quantile(q float64) time.Duration {
	if h.n == 0 {
		return 0
	}
	keys := make([]int32, 0, len(h.buckets))
	for k := range h.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	target := uint64(math.Ceil(q * float64(h.n)))
	var seen uint64
	for _, k := range keys {
		seen += h.buckets[k]
		if seen >= max(target, 1) {
			v := bucketValue(k)
			return time.Duration(min(max(v, h.min), h.max))
		}
	}
	return time.Duration(h.max)
}

// Stats summarises a histogram.
func (h *Histogram) Stats() *DurationStats {
	if h.n == 0 {
		return nil
	}
	return &DurationStats{Count: h.n, MinNS: h.min, P50NS: int64(h.Quantile(0.5)), P95NS: int64(h.Quantile(0.95)),
		P99NS: int64(h.Quantile(0.99)), MaxNS: h.max}
}

// DurationStats are quantiles of a duration histogram (nanoseconds).
type DurationStats struct {
	Count uint64 `json:"count"`
	MinNS int64  `json:"min_ns"`
	P50NS int64  `json:"p50_ns"`
	P95NS int64  `json:"p95_ns"`
	P99NS int64  `json:"p99_ns"`
	MaxNS int64  `json:"max_ns"`
}

func tm(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func span(first, last **time.Time, t *time.Time) {
	if t == nil {
		return
	}
	if *first == nil || t.Before(**first) {
		*first = tm(t)
	}
	if *last == nil || t.After(**last) {
		*last = tm(t)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
