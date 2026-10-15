// SPDX-License-Identifier: MIT

package analyze

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

// Overview counts transactions by status, function and quality flag.
type Overview struct {
	r OverviewResult
}

// OverviewResult is the overview of a trace.
type OverviewResult struct {
	Transactions uint64            `json:"transactions"`
	Connections  uint64            `json:"connections"`
	ByStatus     map[string]uint64 `json:"by_status"`
	ByFunction   map[string]uint64 `json:"by_function"`
	ByClass      map[string]uint64 `json:"by_class"`
	Flags        map[string]uint64 `json:"flags"`
	Gaps         uint64            `json:"gaps"`
	Resyncs      uint64            `json:"resyncs"`
	First        *time.Time        `json:"first,omitempty"`
	Last         *time.Time        `json:"last,omitempty"`
	DurationNS   int64             `json:"duration_ns"`
}

// NewOverview returns an Overview.
func NewOverview() *Overview {
	return &Overview{r: OverviewResult{ByStatus: map[string]uint64{}, ByFunction: map[string]uint64{}, ByClass: map[string]uint64{},
		Flags: map[string]uint64{}}}
}

// Event implements trace.Sink.
func (o *Overview) Event(e *model.Event) error {
	switch {
	case e.Kind == model.KindConnOpen:
		o.r.Connections++
	case e.Gap != nil:
		o.r.Gaps++
	case e.Resync != nil:
		o.r.Resyncs++
	case e.Txn != nil:
		t := e.Txn
		o.r.Transactions++
		o.r.ByStatus[t.Status]++
		o.r.ByFunction[strconv.Itoa(int(t.Function))]++
		o.r.ByClass[t.Class]++
		for _, f := range t.Flags {
			o.r.Flags[f]++
		}
		span(&o.r.First, &o.r.Last, t.Time())
	}
	return nil
}

// Result returns the overview.
func (o *Overview) Result() *OverviewResult {
	r := o.r
	if r.First != nil {
		r.DurationNS = int64(r.Last.Sub(*r.First))
	}
	return &r
}

// Devices aggregates per server endpoint and unit.
type Devices struct {
	m        map[string]*device
	overflow uint64
}

type device struct {
	DeviceResult
	clients map[string]bool
	lat     Histogram
}

// DeviceResult is one server endpoint and unit.
type DeviceResult struct {
	Server          string            `json:"server"`
	Unit            uint8             `json:"unit"`
	Transactions    uint64            `json:"transactions"`
	ByFunction      map[string]uint64 `json:"by_function"`
	ByStatus        map[string]uint64 `json:"by_status"`
	Clients         []string          `json:"clients"`
	ClientsOverflow uint64            `json:"clients_overflow"`
	First           *time.Time        `json:"first,omitempty"`
	Last            *time.Time        `json:"last,omitempty"`
	RequestBytes    uint64            `json:"request_bytes"`
	ResponseBytes   uint64            `json:"response_bytes"`
	Latency         *DurationStats    `json:"latency,omitempty"`
}

// DevicesResult lists the devices, ordered by server and unit.
type DevicesResult struct {
	Devices  []DeviceResult `json:"devices"`
	Overflow uint64         `json:"overflow"` // transactions of devices beyond MaxDevices
}

// NewDevices returns a Devices aggregator.
func NewDevices() *Devices { return &Devices{m: map[string]*device{}} }

// Event implements trace.Sink.
func (d *Devices) Event(e *model.Event) error {
	t := e.Txn
	if t == nil {
		return nil
	}
	k := fmt.Sprintf("%s/%d", t.Server, t.Unit)
	x := d.m[k]
	if x == nil {
		if len(d.m) >= MaxDevices {
			d.overflow++
			return nil
		}
		x = &device{DeviceResult: DeviceResult{Server: t.Server.String(), Unit: t.Unit, ByFunction: map[string]uint64{},
			ByStatus: map[string]uint64{}}, clients: map[string]bool{}}
		d.m[k] = x
	}
	x.Transactions++
	x.ByFunction[strconv.Itoa(int(t.Function))]++
	x.ByStatus[t.Status]++
	c := t.Client.Addr().String()
	if !x.clients[c] {
		if len(x.clients) < MaxClientsPerDevice {
			x.clients[c] = true
		} else {
			x.ClientsOverflow++
		}
	}
	span(&x.First, &x.Last, t.Time())
	if t.Request != nil {
		x.RequestBytes += uint64(t.Request.Size)
	}
	if t.Response != nil {
		x.ResponseBytes += uint64(t.Response.Size)
	}
	if t.Request != nil && t.Response != nil {
		x.lat.Add(time.Duration(t.LatencyNS))
	}
	return nil
}

// Result returns the devices.
func (d *Devices) Result() *DevicesResult {
	r := &DevicesResult{Devices: []DeviceResult{}, Overflow: d.overflow}
	for _, k := range keys(d.m) {
		x := d.m[k]
		res := x.DeviceResult
		res.Clients = keys(x.clients)
		res.Latency = x.lat.Stats()
		r.Devices = append(r.Devices, res)
	}
	sort.SliceStable(r.Devices, func(i, j int) bool {
		a, b := r.Devices[i], r.Devices[j]
		pa, _ := netip.ParseAddrPort(a.Server)
		pb, _ := netip.ParseAddrPort(b.Server)
		if c := pa.Compare(pb); c != 0 {
			return c < 0
		}
		return a.Unit < b.Unit
	})
	return r
}

// Patterns finds the poll patterns: one per client, server, unit and
// request PDU, with its cadence and how often the response changed.
type Patterns struct {
	m        map[string]*pattern
	order    []string
	overflow uint64
}

type pattern struct {
	PatternResult
	lastReq  int64
	lastResp uint64
	gaps     Histogram
}

// PatternResult is one repeated request.
type PatternResult struct {
	Client     string         `json:"client"`
	Server     string         `json:"server"`
	Unit       uint8          `json:"unit"`
	Function   uint8          `json:"function"`
	Request    string         `json:"request_pdu"` // hex
	Summary    string         `json:"summary"`
	Count      uint64         `json:"count"`
	First      *time.Time     `json:"first,omitempty"`
	Last       *time.Time     `json:"last,omitempty"`
	Interval   *DurationStats `json:"interval,omitempty"` // between successive requests
	JitterNS   int64          `json:"jitter_ns"`          // median absolute deviation of the interval
	Responses  uint64         `json:"responses"`
	Changed    uint64         `json:"changed"`    // responses that differ from the previous one
	Volatility float64        `json:"volatility"` // changed / (responses - 1)
}

// PatternsResult lists the patterns, most frequent first.
type PatternsResult struct {
	Patterns []PatternResult `json:"patterns"`
	Overflow uint64          `json:"overflow"` // transactions of patterns beyond MaxPatterns
}

// NewPatterns returns a Patterns aggregator.
func NewPatterns() *Patterns { return &Patterns{m: map[string]*pattern{}} }

// Event implements trace.Sink.
func (p *Patterns) Event(e *model.Event) error {
	t := e.Txn
	if t == nil || t.Request == nil || len(t.Request.PDU) == 0 {
		return nil
	}
	k := t.Client.Addr().String() + "|" + t.Server.String() + "|" + strconv.Itoa(int(t.Unit)) + "|" + string(t.Request.PDU)
	x := p.m[k]
	if x == nil {
		if len(p.m) >= MaxPatterns {
			p.overflow++
			return nil
		}
		x = &pattern{PatternResult: PatternResult{Client: t.Client.Addr().String(), Server: t.Server.String(), Unit: t.Unit,
			Function: t.Function, Request: hex.EncodeToString(t.Request.PDU), Summary: mbtcpSummary(t)}}
		p.m[k] = x
		p.order = append(p.order, k)
	}
	x.Count++
	if at := t.Request.First; at != nil {
		ns := at.UnixNano()
		if x.lastReq != 0 && ns >= x.lastReq {
			x.gaps.Add(time.Duration(ns - x.lastReq))
		}
		x.lastReq = ns
		span(&x.First, &x.Last, at)
	}
	if t.Response != nil && len(t.Response.PDU) > 0 {
		h := fnv.New64a()
		h.Write(t.Response.PDU)
		sum := h.Sum64()
		if x.Responses > 0 && sum != x.lastResp {
			x.Changed++
		}
		x.Responses++
		x.lastResp = sum
	}
	return nil
}

func mbtcpSummary(t *model.Transaction) string {
	if t.Request != nil && t.Request.View != nil {
		return mbtcp.Summary(*t.Request.View, nil)
	}
	return t.Summary
}

// Result returns the patterns.
func (p *Patterns) Result() *PatternsResult {
	r := &PatternsResult{Patterns: []PatternResult{}, Overflow: p.overflow}
	for _, k := range p.order {
		x := p.m[k]
		res := x.PatternResult
		res.Interval = x.gaps.Stats()
		if res.Interval != nil {
			res.JitterNS = x.gaps.mad(res.Interval.P50NS)
		}
		if res.Responses > 1 {
			res.Volatility = float64(res.Changed) / float64(res.Responses-1)
		}
		r.Patterns = append(r.Patterns, res)
	}
	sort.SliceStable(r.Patterns, func(i, j int) bool { return r.Patterns[i].Count > r.Patterns[j].Count })
	return r
}

// mad estimates the median absolute deviation from the median m.
func (h *Histogram) mad(m int64) int64 {
	var dev Histogram
	for b, n := range h.buckets {
		v := bucketValue(b)
		d := v - m
		if d < 0 {
			d = -d
		}
		dev.addN(time.Duration(d), n)
	}
	return int64(dev.Quantile(0.5))
}

// Coverage records which addresses were read and written, per server,
// unit and data space, as merged intervals.
type Coverage struct {
	m        map[string]*spaceCov
	overflow uint64
}

type spaceCov struct {
	server   string
	unit     uint8
	space    string
	read     []Interval
	written  []Interval
	overflow uint64
}

// Interval is a range of addresses with how often and when it was touched.
type Interval struct {
	Start uint16     `json:"start"`
	End   uint16     `json:"end"` // inclusive
	Count uint64     `json:"count"`
	First *time.Time `json:"first,omitempty"`
	Last  *time.Time `json:"last,omitempty"`
}

// CoverageResult is one server, unit and data space.
type CoverageResult struct {
	Server   string     `json:"server"`
	Unit     uint8      `json:"unit"`
	Space    string     `json:"space"`
	Read     []Interval `json:"read"`
	Written  []Interval `json:"written"`
	Overflow uint64     `json:"overflow"` // ranges not recorded beyond MaxIntervals
}

// NewCoverage returns a Coverage aggregator.
func NewCoverage() *Coverage { return &Coverage{m: map[string]*spaceCov{}} }

// Event implements trace.Sink. Only answered transactions count.
func (c *Coverage) Event(e *model.Event) error {
	t := e.Txn
	if t == nil || (t.Status != model.StatusOK) {
		return nil
	}
	for _, r := range t.Ranges {
		if r.Count == 0 {
			continue
		}
		k := fmt.Sprintf("%s/%d/%s", t.Server, t.Unit, r.Space)
		x := c.m[k]
		if x == nil && len(c.m) >= MaxCoverageSpaces {
			c.overflow++
			continue
		}
		if x == nil {
			x = &spaceCov{server: t.Server.String(), unit: t.Unit, space: string(r.Space)}
			c.m[k] = x
		}
		end := uint32(r.Start) + uint32(r.Count) - 1
		if end > 0xFFFF {
			end = 0xFFFF
		}
		iv := Interval{Start: r.Start, End: uint16(end), Count: 1}
		span(&iv.First, &iv.Last, t.Time())
		if r.Write {
			x.written = merge(x.written, iv, &x.overflow)
		} else {
			x.read = merge(x.read, iv, &x.overflow)
		}
	}
	return nil
}

// merge adds iv to a sorted list of disjoint intervals, joining every
// interval it overlaps or touches.
func merge(list []Interval, iv Interval, overflow *uint64) []Interval {
	i := sort.Search(len(list), func(i int) bool { return uint32(list[i].End)+1 >= uint32(iv.Start) })
	j := i
	for j < len(list) && uint32(list[j].Start) <= uint32(iv.End)+1 {
		x := list[j]
		iv.Start, iv.End = min(iv.Start, x.Start), max(iv.End, x.End)
		iv.Count += x.Count
		span(&iv.First, &iv.Last, x.First)
		span(&iv.First, &iv.Last, x.Last)
		j++
	}
	if i == j && len(list) >= MaxIntervals {
		*overflow++
		return list
	}
	out := append(list[:i:i], iv)
	return append(out, list[j:]...)
}

// Overflow counts the ranges of servers, units and spaces beyond
// MaxCoverageSpaces, which are not recorded.
func (c *Coverage) Overflow() uint64 { return c.overflow }

// Result returns the coverage, ordered by server, unit and space.
func (c *Coverage) Result() []CoverageResult {
	out := []CoverageResult{}
	for _, k := range keys(c.m) {
		x := c.m[k]
		out = append(out, CoverageResult{Server: x.server, Unit: x.unit, Space: x.space, Read: nz(x.read), Written: nz(x.written), Overflow: x.overflow})
	}
	return out
}

func nz(x []Interval) []Interval {
	if x == nil {
		return []Interval{}
	}
	return x
}
