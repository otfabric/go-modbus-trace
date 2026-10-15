// SPDX-License-Identifier: MIT

package mbcapexport

import (
	"strconv"
	"time"

	"github.com/otfabric/go-modbus-capture/capture"

	"github.com/otfabric/go-modbus-trace/trace"
)

// ReportSchemaVersion is the version of the report's JSON form
// (docs/schema/export-report-1.schema.json).
const ReportSchemaVersion = 1

// Report describes an export (MBCAP-EXPORT.md section 5). The identity
// TransactionsSeen = SamplesWritten + ChangeOnlyDropped + the sum of
// Excluded holds exactly.
type Report struct {
	SchemaVersion     int               `json:"schema_version"`
	Library           string            `json:"library"`
	CaptureLibrary    string            `json:"capture_library"`
	Format            string            `json:"format"`
	Inputs            []ReportInput     `json:"inputs"`
	Selection         string            `json:"selection"`
	TickNS            uint64            `json:"tick_ns"`
	WallStart         time.Time         `json:"wall_start"`
	TransactionsSeen  uint64            `json:"transactions_seen"`
	SamplesWritten    uint64            `json:"samples_written"`
	ChangeOnlyDropped uint64            `json:"change_only_dropped"`
	Excluded          map[string]uint64 `json:"excluded"`
	Targets           []*TargetReport   `json:"targets"`
	Quality           ReportQuality     `json:"quality"`
	Warnings          []Warning         `json:"warnings"`
	Replay            ReplayEstimate    `json:"replay"`
	changed           uint64
}

// ReportInput is one input trace.
type ReportInput struct {
	File    string     `json:"file"`
	SHA256  string     `json:"sha256"`
	Packets uint64     `json:"packets"`
	First   *time.Time `json:"first,omitempty"`
	Last    *time.Time `json:"last,omitempty"`
}

// TargetReport is one target of the capture.
type TargetReport struct {
	ID         uint32            `json:"id"`
	Server     string            `json:"server"`
	Unit       uint8             `json:"unit"`
	Label      string            `json:"label"`
	RoleSource string            `json:"role_source"`
	Streams    []*StreamReport   `json:"streams"`
	Samples    uint64            `json:"samples"`
	Exceptions uint64            `json:"exceptions"`
	ByFunction map[string]uint64 `json:"by_function"`
	First      *time.Time        `json:"first,omitempty"`
	Last       *time.Time        `json:"last,omitempty"`
}

// StreamReport is one stream (a client of a target).
type StreamReport struct {
	ID      uint32 `json:"id"`
	Client  string `json:"client"`
	Samples uint64 `json:"samples"`
}

// ReportQuality counts conditions of the trace that a user weighs.
type ReportQuality struct {
	Retransmitted    uint64 `json:"retransmitted"` // transactions with the flag
	Gaps             uint64 `json:"gaps"`
	Resyncs          uint64 `json:"resyncs"`
	SnaplenTruncated uint64 `json:"snaplen_truncated"`
	CaptureDrops     uint64 `json:"capture_drops"`
}

// Warning is one finding about the replay of this capture.
type Warning struct {
	Code         string     `json:"code"`
	Target       uint32     `json:"target,omitempty"`
	Space        string     `json:"space,omitempty"`
	Start        *uint16    `json:"start,omitempty"`
	Count        uint16     `json:"count,omitempty"`
	WriteTime    *time.Time `json:"write_time,omitempty"`
	LastReadTime *time.Time `json:"last_read_time,omitempty"`
	Text         string     `json:"text"`
}

// ReplayEstimate is what modbusctl's replay is expected to hold in memory
// (DECISIONS.md D6: 12 MiB + 750 B per sample + 36 B per changed value).
type ReplayEstimate struct {
	Samples                uint64 `json:"samples"`
	ChangedValues          uint64 `json:"changed_values"`
	EstimatedInMemoryBytes uint64 `json:"estimated_in_memory_bytes"`
}

func newReport() *Report {
	r := &Report{SchemaVersion: ReportSchemaVersion, Library: "go-modbus-trace " + trace.Version,
		CaptureLibrary: "go-modbus-capture " + CaptureLibraryVersion(), Excluded: map[string]uint64{}}
	for _, x := range Reasons {
		r.Excluded[string(x)] = 0
	}
	return r
}

func (x *exporter) finishReport(sum *trace.FileSummary, h capture.Header, disorder bool) {
	r := x.rep
	maj, min := capture.VersionMajor, capture.VersionMinor
	r.Format = "MBCAP draft " + strconv.Itoa(maj) + "." + strconv.Itoa(min)
	r.Selection = x.eo.Selection.String()
	r.TickNS, r.WallStart = h.TickNS, h.WallStart
	for _, in := range sum.Inputs {
		r.Inputs = append(r.Inputs, ReportInput{File: in.File, SHA256: in.SHA256, Packets: in.Packets})
	}
	if len(r.Inputs) == 1 {
		r.Inputs[0].First, r.Inputs[0].Last = sum.First, sum.Last
	}
	r.Quality.Gaps = sum.Quality.Gaps
	if sum.CaptureDrop != nil {
		r.Quality.CaptureDrops = *sum.CaptureDrop
	}
	r.Targets = []*TargetReport{}
	units := map[uint8]int{}
	for _, tg := range x.tlist {
		r.Targets = append(r.Targets, tg.rep)
		for _, st := range tg.streams {
			tg.rep.Streams = append(tg.rep.Streams, st.rep)
		}
		units[tg.Unit]++
	}
	r.Warnings = []Warning{{Code: "format_draft", Text: "MBCAP is a draft format: readers of version 1.0 will not read this file"}}
	if r.Quality.CaptureDrops > 0 {
		r.Warnings = append(r.Warnings, Warning{Code: "capture_drops", Text: "the capture host dropped packets: reads may be missing"})
	}
	if r.Quality.Gaps > 0 {
		r.Warnings = append(r.Warnings, Warning{Code: "gap_in_window", Text: "the trace has gaps: transactions in them are not in the capture"})
	}
	if disorder {
		r.Warnings = append(r.Warnings, Warning{Code: "time_disorder", Text: "samples are more than a second out of time order (merged captures, clock steps)"})
	}
	for _, tg := range x.tlist {
		if units[tg.Unit] > 1 {
			r.Warnings = append(r.Warnings, Warning{Code: "unit_collision", Target: tg.ID,
				Text: "another target uses the same unit ID: replay them separately (--target, --port) or remap one with --unit"})
		}
		if tg.role == "structure" {
			r.Warnings = append(r.Warnings, Warning{Code: "role_guessed", Target: tg.ID, Text: "the server was decided from the traffic's structure only"})
		}
		if tg.rep.Samples == 1 {
			r.Warnings = append(r.Warnings, Warning{Code: "single_sample_target", Target: tg.ID, Text: "the target was read once"})
		}
		r.Warnings = append(r.Warnings, x.staleAfterWrite(tg)...)
	}
	r.Replay.Samples = r.SamplesWritten
	r.Replay.ChangedValues = r.changed
	r.Replay.EstimatedInMemoryBytes = 12<<20 + 750*r.SamplesWritten + 36*r.changed
	if x.eo.WarnReplayMemory > 0 && r.Replay.EstimatedInMemoryBytes > uint64(x.eo.WarnReplayMemory) {
		r.Warnings = append(r.Warnings, Warning{Code: "replay_memory",
			Text: "a replay of this capture needs about " + strconv.FormatUint(r.Replay.EstimatedInMemoryBytes>>20, 10) + " MiB: export a shorter time window"})
	}
}

// staleAfterWrite finds the writes that came after the last exported read
// of the range they touch: the replay keeps the value from before them.
func (x *exporter) staleAfterWrite(tg *target) []Warning {
	type wk struct {
		space        string
		start, count uint16
	}
	last := map[wk]int64{}
	var order []wk
	for _, w := range x.writes[tg.key] {
		k := wk{w.space, w.start, w.count}
		if _, ok := last[k]; !ok {
			order = append(order, k)
		}
		last[k] = max(last[k], w.at)
	}
	var out []Warning
	for _, k := range order {
		at := last[k]
		var lastRead int64
		overlaps := false
		for rk, t := range tg.reads {
			if rk.space == k.space && uint32(rk.start) < uint32(k.start)+uint32(k.count) && uint32(k.start) < uint32(rk.start)+uint32(rk.count) {
				overlaps = true
				lastRead = max(lastRead, t)
			}
		}
		if !overlaps || lastRead >= at {
			continue
		}
		wt, rt := time.Unix(0, at).UTC(), time.Unix(0, lastRead).UTC()
		start := k.start
		out = append(out, Warning{Code: "stale_after_write", Target: tg.ID, Space: k.space, Start: &start, Count: k.count,
			WriteTime: &wt, LastReadTime: &rt, Text: "a write came after the last read of this range: the replay keeps the value from before it"})
	}
	return out
}
