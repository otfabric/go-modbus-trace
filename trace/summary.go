// SPDX-License-Identifier: MIT

package trace

import (
	"net/netip"
	"time"
)

// FileSummary describes a trace (the result of Scan). With several input
// files the top-level file, format and size describe them together and
// Inputs each one.
type FileSummary struct {
	File        string      `json:"file"` // base name, or "-"; several joined by commas
	Format      string      `json:"format"`
	Gzip        bool        `json:"gzip"`
	InputBytes  int64       `json:"input_bytes"` // as stored (compressed for gzip)
	SHA256      string      `json:"sha256"`      // of the input as stored (empty for several: see Inputs); complete only if the read reached the end
	Inputs      []Input     `json:"inputs"`
	Packets     uint64      `json:"packets"`
	Bytes       uint64      `json:"bytes"` // captured bytes
	First       *time.Time  `json:"first,omitempty"`
	Last        *time.Time  `json:"last,omitempty"`
	Interfaces  []Interface `json:"interfaces"`
	Sections    []Section   `json:"sections,omitempty"`
	Snaplen     Snaplen     `json:"snaplen"`
	CaptureDrop *uint64     `json:"capture_drops,omitempty"` // sum of pcapng isb_ifdrop
	// Unsupported counts packets that did not yield a TCP segment, by
	// reason (not_ip, not_tcp, tunnel, ipsec, short, bad_header, ...).
	Unsupported map[string]uint64 `json:"unsupported"`
	Fragments   Fragments         `json:"fragments"`
	Reader      ReaderCounters    `json:"reader"`
	Connections ConnCounters      `json:"connections"`
	Quality     Quality           `json:"quality"`
	// TimeBackwards counts packets stamped earlier than the packet before
	// them (merged captures, clock steps). The pipeline never sorts.
	TimeBackwards uint64 `json:"time_backwards"`
	// TSOSegments counts IPv4 packets whose total length was 0: captured
	// on the sending host before TCP segmentation offload filled it in.
	// They are used at their captured length, as Wireshark does; not an
	// error.
	TSOSegments uint64 `json:"tso_segments"`
	// InternalErrors are recovered panics, the first 100 of
	// InternalErrorCount; a non-zero count is a bug worth reporting: in the
	// library, or in the caller's Sink when it was a call of the sink that
	// did not return normally.
	InternalErrors     []InternalError `json:"internal_errors,omitempty"`
	InternalErrorCount uint64          `json:"internal_error_count,omitempty"`
	// Error is set when the read ended early on a damaged file: the text
	// of the error the pass returned (it wraps ErrCorrupt).
	Error string `json:"error,omitempty"`
	// Transactions and TransactionFlags count the transactions by status
	// and by quality flag (Analyze only).
	Transactions     map[string]uint64 `json:"transactions,omitempty"`
	TransactionFlags map[string]uint64 `json:"transaction_flags,omitempty"`
}

// Input describes one input file.
type Input struct {
	File       string `json:"file"` // base name, or "-"
	Format     string `json:"format"`
	Gzip       bool   `json:"gzip"`
	InputBytes int64  `json:"input_bytes"`
	SHA256     string `json:"sha256"`
	Packets    uint64 `json:"packets"`
}

// Interface is a capture interface.
type Interface struct {
	ID          int     `json:"id"`      // within its input
	Part        int     `json:"part"`    // index of the input file
	Section     int     `json:"section"` // pcapng section index within its input
	LinkType    uint16  `json:"link_type"`
	Link        string  `json:"link"`
	SnapLen     uint32  `json:"snaplen"`
	TSResol     byte    `json:"tsresol"` // pcapng if_tsresol: decimal digits, or 0x80|n for 2^-n
	Name        string  `json:"name,omitempty"`
	Description string  `json:"description,omitempty"`
	Packets     uint64  `json:"packets"`
	Drops       *uint64 `json:"drops,omitempty"`
}

// Section is pcapng section metadata (the capturing tool).
type Section struct {
	Part        int    `json:"part"`
	Application string `json:"application,omitempty"`
	OS          string `json:"os,omitempty"`
	Hardware    string `json:"hardware,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// Snaplen reports snap-length truncation.
type Snaplen struct {
	Max              uint32 `json:"max"`               // largest interface snap length (0: unlimited)
	TruncatedPackets uint64 `json:"truncated_packets"` // packets with caplen < origlen
	PayloadBytesCut  uint64 `json:"payload_bytes_cut"` // TCP payload bytes the snap length removed
}

// Fragments reports IP fragment reassembly.
type Fragments struct {
	Reassembled uint64 `json:"reassembled"` // datagrams
	Dropped     uint64 `json:"dropped"`     // incomplete datagrams dropped by the budget
	Incomplete  int    `json:"incomplete"`  // incomplete at the end of the trace
}

// ReaderCounters report what the file reader skipped or tolerated.
type ReaderCounters struct {
	SimplePackets uint64 `json:"simple_packets"` // no timestamp: used for flow state, never for timing
	SkippedBlocks uint64 `json:"skipped_blocks"` // pcapng blocks skipped: damaged ones with a plausible length, interface blocks past Limits.MaxInterfaces, and packets that name no interface kept
	UnknownBlocks uint64 `json:"unknown_blocks"`
	BadOptions    uint64 `json:"bad_options"`  // pcapng option areas that did not parse (ignored), an invalid if_tsresol, or option text past the 16 MiB kept per input
	OtherFrames   uint64 `json:"other_frames"` // custom and journal blocks Wireshark numbers as frames
	TruncatedTail bool   `json:"truncated_tail"`
	// BadTimestamps counts pcapng packets whose time, with the interface's
	// resolution and offset, does not fit in 64-bit nanoseconds (before
	// 1677 or after 2262). They are read without a time, like simple
	// packets: used for flow state, never for timing.
	BadTimestamps uint64 `json:"bad_timestamps"`
}

// ConnCounters report connection tracking.
type ConnCounters struct {
	Total      uint64 `json:"total"`               // connection epochs
	Midstream  uint64 `json:"midstream"`           // without a captured handshake
	Evicted    uint64 `json:"evicted"`             // dropped from a full table (Limits.MaxConns), least recently seen first, or closed by Limits.AnalysisBudget
	Superseded uint64 `json:"superseded"`          // ended by a new epoch of the same 4-tuple
	MaxTracked int    `json:"max_tracked"`         // most connections tracked at once
	AfterClose uint64 `json:"packets_after_close"` // packets of a connection after its FIN or RST (final ACKs)
	// FlowsDropped counts the connections that are not in the flow list
	// Scan returned because it was full (Limits.MaxFlows); 0 for Analyze,
	// which keeps no list.
	FlowsDropped uint64 `json:"flows_dropped"`
}

// Quality counts TCP and framing conditions over the trace.
type Quality struct {
	Retransmitted      uint64 `json:"retransmitted"`       // segments already delivered, seen again; not transactions, see model.FlagRetransmitted
	OutOfOrder         uint64 `json:"out_of_order"`        // segments held until the bytes before them came
	OverlapConflicts   uint64 `json:"overlap_conflict"`    // retransmissions whose bytes differ (the first data wins)
	Keepalives         uint64 `json:"keepalives"`          // one-byte probes before the next expected byte
	SYNRetransmits     uint64 `json:"syn_retransmits"`     // repeated SYNs of one epoch
	Gaps               uint64 `json:"gaps"`                // holes in a direction's byte stream, of any cause
	GapBytes           uint64 `json:"gap_bytes"`           // bytes in those holes, where the sequence numbers tell
	ReassemblyOverflow uint64 `json:"reassembly_overflow"` // gaps declared by Limits.BufferPerDir
	ReassemblyBudget   uint64 `json:"reassembly_budget"`   // gaps declared by Limits.BufferTotal
	AnalysisBudget     uint64 `json:"analysis_budget"`     // times Limits.AnalysisBudget freed state: roles decided early, a request decided unanswered and uncertain, a connection closed as evicted
	Resyncs            uint64 `json:"resyncs"`             // framing resynchronisations
	ResyncFailed       uint64 `json:"resync_failed"`       // resyncs that found no header within Limits.ResyncScan
	JunkBytes          uint64 `json:"junk_bytes"`          // bytes of TCP payload that framed as nothing
	ForeignFrames      uint64 `json:"foreign_protocol"`
	SnaplenTruncated   uint64 `json:"snaplen_truncated"` // ADUs cut by the snap length
}

// InternalError is a recovered panic while decoding one packet (Frame 0:
// while flushing at the end of the trace); a Sink call for that packet that
// did not return normally is recorded the same way.
type InternalError struct {
	Frame   uint64 `json:"frame"` // within the input being read when it happened
	Message string `json:"message"`
}

// Flow is one TCP connection epoch with its Modbus assessment.
type Flow struct {
	ID uint32 `json:"id"`
	// A and B are the endpoints; when the role is known A is the client
	// and B the server.
	A          netip.AddrPort `json:"a"`
	B          netip.AddrPort `json:"b"`
	Role       string         `json:"role_source"` // override, syn, port, structure, unknown
	RoleGuess  bool           `json:"role_guessed"`
	Confidence float64        `json:"role_confidence"`
	Open       string         `json:"open"`  // syn, midstream
	Close      string         `json:"close"` // fin, rst, end_of_trace, evicted, superseded
	First      *time.Time     `json:"first,omitempty"`
	Last       *time.Time     `json:"last,omitempty"`
	Iface      uint32         `json:"interface"` // the interface of its first packet
	MultiIface bool           `json:"multiple_interfaces"`
	Packets    [2]uint64      `json:"packets"` // A to B, B to A
	Bytes      [2]uint64      `json:"bytes"`   // TCP payload bytes
	// Class is modbus_tcp, tls or other_tcp.
	Class string `json:"class"`
	// Score is the share of framed units that are valid Modbus ADUs, in
	// the better direction (0..1).
	Score       float64   `json:"score"`
	ADUs        [2]uint64 `json:"adus"`
	MaxRun      [2]uint64 `json:"max_run"`          // longest run of consecutive valid ADUs
	Foreign     uint64    `json:"foreign_protocol"` // frames with a non-zero MBAP protocol ID, skipped by length
	Resyncs     uint64    `json:"resyncs"`          // framing resynchronisations, both directions
	JunkBytes   uint64    `json:"junk_bytes"`
	ServerPort  uint16    `json:"server_port,omitempty"` // B's port when the role is known
	Gaps        uint64    `json:"gaps"`
	GapBytes    uint64    `json:"gap_bytes"`
	Retransmits uint64    `json:"retransmitted"`
	OutOfOrder  uint64    `json:"out_of_order"`
	Conflicts   uint64    `json:"overlap_conflict"`
}

// Flow classes.
const (
	ClassModbus = "modbus_tcp"
	ClassTLS    = "tls"
	ClassOther  = "other_tcp"
)
