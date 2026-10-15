// SPDX-License-Identifier: MIT

package trace

import (
	"net/netip"
	"time"
)

// FileSummary describes a trace file (the result of Scan).
type FileSummary struct {
	File        string      `json:"file"` // base name, or "-"
	Format      string      `json:"format"`
	Gzip        bool        `json:"gzip"`
	InputBytes  int64       `json:"input_bytes"` // as stored (compressed for gzip)
	SHA256      string      `json:"sha256"`      // of the input as stored; complete only if the read reached the end
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
	TimeBackwards  uint64          `json:"time_backwards"`
	InternalErrors []InternalError `json:"internal_errors,omitempty"`
	// Error is set when the read ended early on a damaged file.
	Error string `json:"error,omitempty"`
	// Transactions and TransactionFlags count the transactions by status
	// and by quality flag (Analyze only).
	Transactions     map[string]uint64 `json:"transactions,omitempty"`
	TransactionFlags map[string]uint64 `json:"transaction_flags,omitempty"`
}

// Interface is a capture interface.
type Interface struct {
	ID          int     `json:"id"`
	Section     int     `json:"section"`
	LinkType    uint16  `json:"link_type"`
	Link        string  `json:"link"`
	SnapLen     uint32  `json:"snaplen"`
	TSResol     byte    `json:"tsresol"`
	Name        string  `json:"name,omitempty"`
	Description string  `json:"description,omitempty"`
	Packets     uint64  `json:"packets"`
	Drops       *uint64 `json:"drops,omitempty"`
}

// Section is pcapng section metadata (the capturing tool).
type Section struct {
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
	SkippedBlocks uint64 `json:"skipped_blocks"` // damaged pcapng blocks with a plausible length
	UnknownBlocks uint64 `json:"unknown_blocks"`
	OtherFrames   uint64 `json:"other_frames"` // custom and journal blocks Wireshark numbers as frames
	TruncatedTail bool   `json:"truncated_tail"`
}

// ConnCounters report connection tracking.
type ConnCounters struct {
	Total      uint64 `json:"total"` // connection epochs
	Midstream  uint64 `json:"midstream"`
	Evicted    uint64 `json:"evicted"`
	Superseded uint64 `json:"superseded"`
	MaxTracked int    `json:"max_tracked"`
	AfterClose uint64 `json:"packets_after_close"`
}

// Quality counts TCP and framing conditions over the trace.
type Quality struct {
	Retransmitted      uint64 `json:"retransmitted"`
	OutOfOrder         uint64 `json:"out_of_order"`
	OverlapConflicts   uint64 `json:"overlap_conflict"`
	Keepalives         uint64 `json:"keepalives"`
	SYNRetransmits     uint64 `json:"syn_retransmits"`
	Gaps               uint64 `json:"gaps"`
	GapBytes           uint64 `json:"gap_bytes"`
	ReassemblyOverflow uint64 `json:"reassembly_overflow"`
	ReassemblyBudget   uint64 `json:"reassembly_budget"`
	Resyncs            uint64 `json:"resyncs"`
	ResyncFailed       uint64 `json:"resync_failed"`
	JunkBytes          uint64 `json:"junk_bytes"` // bytes of TCP payload that framed as nothing
	ForeignFrames      uint64 `json:"foreign_protocol"`
	SnaplenTruncated   uint64 `json:"snaplen_truncated"` // ADUs cut by the snap length
}

// InternalError is a recovered panic while decoding one packet.
type InternalError struct {
	Frame   uint64 `json:"frame"`
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
	Iface      uint32         `json:"interface"`
	MultiIface bool           `json:"multiple_interfaces"`
	Packets    [2]uint64      `json:"packets"` // A to B, B to A
	Bytes      [2]uint64      `json:"bytes"`   // TCP payload bytes
	// Class is modbus_tcp, tls or other_tcp.
	Class string `json:"class"`
	// Score is the share of framed units that are valid Modbus ADUs, in
	// the better direction (0..1).
	Score       float64   `json:"score"`
	ADUs        [2]uint64 `json:"adus"`
	MaxRun      [2]uint64 `json:"max_run"` // longest run of consecutive valid ADUs
	Foreign     uint64    `json:"foreign_protocol"`
	Resyncs     uint64    `json:"resyncs"`
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
