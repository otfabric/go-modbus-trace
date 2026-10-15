// SPDX-License-Identifier: MIT

// Package model holds the events go-modbus-trace produces: connections,
// transactions with their ADUs and provenance, gaps, resyncs and notes. The
// types have JSON tags; docs/schema/event-1.schema.json describes their JSON
// form and a test keeps the two in step.
package model

import (
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
)

// EventSemanticsVersion changes whenever the meaning of events changes, so
// an application can invalidate what it cached from earlier events.
const EventSemanticsVersion = 1

// SchemaVersion is the version of the events' JSON form.
const SchemaVersion = 1

// Hex is raw bytes, written as lowercase hex in JSON.
type Hex []byte

// MarshalText implements encoding.TextMarshaler.
func (h Hex) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h)), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hex) UnmarshalText(b []byte) error {
	x, err := hex.DecodeString(string(b))
	*h = x
	return err
}

// FrameRef points at the packet that carried part of an ADU.
type FrameRef struct {
	Part   uint16     `json:"part,omitempty"` // index of the input file, when there are several
	Frame  uint64     `json:"frame"`          // 1-based within its file, as Wireshark numbers frames
	Offset int64      `json:"offset"`         // record or block start in the (decompressed) file
	Iface  uint32     `json:"interface"`
	Time   *time.Time `json:"time,omitempty"` // absent for a packet without timestamp
	PayOff int32      `json:"payload_offset"` // of these bytes in the packet; -1 after IP reassembly
	PayLen int32      `json:"payload_length"` // bytes of the ADU in this packet
}

// Connection is a TCP connection epoch. Directions are client to server
// (index 0) and server to client (index 1); when the role is unknown,
// Client and Server are the endpoints as first seen.
type Connection struct {
	ID             uint32         `json:"id"`
	Client         netip.AddrPort `json:"client"`
	Server         netip.AddrPort `json:"server"`
	RoleSource     string         `json:"role_source"` // override, syn, port, structure, unknown
	RoleConfidence float64        `json:"role_confidence"`
	Open           string         `json:"open"`            // syn, midstream
	Close          string         `json:"close,omitempty"` // fin, rst, end_of_trace, evicted, superseded (on conn.close)
	First          *time.Time     `json:"first,omitempty"`
	Last           *time.Time     `json:"last,omitempty"`
	Iface          uint32         `json:"interface"`
	MultiIface     bool           `json:"multiple_interfaces,omitempty"`
	Packets        [2]uint64      `json:"packets"`
	Bytes          [2]uint64      `json:"bytes"`
	Transactions   uint64         `json:"transactions"`
}

// ADU is one Modbus/TCP ADU of a transaction.
type ADU struct {
	TID   uint16      `json:"tid"`
	Unit  uint8       `json:"unit"`
	PDU   Hex         `json:"pdu,omitempty"` // omitted with Options.OmitPDU; recoverable through Refs
	Size  int         `json:"size"`          // bytes on the wire, header included
	View  *mbtcp.View `json:"view,omitempty"`
	Refs  []FrameRef  `json:"refs"`
	First *time.Time  `json:"first,omitempty"` // first and last packet times
	Last  *time.Time  `json:"last,omitempty"`
	Flags []string    `json:"flags,omitempty"` // ADU-level quality flags
}

// Transaction is a request with its response, or one of them alone.
type Transaction struct {
	Seq       uint64         `json:"seq"` // order of determination
	Conn      uint32         `json:"conn"`
	Client    netip.AddrPort `json:"client"`
	Server    netip.AddrPort `json:"server"`
	Unit      uint8          `json:"unit"`
	TID       uint16         `json:"tid"`
	Function  uint8          `json:"function"`
	Sub       *uint16        `json:"sub,omitempty"` // FC08 sub-function, FC43 MEI type
	Class     string         `json:"class"`         // read, write, other
	Ranges    []mbtcp.Range  `json:"ranges,omitempty"`
	Request   *ADU           `json:"request,omitempty"`
	Response  *ADU           `json:"response,omitempty"`
	Status    string         `json:"status"`
	Exception uint8          `json:"exception,omitempty"`
	LatencyNS int64          `json:"latency_ns,omitempty"` // request last byte to response first byte
	Flags     []string       `json:"flags,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
	Summary   string         `json:"summary"`
}

// Time returns the transaction's time: the request's first packet, or the
// response's for an orphan response.
func (t *Transaction) Time() *time.Time {
	if t.Request != nil && t.Request.First != nil {
		return t.Request.First
	}
	if t.Response != nil {
		return t.Response.First
	}
	return nil
}

// Transaction statuses.
const (
	StatusOK         = "ok"
	StatusException  = "exception"
	StatusUnanswered = "unanswered"      // no response before the connection ended, the trace ended, or the request was pushed out
	StatusOrphan     = "orphan_response" // no outstanding request: midstream start or a lost request
	StatusAmbiguous  = "ambiguous"       // several outstanding requests with the same key and different PDUs
	StatusMalformed  = "malformed"       // empty, cut by the snap length, or a foreign protocol: reported alone
	StatusUncertain  = "uncertain"       // touched by a gap or a resync, or the roles are unknown
)

// Quality flags.
const (
	FlagRetransmitted = "retransmitted"
	FlagOutOfOrder    = "out_of_order"
	FlagGapAdjacent   = "gap_adjacent"
	FlagResynced      = "resynced"
	FlagSnaplen       = "snaplen_truncated"
	FlagMidstream     = "midstream"
	FlagRoleGuessed   = "role_guessed"
	FlagRoleUnknown   = "role_unknown"
	FlagRetried       = "retried"
	FlagClockOrder    = "clock_order"
	FlagSlow          = "slow"
	FlagInvalidPDU    = "invalid_pdu"
	FlagSerialOverTCP = "serial_function_over_tcp"
	FlagUnknownFunc   = "unknown_function"
	FlagBroadcast     = "broadcast"
	FlagForeign       = "foreign_protocol"
)

// Gap is a hole in a direction's byte stream.
type Gap struct {
	Conn   uint32 `json:"conn"`
	Dir    string `json:"dir"` // c2s, s2c
	Pos    uint64 `json:"pos"` // stream position
	Bytes  int64  `json:"bytes"`
	Reason string `json:"reason"` // loss, snaplen, reassembly_overflow, reassembly_budget, resync_failed, incomplete
}

// Resync is a framing resynchronisation.
type Resync struct {
	Conn       uint32 `json:"conn"`
	Dir        string `json:"dir"`
	Pos        uint64 `json:"pos"`
	Skipped    int    `json:"skipped"`
	Confidence string `json:"confidence"` // next_header, run_end
}

// Note is a fact about the trace as a whole.
type Note struct {
	Code  string  `json:"code"` // capture_drops, snaplen, unsupported, damaged_file, internal_error
	Iface *uint32 `json:"interface,omitempty"`
	Count uint64  `json:"count,omitempty"`
	Text  string  `json:"text"`
}

// Event kinds.
const (
	KindConnOpen  = "conn.open"
	KindConnClose = "conn.close"
	KindTxn       = "txn"
	KindGap       = "gap"
	KindResync    = "resync"
	KindNote      = "trace.note"
)

// Event is one event; exactly one payload is set.
type Event struct {
	Kind   string       `json:"kind"`
	Seq    uint64       `json:"seq"`
	Time   *time.Time   `json:"time,omitempty"`
	Conn   *Connection  `json:"conn,omitempty"`
	Txn    *Transaction `json:"txn,omitempty"`
	Gap    *Gap         `json:"gap,omitempty"`
	Resync *Resync      `json:"resync,omitempty"`
	Note   *Note        `json:"note,omitempty"`
}
