// SPDX-License-Identifier: MIT

package mbtcp

import (
	"encoding/binary"
	"net/netip"
)

// RoleSource says how the server of a connection was decided.
type RoleSource uint8

// Role sources, strongest first.
const (
	RoleUnknown   RoleSource = iota // undecidable: not exported
	RoleOverride                    // the user named the server or the client
	RoleSYN                         // the sender of the first SYN is the client
	RolePort                        // exactly one endpoint uses a configured server port
	RoleStructure                   // requests parse as requests and responses pair with them
)

func (r RoleSource) String() string {
	return [...]string{"unknown", "override", "syn", "port", "structure"}[r]
}

// Guessed reports a role taken from a port without a handshake, or from
// structure (the role_guessed flag).
func (r RoleSource) Guessed(sawSYN bool) bool {
	return r == RoleStructure || (r == RolePort && !sawSYN)
}

// Sample is the start of an ADU kept for the structure test.
type Sample struct {
	Order uint32 // position over both directions, in delivery order
	TID   uint16
	Unit  uint8
	Len   uint16   // PDU length
	Head  [10]byte // the first PDU bytes (enough for every shape rule)
}

// NewSample keeps the start of a PDU.
func NewSample(order uint32, tid uint16, unit uint8, pdu []byte) Sample {
	s := Sample{Order: order, TID: tid, Unit: unit, Len: uint16(len(pdu))}
	copy(s.Head[:], pdu)
	return s
}

// MaxSamples is the number of ADUs per direction the structure test uses.
const MaxSamples = 20

// RoleInput is what the role decision uses.
type RoleInput struct {
	Endpoints   [2]netip.AddrPort // the senders of direction 0 and 1
	SYNFrom     int               // direction of the first SYN without ACK, -1 if none
	SYNACKFrom  int               // direction of the first SYN+ACK, -1 if none
	ServerPorts []uint16
	Servers     []netip.AddrPort // a zero port matches any port
	Clients     []netip.AddrPort
	Samples     [2][]Sample
}

// Role is a decision.
type Role struct {
	Server     int // direction whose sender is the server; -1 if unknown
	Source     RoleSource
	Confidence float64
}

func match(list []netip.AddrPort, e netip.AddrPort) bool {
	for _, x := range list {
		if x.Addr() == e.Addr() && (x.Port() == 0 || x.Port() == e.Port()) {
			return true
		}
	}
	return false
}

// DecideRole decides which endpoint is the server, in the documented order.
func DecideRole(in RoleInput) Role {
	for d := range 2 {
		if match(in.Servers, in.Endpoints[d]) && !match(in.Servers, in.Endpoints[1-d]) {
			return Role{Server: d, Source: RoleOverride, Confidence: 1}
		}
		if match(in.Clients, in.Endpoints[d]) && !match(in.Clients, in.Endpoints[1-d]) {
			return Role{Server: 1 - d, Source: RoleOverride, Confidence: 1}
		}
	}
	if in.SYNFrom >= 0 {
		return Role{Server: 1 - in.SYNFrom, Source: RoleSYN, Confidence: 1}
	}
	if in.SYNACKFrom >= 0 {
		return Role{Server: in.SYNACKFrom, Source: RoleSYN, Confidence: 1}
	}
	p0, p1 := portIn(in.ServerPorts, in.Endpoints[0].Port()), portIn(in.ServerPorts, in.Endpoints[1].Port())
	if p0 != p1 {
		d := 0
		if p1 {
			d = 1
		}
		return Role{Server: d, Source: RolePort, Confidence: 0.9}
	}
	a, b := structure(in.Samples, 0), structure(in.Samples, 1) // a: direction 0 sends requests
	switch {
	case a >= 0.8 && a-b >= 0.2:
		return Role{Server: 1, Source: RoleStructure, Confidence: a}
	case b >= 0.8 && b-a >= 0.2:
		return Role{Server: 0, Source: RoleStructure, Confidence: b}
	}
	return Role{Server: -1, Source: RoleUnknown}
}

func portIn(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// structure scores the orientation in which direction req sends requests:
// the mean of the share of ADUs that have the shape of their assumed role
// and the share of responses that pair with an earlier request.
func structure(s [2][]Sample, req int) float64 {
	reqs, resps := s[req], s[1-req]
	n := len(reqs) + len(resps)
	if n == 0 || len(resps) == 0 {
		return 0
	}
	shaped := 0
	for i := range reqs {
		if RequestShape(&reqs[i]) {
			shaped++
		}
	}
	for i := range resps {
		if ResponseShape(&resps[i]) {
			shaped++
		}
	}
	paired := 0
	for _, r := range resps {
		for _, q := range reqs {
			if q.Order < r.Order && q.TID == r.TID && q.Unit == r.Unit && (q.Head[0] == r.Head[0] || q.Head[0]|0x80 == r.Head[0]) {
				paired++
				break
			}
		}
	}
	return (float64(shaped)/float64(n) + float64(paired)/float64(len(resps))) / 2
}

func u16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

// RequestShape reports whether a PDU has the size and fields of a request
// of its function. Unknown functions do not.
func RequestShape(s *Sample) bool {
	h, n := s.Head[:], int(s.Len)
	if n == 0 {
		return false
	}
	switch fc := h[0]; fc {
	case 1, 2:
		return n == 5 && u16(h[3:]) >= 1 && u16(h[3:]) <= 2000
	case 3, 4:
		return n == 5 && u16(h[3:]) >= 1 && u16(h[3:]) <= 125
	case 5:
		return n == 5 && (u16(h[3:]) == 0xFF00 || u16(h[3:]) == 0)
	case 6:
		return n == 5
	case 7, 11, 12, 17:
		return n == 1
	case 8:
		return n >= 3
	case 15:
		q := u16(h[3:])
		return n >= 6 && q >= 1 && q <= 1968 && int(h[5]) == (q+7)/8 && n == 6+int(h[5])
	case 16:
		q := u16(h[3:])
		return n >= 6 && q >= 1 && q <= 123 && int(h[5]) == 2*q && n == 6+int(h[5])
	case 20, 21:
		return n >= 2 && n == 2+int(h[1])
	case 22:
		return n == 7
	case 23:
		return n >= 10 && n == 10+int(h[9])
	case 24:
		return n == 3
	case 43:
		return n >= 2 && (h[1] == 13 || h[1] == 14)
	default:
		return false
	}
}

// ResponseShape reports whether a PDU has the size and fields of a
// response (or exception response) of its function.
func ResponseShape(s *Sample) bool {
	h, n := s.Head[:], int(s.Len)
	if n == 0 {
		return false
	}
	fc := h[0]
	if fc&0x80 != 0 {
		return n == 2 && fc&0x7F != 0
	}
	switch fc {
	case 1, 2:
		return n >= 3 && n == 2+int(h[1])
	case 3, 4, 23:
		return n >= 4 && h[1]%2 == 0 && n == 2+int(h[1])
	case 5, 6, 15, 16:
		return n == 5
	case 7:
		return n == 2
	case 11:
		return n == 5
	case 12, 17, 20, 21:
		return n >= 2 && n == 2+int(h[1])
	case 8:
		return n >= 3
	case 22:
		return n == 7
	case 24:
		return n >= 5
	case 43:
		return n >= 2 && (h[1] == 13 || h[1] == 14)
	default:
		return false
	}
}
