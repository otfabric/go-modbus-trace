// SPDX-License-Identifier: MIT

// Package mbcapexport turns the transactions of a passive trace into an
// MBCAP capture that modbusctl can replay as a virtual device
// (docs/MBCAP-EXPORT.md). Only matched, valid reads are written, through
// go-modbus-capture's own writers; every transaction left out is counted
// under a stable reason code.
package mbcapexport

import (
	"slices"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

// Reason says why a transaction is not written. Admit is the empty reason.
type Reason string

// Reasons (stable codes, MBCAP-EXPORT.md section 3).
const (
	Admit               Reason = ""
	RoleUnknown         Reason = "role_unknown"
	Malformed           Reason = "malformed"
	WriteFunction       Reason = "write_function"
	FC23                Reason = "fc23"
	UnsupportedFunction Reason = "unsupported_function"
	FC08StateChanging   Reason = "fc08_state_changing"
	MEINot14            Reason = "mei_not_14"
	Unanswered          Reason = "unanswered"
	OrphanResponse      Reason = "orphan_response"
	AmbiguousPair       Reason = "ambiguous_pair"
	Uncertain           Reason = "uncertain"
	SnaplenTruncated    Reason = "snaplen_truncated"
	Resynced            Reason = "resynced"
	InvalidPDU          Reason = "invalid_pdu"
	ResponseMismatch    Reason = "response_mismatch"
	ClockOrder          Reason = "clock_order"
	ExceptionsDisabled  Reason = "exceptions_disabled"
	NotSelected         Reason = "not_selected"
	OutsideWindow       Reason = "outside_window"
)

// Reasons lists every reason code, in report order.
var Reasons = []Reason{RoleUnknown, Malformed, WriteFunction, FC23, UnsupportedFunction, FC08StateChanging, MEINot14,
	Unanswered, OrphanResponse, AmbiguousPair, Uncertain, SnaplenTruncated, Resynced, InvalidPDU, ResponseMismatch,
	ClockOrder, ExceptionsDisabled, NotSelected, OutsideWindow}

// readFunctions are the functions a capture holds (FC08 and FC43 depend on
// the sub-function and MEI type).
var readFunctions = map[uint8]bool{1: true, 2: true, 3: true, 4: true, 7: true, 8: true, 11: true, 12: true, 17: true,
	20: true, 24: true, 43: true}

var writeFunctions = map[uint8]bool{5: true, 6: true, 15: true, 16: true, 21: true, 22: true}

// Classify decides whether a transaction belongs in an MBCAP capture. It
// looks at the transaction only (not at a selection, a time window or the
// exceptions option), so an application can store and preview the
// decision; the exporter uses exactly this function.
func Classify(t *model.Transaction) Reason {
	has := func(f string) bool { return slices.Contains(t.Flags, f) }
	switch {
	case has(model.FlagRoleUnknown):
		return RoleUnknown
	case t.Status == model.StatusMalformed:
		return Malformed
	}
	switch fc := t.Function; {
	case fc == 23:
		return FC23
	case writeFunctions[fc]:
		return WriteFunction
	case !readFunctions[fc]:
		return UnsupportedFunction
	case fc == 8 && (t.Sub == nil || !mbtcp.DiagnosticsAdmissible(*t.Sub)):
		return FC08StateChanging
	case fc == 43 && (t.Sub == nil || *t.Sub != mbtcp.MEIDeviceID):
		return MEINot14
	}
	switch t.Status {
	case model.StatusUnanswered:
		return Unanswered
	case model.StatusOrphan:
		return OrphanResponse
	case model.StatusAmbiguous:
		return AmbiguousPair
	case model.StatusUncertain:
		return Uncertain
	case model.StatusOK, model.StatusException:
	default:
		return Malformed
	}
	if t.Request == nil || t.Response == nil || len(t.Request.PDU) == 0 || len(t.Response.PDU) == 0 {
		return Malformed // PDUs omitted (Options.OmitPDU) or missing: nothing to write
	}
	switch {
	case has(model.FlagSnaplen):
		return SnaplenTruncated
	case has(model.FlagResynced):
		return Resynced
	case has(model.FlagClockOrder):
		return ClockOrder
	case slices.Contains(t.Warnings, mbtcp.WarnMismatch):
		return ResponseMismatch
	case has(model.FlagInvalidPDU):
		return InvalidPDU
	}
	if t.Status == model.StatusOK && t.Function <= 4 && !splits(t.Request.PDU, t.Response.PDU) {
		return ResponseMismatch
	}
	return Admit
}

// splits mirrors capture.SplitAddresses: an FC01-04 response must hold
// exactly the requested quantity, without wrapping the address space.
func splits(req, resp []byte) bool {
	if len(req) != 5 || len(resp) < 2 || resp[0] != req[0] {
		return false
	}
	start := uint32(req[1])<<8 | uint32(req[2])
	q := uint32(req[3])<<8 | uint32(req[4])
	if q == 0 || start+q-1 > 0xFFFF {
		return false
	}
	n := 2 * q
	if req[0] <= 2 {
		n = (q + 7) / 8
	}
	return int(resp[1]) == int(n) && len(resp) == 2+int(n)
}
