// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestGzipDamage: a gzip trace whose checksum does not match ends the pass
// with an error wrapping ErrCorrupt and the cause, the summary says so, and
// everything read before it is reported. A gzip stream that stops early is
// a cut-short tail and no error, as for a plain file.
func TestGzipDamage(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		poll(c, 1, 50)
		c.Close()
	})
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	ctx := context.Background()
	clean, _, err := Scan(ctx, OpenReader(bytes.NewReader(buf.Bytes())), ScanOptions{})
	if err != nil || clean.Error != "" || !clean.Gzip {
		t.Fatalf("intact: %v, %+v", err, clean)
	}

	bad := bytes.Clone(buf.Bytes())
	bad[len(bad)-8] ^= 0x01 // the checksum of the uncompressed data
	sum, flows, err := Scan(ctx, OpenReader(bytes.NewReader(bad)), ScanOptions{})
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("scan: %v", err)
	}
	if sum == nil || sum.Error == "" || sum.Packets != clean.Packets || len(flows) != 1 || flows[0].ADUs != [2]uint64{50, 50} || sum.Reader.TruncatedTail {
		t.Errorf("scan: summary %+v, flows %+v", sum, flows)
	}
	var ok, notes int
	sum, err = Analyze(ctx, OpenReader(bytes.NewReader(bad)), Options{}, SinkFunc(func(e *model.Event) error {
		if e.Txn != nil && e.Txn.Status == model.StatusOK {
			ok++
		}
		if e.Note != nil && e.Note.Code == "damaged_file" && e.Note.Text != "" {
			notes++
		}
		return nil
	}))
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, gzip.ErrChecksum) || sum == nil || sum.Error != err.Error() || ok != 50 || notes != 1 {
		t.Errorf("analyze: %v, summary error %q, %d transactions, %d notes", err, sum.Error, ok, notes)
	}

	cut := buf.Bytes()[:buf.Len()*2/3]
	sum, _, err = Scan(ctx, OpenReader(bytes.NewReader(cut)), ScanOptions{})
	if err != nil || sum.Error != "" || !sum.Reader.TruncatedTail || sum.Packets == 0 || sum.Packets >= clean.Packets {
		t.Errorf("a stream that stops early: %v, %d of %d packets, reader %+v", err, sum.Packets, clean.Packets, sum.Reader)
	}
}

// TestPacketTimeOutOfRange: a pcapng packet whose time does not fit in
// 64-bit nanoseconds is read without a time and counted. Its bytes are
// used; the trace's first and last time, the order of packets in time and
// the times of its ADU ignore it.
func TestPacketTimeOutOfRange(t *testing.T) {
	data, _ := build(t, tracetest.Options{Format: tracetest.PcapNG, Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet, TSResol: 9}}},
		func(b *tracetest.Builder) {
			c := b.Conn(tracetest.ConnOptions{})
			poll(c, 1, 3)
			c.Close()
		})
	clean, evs := analyze(t, data, Options{})
	ref := txns(evs)[1].Request.Refs[0]
	if ref.Time == nil || clean.Reader.BadTimestamps != 0 {
		t.Fatalf("clean trace: ref %+v, reader %+v", ref, clean.Reader)
	}
	bad := bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[ref.Offset+12:], 0xFFFFFFFF) // the upper half of the block's timestamp
	sum, evs := analyze(t, bad, Options{})
	tx := txns(evs)[1]
	if sum.Reader.BadTimestamps != 1 || sum.TimeBackwards != 0 || !sum.First.Equal(*clean.First) || !sum.Last.Equal(*clean.Last) || sum.Packets != clean.Packets {
		t.Errorf("summary: reader %+v, time backwards %d, first %v, last %v", sum.Reader, sum.TimeBackwards, sum.First, sum.Last)
	}
	if tx.Status != model.StatusOK || tx.Request.Refs[0].Time != nil || tx.Request.First != nil || tx.Request.Refs[0].Frame != ref.Frame {
		t.Errorf("the transaction of the packet: %s, request %+v", tx.Status, tx.Request)
	}
	if sum.Transactions[model.StatusOK] != 3 {
		t.Errorf("transactions %v", sum.Transactions)
	}
}
