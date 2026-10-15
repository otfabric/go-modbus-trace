// SPDX-License-Identifier: MIT

package trace

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/otfabric/go-modbus-trace/internal/pcapio"
	"github.com/otfabric/go-modbus-trace/model"
)

// ErrNotSeekable reports random access to a gzip file or a stream: an
// application that needs it decompresses the trace to a file first.
var ErrNotSeekable = pcapio.ErrNotSeekable

// ErrFrameRef is wrapped by the error Frames returns for a reference to an
// input file this File does not have (a reference from another trace).
var ErrFrameRef = errors.New("trace: frame reference to a file not in this trace")

// Frame is one packet read back by reference.
type Frame struct {
	Ref      model.FrameRef // the reference it was read by
	LinkType uint16         // LINKTYPE_ value of its interface
	TimeNS   int64          // packet time, nanoseconds since 1970
	OrigLen  uint32         // length on the wire; more than len(Data) when the snap length cut it
	Data     []byte         // the captured packet
	Payload  []byte         // the ADU bytes this packet carried; nil after IP reassembly
}

type frameIndex struct {
	once sync.Once
	ix   *pcapio.Index
	err  error
}

// Frames re-reads the referenced packets of uncompressed trace files by
// their offsets, so an application can show raw bytes without keeping
// them. It is safe for concurrent use.
func (f *File) Frames(refs []model.FrameRef) ([]Frame, error) {
	for _, p := range f.parts {
		if p.stream != nil {
			return nil, ErrNotSeekable
		}
	}
	out := make([]Frame, 0, len(refs))
	for _, r := range refs {
		if int(r.Part) >= len(f.parts) {
			return out, fmt.Errorf("%w: frame %d of input %d", ErrFrameRef, r.Frame, r.Part)
		}
		fr, err := f.parts[r.Part].frame(r)
		if err != nil {
			return out, err
		}
		out = append(out, fr)
	}
	return out, nil
}

func (p *part) frame(r model.FrameRef) (Frame, error) {
	if p.stream != nil {
		return Frame{}, ErrNotSeekable
	}
	fh, err := os.Open(p.path)
	if err != nil {
		return Frame{}, err
	}
	defer func() { _ = fh.Close() }()
	p.index.once.Do(func() {
		fi, err := fh.Stat()
		if err != nil {
			p.index.err = err
			return
		}
		p.index.ix, p.index.err = pcapio.NewIndex(fh, fi.Size())
	})
	if errors.Is(p.index.err, pcapio.ErrNotSeekable) {
		return Frame{}, ErrNotSeekable
	}
	if p.index.err != nil {
		return Frame{}, p.index.err
	}
	pk, err := p.index.ix.ReadAt(fh, r.Offset)
	if err != nil {
		return Frame{}, fmt.Errorf("frame %d: %w", r.Frame, err)
	}
	fr := Frame{Ref: r, LinkType: pk.LinkType, TimeNS: pk.TimeNS, OrigLen: pk.OrigLen, Data: pk.Data}
	if r.PayOff >= 0 && int(r.PayOff)+int(r.PayLen) <= len(pk.Data) {
		fr.Payload = pk.Data[r.PayOff : r.PayOff+r.PayLen]
	}
	return fr, nil
}
