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
var ErrNotSeekable = errors.New("trace: random access needs an uncompressed trace file")

// Frame is one packet read back by reference.
type Frame struct {
	Ref      model.FrameRef
	LinkType uint16
	TimeNS   int64
	OrigLen  uint32
	Data     []byte // the captured packet
	Payload  []byte // the ADU bytes this packet carried; nil after IP reassembly
}

type frameIndex struct {
	once sync.Once
	ix   *pcapio.Index
	err  error
}

// Frames re-reads the referenced packets of an uncompressed trace file by
// their offsets, so an application can show raw bytes without keeping
// them. It is safe for concurrent use.
func (f *File) Frames(refs []model.FrameRef) ([]Frame, error) {
	if f.stream != nil {
		return nil, ErrNotSeekable
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	f.index.once.Do(func() {
		fi, err := fh.Stat()
		if err != nil {
			f.index.err = err
			return
		}
		f.index.ix, f.index.err = pcapio.NewIndex(fh, fi.Size())
	})
	if errors.Is(f.index.err, pcapio.ErrNotSeekable) {
		return nil, ErrNotSeekable
	}
	if f.index.err != nil {
		return nil, f.index.err
	}
	out := make([]Frame, 0, len(refs))
	for _, r := range refs {
		p, err := f.index.ix.ReadAt(fh, r.Offset)
		if err != nil {
			return out, fmt.Errorf("frame %d: %w", r.Frame, err)
		}
		fr := Frame{Ref: r, LinkType: p.LinkType, TimeNS: p.TimeNS, OrigLen: p.OrigLen, Data: p.Data}
		if r.PayOff >= 0 && int(r.PayOff)+int(r.PayLen) <= len(p.Data) {
			fr.Payload = p.Data[r.PayOff : r.PayOff+r.PayLen]
		}
		out = append(out, fr)
	}
	return out, nil
}
