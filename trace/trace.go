// SPDX-License-Identifier: MIT

// Package trace is the facade of go-modbus-trace: it opens a packet trace
// (pcap or pcapng, plain or gzip, from a file or a stream), finds the
// Modbus/TCP traffic in it and reports what it found.
//
// The library is offline: it never opens a socket and never captures live.
// Its only clock is the trace's timestamps, and the same input gives the
// same output.
package trace

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/otfabric/go-modbus-trace/internal/flow"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
	"github.com/otfabric/go-modbus-trace/mbtcp"
)

// Errors.
var (
	// ErrFormat reports an input that is neither pcap nor pcapng.
	ErrFormat = pcapio.ErrFormat
	// ErrCorrupt reports damage that ended the read; what was read before
	// it is reported. Damage is a record or block length that cannot be, a
	// gzip input that does not decompress as stored (its checksum or length
	// does not match, its data is damaged), a read of the input that fails,
	// and a pcapng file with more sections than Limits.MaxSections. The
	// error also wraps its cause where there is one (gzip.ErrChecksum, the
	// read error).
	ErrCorrupt = pcapio.ErrCorrupt
	// ErrConsumed reports a second pass over a stream input.
	ErrConsumed = errors.New("trace: a stream input can be read only once")
	// ErrNoInput is returned by OpenFiles without a path.
	ErrNoInput = errors.New("trace: no input")
)

// maxParts is the number of files one trace can have: FrameRef.Part, the
// index of a file, is a uint16.
const maxParts = math.MaxUint16 + 1

// File is an opened trace: one or more paths (any number of passes), or a
// stream (one). Several paths are one continuous trace, read in the order
// given: connection state carries from one file to the next (rotated
// tcpdump -C/-G files).
type File struct {
	parts []*part
}

type part struct {
	path   string
	size   int64
	stream io.Reader
	used   atomic.Bool // a stream was handed to a pass
	index  frameIndex  // for Frames
}

// Open opens a trace file by path. Nothing is read until a pass runs.
func Open(path string) (*File, error) { return OpenFiles(path) }

// OpenFiles opens several trace files that are one trace, in time order.
func OpenFiles(paths ...string) (*File, error) {
	if len(paths) == 0 {
		return nil, ErrNoInput
	}
	if len(paths) > maxParts {
		return nil, fmt.Errorf("trace: %d files, more than the %d a frame reference can name", len(paths), maxParts)
	}
	f := &File{}
	for _, path := range paths {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			return nil, fmt.Errorf("trace: %s: is a directory", path)
		}
		f.parts = append(f.parts, &part{path: path, size: fi.Size()})
	}
	return f, nil
}

// OpenReader wraps a stream (for example standard input). It can be read
// by one pass only.
func OpenReader(r io.Reader) *File { return &File{parts: []*part{{stream: r, size: -1}}} }

// Name returns the path ("-" for a stream); for several files the paths
// joined by commas.
func (f *File) Name() string {
	names := make([]string, len(f.parts))
	for i, p := range f.parts {
		names[i] = p.name()
	}
	return strings.Join(names, ",")
}

// Names returns the path of every input ("-" for a stream).
func (f *File) Names() []string {
	names := make([]string, len(f.parts))
	for i, p := range f.parts {
		names[i] = p.name()
	}
	return names
}

// Size returns the total size of the files, or -1 for a stream.
func (f *File) Size() int64 {
	var n int64
	for _, p := range f.parts {
		if p.size < 0 {
			return -1
		}
		n += p.size
	}
	return n
}

func (p *part) name() string {
	if p.stream != nil {
		return "-"
	}
	return p.path
}

func (p *part) open() (io.ReadCloser, error) {
	if p.stream != nil {
		if !p.used.CompareAndSwap(false, true) {
			return nil, ErrConsumed
		}
		return io.NopCloser(p.stream), nil
	}
	return os.Open(p.path)
}

// Limits bound memory. Zero values take the defaults. What a pass holds at
// most is the sum of the limits and the fixed state of the tracked
// connections; it does not grow with the size of the trace
// (docs/ARCHITECTURE.md section 2).
type Limits struct {
	MaxConns       int // tracked connections (100,000)
	BufferPerDir   int // out-of-order bytes per direction (1 MiB)
	BufferTotal    int // out-of-order bytes over all connections (64 MiB)
	ResyncScan     int // bytes scanned for a resync (64 KiB)
	FragmentBudget int // IP fragment bytes held (16 MiB)
	MaxPacket      int // largest captured packet read (256 KiB)
	// AnalysisBudget bounds what Analyze holds between packets over all
	// connections, in bytes (64 MiB): requests waiting for a response, ADUs
	// held while a connection's roles are undecided, and the provenance of
	// bytes being framed. Past it, the connection whose state was added to
	// least recently gives up state: its roles are decided with what there
	// is, then its oldest outstanding requests are decided unanswered and
	// uncertain, and a connection that holds only partly framed bytes is
	// closed as evicted. Counted in Quality.AnalysisBudget.
	AnalysisBudget int
	// MaxFlows bounds the flows Scan returns (1,000,000). The list is the
	// result of Scan, so it grows with the number of connections in the
	// trace, about 400 bytes each, up to this limit; the flows of
	// connections that close after it is full are counted in
	// ConnCounters.FlowsDropped and left out.
	MaxFlows int
	// MaxInterfaces bounds the interfaces kept from one input file, over
	// all its pcapng sections (65,536). An Interface Description Block past
	// it is skipped with the packets that name its interface, and counted
	// in ReaderCounters.SkippedBlocks.
	MaxInterfaces int
	// MaxSections bounds the pcapng sections read from one input file
	// (65,536). A Section Header Block past it ends the read with
	// ErrCorrupt and the results so far.
	MaxSections int
}

// The defaults of the limits that are not another package's. Each is chosen
// well above what captures hold (docs/ARCHITECTURE.md section 2 says why).
const (
	defaultFragmentBudget = 16 << 20
	defaultAnalysisBudget = 64 << 20
	defaultMaxFlows       = 1_000_000
)

// DefaultLimits are the documented defaults.
var DefaultLimits = Limits{
	MaxConns:       flow.DefaultLimits.MaxConns,
	BufferPerDir:   flow.DefaultLimits.BufferPerDir,
	BufferTotal:    flow.DefaultLimits.BufferTotal,
	ResyncScan:     mbtcp.DefaultResyncLimit,
	FragmentBudget: defaultFragmentBudget,
	MaxPacket:      pcapio.DefaultMaxPacket,
	AnalysisBudget: defaultAnalysisBudget,
	MaxFlows:       defaultMaxFlows,
	MaxInterfaces:  pcapio.DefaultMaxInterfaces,
	MaxSections:    pcapio.DefaultMaxSections,
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.MaxConns <= 0 {
		l.MaxConns = d.MaxConns
	}
	if l.BufferPerDir <= 0 {
		l.BufferPerDir = d.BufferPerDir
	}
	if l.BufferTotal <= 0 {
		l.BufferTotal = d.BufferTotal
	}
	if l.ResyncScan <= 0 {
		l.ResyncScan = d.ResyncScan
	}
	if l.FragmentBudget <= 0 {
		l.FragmentBudget = d.FragmentBudget
	}
	if l.MaxPacket <= 0 {
		l.MaxPacket = d.MaxPacket
	}
	if l.AnalysisBudget <= 0 {
		l.AnalysisBudget = d.AnalysisBudget
	}
	if l.MaxFlows <= 0 {
		l.MaxFlows = d.MaxFlows
	}
	if l.MaxInterfaces <= 0 {
		l.MaxInterfaces = d.MaxInterfaces
	}
	if l.MaxSections <= 0 {
		l.MaxSections = d.MaxSections
	}
	return l
}

// reader returns the limits of the file reader.
func (l Limits) reader() pcapio.Options {
	return pcapio.Options{MaxPacket: l.MaxPacket, MaxInterfaces: l.MaxInterfaces, MaxSections: l.MaxSections}
}

// DefaultServerPorts are the ports taken as Modbus servers by default.
var DefaultServerPorts = []uint16{502}

// ScanOptions configure Scan.
type ScanOptions struct {
	// ServerPorts are server ports for the role decision (default 502).
	ServerPorts []uint16
	// Servers and Clients override the role decision; a zero port matches
	// any port.
	Servers []netip.AddrPort
	Clients []netip.AddrPort
	// Limits bound memory; zero fields take DefaultLimits.
	Limits Limits
	// Progress, if set, is called about every 4 MiB of input with the input
	// bytes read and the total (-1 for a stream).
	Progress func(read, total int64)
}

// Version is the version exports record for this library when the build
// information has none (mbcapexport.LibraryVersion reads it from there).
const Version = "(devel)"
