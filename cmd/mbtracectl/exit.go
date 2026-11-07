// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/export/subtrace"
	"github.com/otfabric/go-modbus-trace/export/timeline"
	"github.com/otfabric/go-modbus-trace/trace"
)

// inputError marks an error in reading a trace: a file that cannot be
// opened, is not a trace or is damaged.
type inputError struct{ err error }

func (e *inputError) Error() string { return e.err.Error() }
func (e *inputError) Unwrap() error { return e.err }

// inputErr marks err, from opening or reading the traces, as an input
// error. Output and cancellation errors carried through it keep their code:
// exitCode tests them first.
func inputErr(err error) error {
	if err == nil {
		return nil
	}
	return &inputError{err}
}

// outputError marks an output that cannot be written: a closed pipe, a full
// disk, a directory that does not exist.
type outputError struct{ err error }

func (e *outputError) Error() string { return e.err.Error() }
func (e *outputError) Unwrap() error { return e.err }

func outputErr(err error) error {
	if err == nil {
		return nil
	}
	return &outputError{err}
}

// outWriter marks the write errors of an output, so that they are told from
// input errors after the library has wrapped them.
type outWriter struct{ w io.Writer }

func (o outWriter) Write(b []byte) (int, error) {
	n, err := o.w.Write(b)
	return n, outputErr(err)
}

// exitCode classifies a command's error (docs/exitcodes.md).
func exitCode(ctx context.Context, err error) int {
	var out *outputError
	var in *inputError
	switch {
	case err == nil:
		return exitOK
	case ctx.Err() != nil, errors.Is(err, context.Canceled):
		return exitInterrupted
	case errors.Is(err, errUsage), errors.Is(err, mbcapexport.ErrOptions), errors.Is(err, subtrace.ErrTransactionSelection),
		errors.Is(err, timeline.ErrUnknownFormat), strings.HasPrefix(err.Error(), "unknown command "): // cobra's
		return exitUsage
	case errors.As(err, &out), errors.Is(err, mbcapexport.ErrWriter):
		return exitInternal
	case errors.As(err, &in), errors.Is(err, trace.ErrFormat), errors.Is(err, trace.ErrCorrupt),
		errors.Is(err, trace.ErrConsumed), errors.Is(err, trace.ErrNoInput):
		return exitInvalidInput
	default:
		return exitInternal
	}
}
