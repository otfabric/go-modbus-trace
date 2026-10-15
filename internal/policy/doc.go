// SPDX-License-Identifier: MIT

// Package policy holds no code. Its tests check the module's dependency
// rules over `go list -deps`: no cgo, no network, no live capture, no
// program execution and no go-modbus outside tests (L19, L20, LA15).
package policy
