// SPDX-License-Identifier: MIT

// Package schemagen writes a JSON Schema (draft 2020-12) for the JSON form
// of a Go value's type, as encoding/json writes it: struct fields by their
// json tags (omitempty fields are optional, the others required), no
// additional properties, named structs under $defs.
package schemagen

import (
	"encoding"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"
)

var (
	timeType      = reflect.TypeOf(time.Time{})
	addrPortType  = reflect.TypeOf(netip.AddrPort{})
	addrType      = reflect.TypeOf(netip.Addr{})
	textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

type gen struct {
	defs map[string]any
}

// Generate returns the schema of v's type, indented, with a final newline.
// A type it cannot map (a channel, a function) is an error.
func Generate(id, title, description string, v any) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	g := &gen{defs: map[string]any{}}
	root := g.schema(reflect.TypeOf(v), false)
	s := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": id, "title": title, "description": description}
	for k, x := range root {
		s[k] = x
	}
	if len(g.defs) > 0 {
		s["$defs"] = g.defs
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func defName(t reflect.Type) string {
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	return pkg + "." + t.Name()
}

// schema returns the schema of t; nullable allows null (a nil pointer,
// slice or map that is not omitted).
func (g *gen) schema(t reflect.Type, nullable bool) map[string]any {
	orNull := func(m map[string]any) map[string]any {
		if !nullable {
			return m
		}
		return map[string]any{"anyOf": []any{m, map[string]any{"type": "null"}}}
	}
	switch t {
	case timeType:
		return orNull(map[string]any{"type": "string", "format": "date-time"})
	case addrPortType:
		return orNull(map[string]any{"type": "string", "description": "ip:port, IPv6 in brackets"})
	case addrType:
		return orNull(map[string]any{"type": "string", "description": "IP address"})
	}
	k := t.Kind()
	if k == reflect.Pointer {
		return g.schema(t.Elem(), nullable)
	}
	if k == reflect.Struct {
		name := defName(t)
		if _, ok := g.defs[name]; !ok {
			g.defs[name] = map[string]any{} // placeholder: recursion
			g.defs[name] = g.object(t)
		}
		return orNull(map[string]any{"$ref": "#/$defs/" + name})
	}
	if t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler) {
		return orNull(map[string]any{"type": "string"})
	}
	switch k { //nolint:exhaustive // the kinds encoding/json writes; the rest panic below
	case reflect.Bool:
		return orNull(map[string]any{"type": "boolean"})
	case reflect.String:
		return orNull(map[string]any{"type": "string"})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return orNull(map[string]any{"type": "integer"})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return orNull(map[string]any{"type": "integer", "minimum": 0})
	case reflect.Float32, reflect.Float64:
		return orNull(map[string]any{"type": "number"})
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return orNull(map[string]any{"type": "string", "description": "base64"})
		}
		return orNull(map[string]any{"type": "array", "items": g.schema(t.Elem(), false)})
	case reflect.Array:
		return map[string]any{"type": "array", "items": g.schema(t.Elem(), false), "minItems": t.Len(), "maxItems": t.Len()}
	case reflect.Map:
		return orNull(map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem(), false)})
	case reflect.Interface:
		return map[string]any{}
	}
	panic(fmt.Sprintf("schemagen: unsupported type %s", t))
}

func (g *gen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var req []string
	g.fields(t, props, &req)
	sort.Strings(req)
	m := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	if len(req) > 0 {
		m["required"] = req
	}
	return m
}

func (g *gen) fields(t reflect.Type, props map[string]any, req *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				g.fields(ft, props, req)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		omit := strings.Contains(opts, "omitempty")
		k := f.Type.Kind()
		nullable := !omit && (k == reflect.Slice || k == reflect.Map || k == reflect.Pointer)
		props[name] = g.schema(f.Type, nullable)
		if !omit {
			*req = append(*req, name)
		}
	}
}
