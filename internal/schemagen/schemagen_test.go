// SPDX-License-Identifier: MIT

package schemagen

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type level int

func (l level) MarshalText() ([]byte, error) { return []byte("x"), nil }

type inner struct {
	N    int    `json:"n"`
	Next *inner `json:"next,omitempty"` // recursion
}

type embedded struct {
	E string `json:"e"`
}

type doc struct {
	embedded
	B      bool              `json:"b"`
	S      string            `json:"s"`
	I      int64             `json:"i"`
	U      uint16            `json:"u"`
	F      float64           `json:"f"`
	Raw    []byte            `json:"raw"`
	List   []string          `json:"list"`
	Opt    []string          `json:"opt,omitempty"`
	Fixed  [2]uint8          `json:"fixed"`
	M      map[string]uint64 `json:"m"`
	Any    any               `json:"any"`
	T      time.Time         `json:"t"`
	TP     *time.Time        `json:"tp"`
	AP     netip.AddrPort    `json:"ap"`
	A      netip.Addr        `json:"a"`
	L      level             `json:"l"`
	In     inner             `json:"in"`
	InP    *inner            `json:"in_p"`
	NoTag  int
	Hidden int `json:"-"`
	lower  int
}

func TestGenerate(t *testing.T) {
	_ = doc{}.lower
	b, err := Generate("https://example/x.json", "X", "a test", doc{})
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != '\n' {
		t.Error("no final newline")
	}
	var s struct {
		Schema string                    `json:"$schema"`
		ID     string                    `json:"$id"`
		Ref    string                    `json:"$ref"`
		Defs   map[string]map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.ID != "https://example/x.json" || s.Ref != "#/$defs/schemagen.doc" || s.Defs["schemagen.inner"] == nil {
		t.Fatalf("schema %s", b)
	}
	d := s.Defs["schemagen.doc"]
	if d["additionalProperties"] != false {
		t.Error("additional properties allowed")
	}
	props := d["properties"].(map[string]any)
	want := map[string]any{
		"e":     map[string]any{"type": "string"},
		"b":     map[string]any{"type": "boolean"},
		"s":     map[string]any{"type": "string"},
		"i":     map[string]any{"type": "integer"},
		"u":     map[string]any{"type": "integer", "minimum": 0.0},
		"f":     map[string]any{"type": "number"},
		"raw":   anyOf(map[string]any{"type": "string", "description": "base64"}),
		"list":  anyOf(map[string]any{"type": "array", "items": map[string]any{"type": "string"}}),
		"opt":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"fixed": map[string]any{"type": "array", "items": map[string]any{"type": "integer", "minimum": 0.0}, "minItems": 2.0, "maxItems": 2.0},
		"m":     anyOf(map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer", "minimum": 0.0}}),
		"any":   map[string]any{},
		"t":     map[string]any{"type": "string", "format": "date-time"},
		"tp":    anyOf(map[string]any{"type": "string", "format": "date-time"}),
		"ap":    map[string]any{"type": "string", "description": "ip:port, IPv6 in brackets"},
		"a":     map[string]any{"type": "string", "description": "IP address"},
		"l":     map[string]any{"type": "string"},
		"in":    map[string]any{"$ref": "#/$defs/schemagen.inner"},
		"in_p":  anyOf(map[string]any{"$ref": "#/$defs/schemagen.inner"}),
		"NoTag": map[string]any{"type": "integer"},
	}
	for k, w := range want {
		if !reflect.DeepEqual(props[k], w) {
			t.Errorf("%s: %v, want %v", k, props[k], w)
		}
	}
	if len(props) != len(want) {
		t.Errorf("%d properties, want %d: %v", len(props), len(want), props)
	}
	req := d["required"].([]any)
	if len(req) != len(want)-1 { // every field but opt
		t.Errorf("required %v", req)
	}
}

func anyOf(m map[string]any) map[string]any {
	return map[string]any{"anyOf": []any{m, map[string]any{"type": "null"}}}
}

func TestUnsupported(t *testing.T) {
	if _, err := Generate("", "", "", struct {
		C chan int `json:"c"`
	}{}); err == nil {
		t.Error("a channel field gave a schema")
	}
}
