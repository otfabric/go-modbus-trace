// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

const eventSchema = "../docs/schema/event-1.schema.json"

func loadSchema(t *testing.T) (*jsonschema.Schema, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(eventSchema)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("event.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("event.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return s, m
}

// TestEventsValidate: the events of varied traces validate against the
// published schema (L22).
func TestEventsValidate(t *testing.T) {
	s, _ := loadSchema(t)
	traces := map[string][]byte{}
	traces["random"], _, _ = randomScript(t, 3)
	traces["faults"], _ = build(t, tracetest.Options{Format: tracetest.PcapNG,
		Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet}, {Link: tracetest.Raw}}}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, rd3)
		c.Response(1, 1, tracetest.Exception(3, 2))
		c.Request(2, 0, rd3)
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Snap: 4}, tracetest.Frame{TID: 9, Unit: 1, PDU: resp3(9)})
		f := tracetest.MBAP(3, 1, rd3)
		f[3] = 5
		c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: f})
		c.Request(4, 1, []byte{43, 14, 1, 0})
		c.Response(4, 1, []byte{43, 14, 1, 1, 0, 0, 1, 0, 2, 'O', 'K'})
		c.Request(5, 1, []byte{0x41})
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 5, Unit: 1, PDU: []byte{0x41, 1}})
		c.Request(6, 1, tracetest.ReadRequest(3, 0, 2))
		c.Response(6, 1, resp3(1))
		c.Close()
		m := b.Conn(tracetest.ConnOptions{Midstream: true, Server: server6, Client: client6})
		m.Response(7, 1, resp3(7))
		b.InterfaceDrops(0, 3)
		b.UDP(0, client, server, []byte("x"))
	})
	for _, bad := range []string{
		`{"kind":"txn","seq":1}`,
		`{"kind":"gap","seq":1,"gap":{"conn":1,"dir":"c2s","pos":0,"bytes":3,"reason":"loss","extra":1}}`,
		`{"kind":"txn","seq":1,"txn":{"seq":1,"conn":1,"client":"a","server":"b","unit":1,"tid":1,"function":3,"class":"read","status":"fine","summary":""}}`,
	} {
		v, _ := jsonschema.UnmarshalJSON(strings.NewReader(bad))
		if s.Validate(v) == nil {
			t.Errorf("the schema accepts %s", bad)
		}
	}
	for name, data := range traces {
		_, evs := analyze(t, data, Options{})
		for _, e := range evs {
			b, _ := json.Marshal(e)
			v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate(v); err != nil {
				t.Fatalf("%s: event %s does not validate: %v", name, b, err)
			}
		}
	}
}

// TestSchemaCoversModel: every JSON field of the model types is in the
// schema, so a change of model that is not made in the schema fails.
func TestSchemaCoversModel(t *testing.T) {
	_, doc := loadSchema(t)
	defs := doc["$defs"].(map[string]any)
	props := func(def string) map[string]any {
		if def == "" {
			return doc["properties"].(map[string]any)
		}
		return defs[def].(map[string]any)["properties"].(map[string]any)
	}
	for def, typ := range map[string]reflect.Type{
		"":            reflect.TypeOf(model.Event{}),
		"connection":  reflect.TypeOf(model.Connection{}),
		"transaction": reflect.TypeOf(model.Transaction{}),
		"adu":         reflect.TypeOf(model.ADU{}),
		"frame_ref":   reflect.TypeOf(model.FrameRef{}),
		"gap":         reflect.TypeOf(model.Gap{}),
		"resync":      reflect.TypeOf(model.Resync{}),
		"note":        reflect.TypeOf(model.Note{}),
		"view":        reflect.TypeOf(mbtcp.View{}),
		"field":       reflect.TypeOf(mbtcp.Field{}),
		"range":       reflect.TypeOf(mbtcp.Range{}),
	} {
		p := props(def)
		var names []string
		for i := 0; i < typ.NumField(); i++ {
			tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			if tag == "" || tag == "-" {
				t.Errorf("%s.%s has no JSON name", typ.Name(), typ.Field(i).Name)
				continue
			}
			names = append(names, tag)
			if _, ok := p[tag]; !ok {
				t.Errorf("schema %q lacks %s (%s.%s)", def, tag, typ.Name(), typ.Field(i).Name)
			}
		}
		if len(names) != len(p) {
			sort.Strings(names)
			t.Errorf("schema %q has %d properties, %s has %d: %v", def, len(p), typ.Name(), len(names), names)
		}
	}
}
