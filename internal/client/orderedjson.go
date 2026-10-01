// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// object is a JSON object that keeps its keys in the order they were read
// or added. A managed settings file this edits must differ only in what it
// changes: re-sorting the operator's keys would turn every first install
// into a rewrite of the whole file.
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

func (o *object) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *object) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *object) empty() bool { return len(o.keys) == 0 }

// child returns the object at k, creating it when absent. A value of another
// type there is an error: the operator's file is not rewritten into a shape
// it did not have.
func (o *object) child(k string) (*object, error) {
	v, ok := o.vals[k]
	if !ok {
		c := newObject()
		o.set(k, c)
		return c, nil
	}
	c, isObj := v.(*object)
	if !isObj {
		return nil, fmt.Errorf("%s is not an object", k)
	}
	return c, nil
}

// parseObject reads one JSON object, keeping key order and number text.
func parseObject(text []byte) (*object, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	o, ok := v.(*object)
	if !ok {
		return nil, errNotObject
	}
	return o, nil
}

var errNotObject = errors.New("does not hold a JSON object")

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := newObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				o.set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			list := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return list, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return tok, nil
	}
}

// marshal writes v indented by two spaces, the layout install.sh's
// json.dumps(indent=2, ensure_ascii=False) writes, so a file either tool
// wrote reads the same to the other.
func marshal(v any) []byte {
	var b bytes.Buffer
	writeValue(&b, v, 0)
	return b.Bytes()
}

func writeValue(b *bytes.Buffer, v any, depth int) {
	pad := strings.Repeat("  ", depth+1)
	switch t := v.(type) {
	case *object:
		if t.empty() {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range t.keys {
			b.WriteString(pad)
			writeString(b, k)
			b.WriteString(": ")
			writeValue(b, t.vals[k], depth+1)
			if i < len(t.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteByte('}')
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range t {
			b.WriteString(pad)
			writeValue(b, e, depth+1)
			if i < len(t)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteByte(']')
	case string:
		writeString(b, t)
	case json.Number:
		b.WriteString(t.String())
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	default:
		// Every value here came from parseValue or from this package's own
		// literals, so this is unreachable; encode it plainly regardless.
		enc, err := json.Marshal(t)
		if err != nil {
			b.WriteString("null")
			return
		}
		b.Write(enc)
	}
}

// writeString encodes s without HTML escaping, so "<", ">" and "&" in an
// operator's value are written as themselves, as json.dumps writes them.
func writeString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		b.WriteString(`""`)
		return
	}
	b.Write(bytes.TrimSuffix(tmp.Bytes(), []byte("\n")))
}
