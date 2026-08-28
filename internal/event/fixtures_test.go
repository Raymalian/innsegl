// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixtureDir holds the golden vectors. They are immutable once merged (doc 02
// §7): a failing fixture test means the serializer changed, and the serializer
// is what must be reverted.
const fixtureDir = "testdata/fixtures/v1"

// goldenFixture is one committed vector: the event object without event_hash,
// the exact canonical bytes it must serialize to, and the resulting event_hash.
type goldenFixture struct {
	name      string
	input     Fields
	canonical []byte
	hash      string
}

// loadFixture reads one vector.
//
// It deliberately does NOT use ParseFields: a fixture decoded by the code under
// test would only ever prove the code agrees with itself. Decoding here is
// plain encoding/json with UseNumber, and integers are converted explicitly.
func loadFixture(t *testing.T, name string) goldenFixture {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(fixtureDir, name+".input.json"))
	if err != nil {
		t.Fatalf("read fixture input: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if derr := dec.Decode(&m); derr != nil {
		t.Fatalf("%s: decode input: %v", name, derr)
	}

	f := make(Fields, len(m))
	for k, v := range m {
		if n, ok := v.(json.Number); ok {
			i, ierr := n.Int64()
			if ierr != nil {
				t.Fatalf("%s: member %q is not an integer: %v", name, k, ierr)
			}
			f[k] = i
			continue
		}
		f[k] = v
	}

	canonical, err := os.ReadFile(filepath.Join(fixtureDir, name+".canonical.json"))
	if err != nil {
		t.Fatalf("read fixture canonical bytes: %v", err)
	}
	hash, err := os.ReadFile(filepath.Join(fixtureDir, name+".hash"))
	if err != nil {
		t.Fatalf("read fixture hash: %v", err)
	}

	return goldenFixture{
		name:      name,
		input:     f,
		canonical: canonical,
		hash:      string(hash),
	}
}

// fixtureNames returns every committed vector, in sorted order.
func fixtureNames(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("read fixture dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".input.json") {
			names = append(names, strings.TrimSuffix(n, ".input.json"))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("no fixtures in %s", fixtureDir)
	}
	return names
}

// fixtureString reads a string member out of a fixture, failing the test
// rather than panicking if the fixture has drifted.
func fixtureString(t *testing.T, f Fields, name string) string {
	t.Helper()
	v, ok := f[name].(string)
	if !ok {
		t.Fatalf("fixture member %q is %T, want string", name, f[name])
	}
	return v
}

// fixtureInt reads an integer member out of a fixture.
func fixtureInt(t *testing.T, f Fields, name string) int64 {
	t.Helper()
	v, ok := f[name].(int64)
	if !ok {
		t.Fatalf("fixture member %q is %T, want int64", name, f[name])
	}
	return v
}

// readFixtureFile returns the exact bytes of a fixture file.
func readFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}
