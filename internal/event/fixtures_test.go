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

// The golden vectors, one directory per schema version. They are immutable
// once merged (doc 02 §7): a failing fixture test means the serializer changed,
// and the serializer is what must be reverted.
//
// # Why there is a directory per version rather than one that moves
//
// doc 08 is unconditional -- a new version is accepted ALONGSIDE all previous
// ones, and verification of old records is supported forever. The chain still
// holds every v1 event ever appended and I4 forbids rewriting them, so v1's
// bytes and hashes have to stay under test after v2 ships. A single directory
// that was regenerated at each bump would delete exactly the evidence that
// old records still verify, and would do it silently.
//
// So the two questions are asked separately and the helpers below say which is
// which at every call site:
//
//	fixtureDirV1     what the ledger already holds, frozen forever
//	currentFixtureDir()  what this build emits, which the append path requires
const fixtureDirV1 = "testdata/fixtures/v1"

// currentFixtureDir holds the vectors for the version this build emits.
// ValidateEvent refuses anything else at append, so an append-path test can
// only start from these.
func currentFixtureDir() string { return "testdata/fixtures/v" + SchemaVersion }

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
	return loadFixtureFrom(t, currentFixtureDir(), name)
}

// loadFixtureV1 reads a vector from the frozen v1 set. It is how a test says
// "this is a record the ledger already holds", which is a different claim from
// "this is what we write now" and must not silently become it.
func loadFixtureV1(t *testing.T, name string) goldenFixture {
	t.Helper()
	return loadFixtureFrom(t, fixtureDirV1, name)
}

func loadFixtureFrom(t *testing.T, fixtureDir, name string) goldenFixture {
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

// fixtureNames returns every committed vector for the version this build
// emits, in sorted order.
func fixtureNames(t *testing.T) []string {
	t.Helper()
	return fixtureNamesIn(t, currentFixtureDir())
}

// fixtureNamesV1 returns the frozen v1 set.
func fixtureNamesV1(t *testing.T) []string {
	t.Helper()
	return fixtureNamesIn(t, fixtureDirV1)
}

func fixtureNamesIn(t *testing.T, fixtureDir string) []string {
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

// readFixtureFile returns the exact bytes of a file in the current version's
// set.
func readFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(currentFixtureDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// readV1FixtureFile returns the exact bytes of a file in the frozen v1 set.
//
// Named for its version rather than defaulting to one, because every current
// caller wants v1 SPECIFICALLY and for a reason that survives the bump:
// `genesis.hash` is the root of the one chain and is not a property of any
// schema version (doc 02 §4.4), and `format-probe` is the serializer's own
// vector, whose v2 form is the registered fingerprint constant rather than a
// fixture triple.
func readV1FixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDirV1, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}
