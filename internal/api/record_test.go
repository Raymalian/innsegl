// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The run page and this API read one fixture: the web page renders it and
// this test decodes it strictly, so a member one side adds or renames that
// the other does not know fails here rather than rendering as a blank.
func TestRunRecordFixtureMatchesTheContract(t *testing.T) {
	for name, into := range map[string]any{
		"record.json":     &RunRecord{},
		"diff-step1.json": &StepDiff{},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "views", "run-page", "fixtures", name))
			if err != nil {
				t.Fatalf("read the fixture: %v", err)
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if derr := dec.Decode(into); derr != nil {
				t.Fatalf("the fixture does not decode strictly into the contract: %v", derr)
			}
			// And back: every member the contract has, the fixture has.
			var fixture, encoded map[string]any
			if uerr := json.Unmarshal(raw, &fixture); uerr != nil {
				t.Fatal(uerr)
			}
			out, err := json.Marshal(into)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(out, &encoded); err != nil {
				t.Fatal(err)
			}
			assertSameKeys(t, "", fixture, encoded)
		})
	}
}

// assertSameKeys walks both documents and fails on any object member that
// one has and the other does not.
func assertSameKeys(t *testing.T, path string, a, b any) {
	t.Helper()
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			t.Errorf("%s: object in the fixture, %T in the contract", path, b)
			return
		}
		for k := range bv {
			if _, ok := av[k]; !ok {
				t.Errorf("%s.%s: in the contract, missing from the fixture", path, k)
			}
		}
		for k, v := range av {
			assertSameKeys(t, path+"."+k, v, bv[k])
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			t.Errorf("%s: array in the fixture, %T in the contract", path, b)
			return
		}
		for i := range av {
			if i < len(bv) {
				assertSameKeys(t, path, av[i], bv[i])
			}
		}
	}
}
