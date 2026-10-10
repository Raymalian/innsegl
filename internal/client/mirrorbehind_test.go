// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"
	"time"
)

// SNAP-009: a branch the core's mirror refused as a rewrite is recorded
// once, read back for `innsegl status`, and cleared by the next push the
// mirror takes.
func TestSNAP009AMirrorRefusalIsRecordedOnceAndClearedByTheNextPush(t *testing.T) {
	paths := ClientPaths(t.TempDir())
	first := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	e := MirrorBehind{Repo: "github.com/acme/widgets", Branch: "main", Local: "aaaa", Reason: "not a fast-forward", Since: first}

	recorded, err := RecordMirrorBehind(paths, e)
	if err != nil || !recorded {
		t.Fatalf("first record = %v %v, want recorded", recorded, err)
	}
	again := e
	again.Since = first.Add(time.Hour)
	again.Local = "bbbb"
	if recorded, err = RecordMirrorBehind(paths, again); err != nil || recorded {
		t.Fatalf("second record = %v %v, want recorded once only", recorded, err)
	}
	other := MirrorBehind{Repo: "github.com/acme/widgets", Branch: "dev", Reason: "x", Since: first}
	if _, err = RecordMirrorBehind(paths, other); err != nil {
		t.Fatal(err)
	}

	got, err := ReadMirrorBehind(paths)
	if err != nil || len(got) != 2 || got[0].Branch != "dev" || got[1].Branch != "main" || !got[1].Since.Equal(first) {
		t.Fatalf("ReadMirrorBehind = %+v %v, want dev and main, main since the first refusal", got, err)
	}

	if err = ClearMirrorBehind(paths, "github.com/acme/widgets", "main"); err != nil {
		t.Fatal(err)
	}
	if err = ClearMirrorBehind(paths, "github.com/acme/widgets", "main"); err != nil {
		t.Fatalf("clearing what is not recorded: %v", err)
	}
	if got, err = ReadMirrorBehind(paths); err != nil || len(got) != 1 || got[0].Branch != "dev" {
		t.Fatalf("after clearing main: %+v %v", got, err)
	}
}

func TestSNAP009NothingRecordedReadsAsNothing(t *testing.T) {
	got, err := ReadMirrorBehind(ClientPaths(t.TempDir()))
	if err != nil || len(got) != 0 {
		t.Fatalf("ReadMirrorBehind with no file = %+v %v", got, err)
	}
}
