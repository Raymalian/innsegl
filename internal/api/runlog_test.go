// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// API-023 through API-025 (proposed for doc 07; doc 07 is not modified here).
//
// The run log shows what an agent actually did, and says of every line whether
// the chain still vouches for it.
//
// # Why the body is not in the ledger, and why that is the point
//
// A `tool_call` event carries `"tool_name": "Edit"` and a `payload_digest`. It
// does not say which file or what changed, and it never will: doc 02 §3 gives
// the body no member and IP E4 makes that mechanical. The chain is also
// append-only, so anything written there can never be deleted — and this is
// data with a 90-day life by the operator's decision.
//
// So the halves live apart, and the split is what makes the local file
// trustworthy: the digest in the chain is evidence about a file the chain does
// not contain. This is the code that spends that evidence. Rendering the bodies
// without checking them would be a log; checking them is a record.
//
// # The three states, and why "expired" is not "missing"
//
// A body that is gone after 90 days is the system working. A body whose bytes
// no longer hash to the digest the chain recorded is something else entirely,
// and a viewer that showed both as an empty cell would hide the only case that
// matters.
func TestAPI023TheRunLogChecksEveryBodyAgainstTheChain(t *testing.T) {
	dir := t.TempDir()
	runID := "run-abc"
	if err := os.MkdirAll(filepath.Join(dir, runID), 0o755); err != nil {
		t.Fatal(err)
	}

	good := `{"tool_name":"Edit","tool_input":{"file_path":"/x/y.go"}}`
	goodDigest := writeBody(t, dir, runID, good)

	altered := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	alteredDigest := writeBody(t, dir, runID, altered)
	// Rewrite the file AFTER its name was fixed by the original digest, which
	// is exactly the shape of tampering this check exists for: the name still
	// claims one thing and the bytes are another.
	if err := os.WriteFile(filepath.Join(dir, runID, alteredDigest+".json"),
		[]byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	gone := "sha256:" + hex.EncodeToString(sha256.New().Sum(nil))

	timeline := []TimelineEvent{
		toolCall(t, 10, "Edit", "sha256:"+goodDigest),
		toolCall(t, 11, "Bash", "sha256:"+alteredDigest),
		toolCall(t, 12, "Write", gone),
		{ChainPosition: 13, EventType: "run_retired", TS: time.Now()},
	}

	log, err := BuildRunLog(runID, dir, 90, timeline)
	if err != nil {
		t.Fatalf("BuildRunLog: %v", err)
	}

	if len(log.Entries) != 3 {
		t.Fatalf("got %d entries, want 3 — only tool_call events have a body, and "+
			"run_retired is not one", len(log.Entries))
	}

	for _, want := range []struct {
		pos       int64
		integrity string
	}{
		{10, LogVerified},
		{11, LogAltered},
		{12, LogExpired},
	} {
		var got LogEntry
		for _, e := range log.Entries {
			if e.ChainPosition == want.pos {
				got = e
			}
		}
		if got.Integrity != want.integrity {
			t.Errorf("chain position %d is %q, want %q", want.pos, got.Integrity, want.integrity)
		}
	}

	for _, e := range log.Entries {
		switch e.ChainPosition {
		case 10:
			if len(e.Body) == 0 {
				t.Error("a verified entry carries no body; there is nothing to read")
			}
		case 11:
			if len(e.Body) != 0 {
				t.Error("an ALTERED body was returned as if it were the record. Its bytes are " +
					"not what the chain vouched for, and showing them beside verified lines " +
					"is how a forgery gets read as evidence")
			}
		case 12:
			if len(e.Body) != 0 {
				t.Error("an expired entry carries a body")
			}
		}
	}

	if log.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d, want 90 — a reader cannot tell an expired "+
			"line from a missing one without knowing the window", log.RetentionDays)
	}
}

// TestAPI024ARunWithNoLogDirectoryIsNotAnError. Bodies are optional by
// construction: a deployment that never enabled the local log, or a run whose
// bodies have all aged out, must render as a timeline with no detail rather
// than as a failure.
func TestAPI024ARunWithNoLogDirectoryIsNotAnError(t *testing.T) {
	log, err := BuildRunLog("run-nothing", t.TempDir(), 90, []TimelineEvent{
		toolCall(t, 1, "Read", "sha256:"+hex.EncodeToString(sha256.New().Sum(nil))),
	})
	if err != nil {
		t.Fatalf("BuildRunLog with no bodies on disk: %v", err)
	}
	if len(log.Entries) != 1 || log.Entries[0].Integrity != LogExpired {
		t.Fatalf("got %+v; a run with no bodies is a run with expired bodies, not an error", log.Entries)
	}
}

// TestAPI025TheLogNeverLeavesItsRunsDirectory. run_id reaches this as a path
// segment from a URL. A run named `../other-run` must not read another run's
// bodies, and one containing a separator must not walk anywhere at all.
func TestAPI025TheLogNeverLeavesItsRunsDirectory(t *testing.T) {
	for _, bad := range []string{"../elsewhere", "a/b", "..", ".", "", "run/../../x"} {
		if _, err := BuildRunLog(bad, t.TempDir(), 90, nil); err == nil {
			t.Errorf("BuildRunLog(%q) was accepted; run_id arrives from a URL and names a directory", bad)
		}
	}
}

func writeBody(t *testing.T, dir, runID, body string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, runID, name+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func toolCall(t *testing.T, pos int64, tool, digest string) TimelineEvent {
	t.Helper()
	canonical := fmt.Sprintf(`{"event_type":"tool_call","tool_name":%q,"payload_digest":%q}`, tool, digest)
	return TimelineEvent{
		ChainPosition: pos,
		EventType:     "tool_call",
		TS:            time.Now(),
		Canonical:     json.RawMessage(canonical),
	}
}
