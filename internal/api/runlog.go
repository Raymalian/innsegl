// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The run log: what an agent did, with the chain's verdict on every line.
//
// # Why this exists in two halves
//
// A `tool_call` event says `"tool_name": "Edit"` and carries a
// `payload_digest`. It does not say which file or what changed, and it never
// will — doc 02 §3 gives the body no member and IP E4 makes that mechanical.
// The chain is append-only as well, so anything written into it can never be
// removed, and the operator's decision is that this detail lives 90 days.
//
// Two requirements that one store cannot meet, so there are two: the chain
// keeps the digest forever, and the operator's own disk keeps the body for a
// while. Neither is a copy of the other.
//
// # What the split buys, and it is the whole point
//
// The digest in the chain is evidence about a file the chain does not contain.
// So a body read back from disk is not merely *a* log — it can be checked, and
// this is where that check happens. Deleting a body later costs nothing,
// because verification reads the digest and not the bytes.
//
// # What never expires
//
// Only bodies. `run_registered`, the SPIFFE ID, the `Agent-Identity` trailer
// and every digest are in the chain and outlive all of this. "Who was this
// agent, and what did it sign" is answerable forever; "what exactly did it type
// last spring" is not, on purpose.
const (
	// LogVerified: the bytes on disk hash to the digest the chain recorded.
	LogVerified = "verified"
	// LogAltered: a body is present and is NOT what was recorded. This is the
	// one state that means something is wrong, and it is why the bodies are
	// checked rather than merely listed.
	LogAltered = "altered"
	// LogExpired: no body. Either it aged out or this deployment never kept
	// one. Distinct from LogAltered because an empty cell must not be able to
	// mean tampering.
	LogExpired = "expired"
)

// LogEntry is one recorded tool call, and the chain's verdict on its body.
type LogEntry struct {
	ChainPosition int64     `json:"chain_position"`
	ToolName      string    `json:"tool_name"`
	TS            time.Time `json:"ts"`
	PayloadDigest string    `json:"payload_digest"`
	Integrity     string    `json:"integrity"`
	// Body is present only when Integrity is LogVerified.
	//
	// An altered body is deliberately withheld. Its bytes are not what the
	// chain vouched for, and rendering them beside verified lines is exactly
	// how a forgery comes to be read as evidence. The reader is told it exists
	// and that it does not match; that is the finding, not the content.
	Body json.RawMessage `json:"body,omitempty"`
}

// RunLog is every tool call one run made, oldest first.
type RunLog struct {
	RunID string `json:"run_id"`
	// RetentionDays is here so a reader can tell an expired line from a line
	// that never had a body. Without the window, both are just absent.
	RetentionDays int        `json:"retention_days"`
	Entries       []LogEntry `json:"entries"`
	Verified      int        `json:"verified"`
	Altered       int        `json:"altered"`
	Expired       int        `json:"expired"`
}

// ErrBadRunID rejects a run identifier that could name a directory.
var ErrBadRunID = errors.New("run_id is not a single path segment")

// BuildRunLog pairs a run's `tool_call` events with the bodies on disk.
//
// It reads; it never writes and never deletes. Retention is the harness hook's
// job — a read path that could delete would be one restart away from pruning
// on someone else's schedule.
func BuildRunLog(runID, dir string, retentionDays int, timeline []TimelineEvent) (RunLog, error) {
	// run_id arrives as a URL path segment and is about to become a directory
	// name. A single segment, or nothing.
	if runID == "" || runID == "." || runID == ".." ||
		strings.ContainsAny(runID, `/\`) || strings.Contains(runID, "..") {
		return RunLog{}, fmt.Errorf("%w: %q", ErrBadRunID, runID)
	}

	log := RunLog{RunID: runID, RetentionDays: retentionDays, Entries: []LogEntry{}}
	for _, ev := range timeline {
		if ev.EventType != "tool_call" {
			continue
		}
		var body struct {
			ToolName      string `json:"tool_name"`
			PayloadDigest string `json:"payload_digest"`
		}
		// A canonical event that will not parse is a defect elsewhere, not a
		// reason to fail the whole page. The entry is still listed -- its
		// position and time are known from the timeline -- and it reports as
		// expired, because without a digest there is nothing to check a body
		// against and claiming otherwise would be a guess.
		if err := json.Unmarshal(ev.Canonical, &body); err != nil {
			body.ToolName, body.PayloadDigest = "", ""
		}

		entry := LogEntry{
			ChainPosition: ev.ChainPosition,
			ToolName:      body.ToolName,
			TS:            ev.TS,
			PayloadDigest: body.PayloadDigest,
			Integrity:     LogExpired,
		}
		if raw, ok := readBody(dir, runID, body.PayloadDigest); ok {
			if bodyMatches(raw, body.PayloadDigest) {
				entry.Integrity = LogVerified
				entry.Body = raw
			} else {
				entry.Integrity = LogAltered
			}
		}
		switch entry.Integrity {
		case LogVerified:
			log.Verified++
		case LogAltered:
			log.Altered++
		default:
			log.Expired++
		}
		log.Entries = append(log.Entries, entry)
	}
	return log, nil
}

// readBody reads the body a digest names, and returns false for every reason
// it might not be there.
func readBody(dir, runID, digest string) (json.RawMessage, bool) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return nil, false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return nil, false
	}
	// Base, though BuildRunLog already refused anything with a separator in
	// it. Two reasons to keep it: this is the line that opens a file whose
	// name came from a URL, and the guard should be beside it rather than
	// forty lines away where a future caller can miss it -- and it is what
	// lets a static analyser see that too.
	raw, err := os.ReadFile(filepath.Join(dir, filepath.Base(runID), hexPart+".json"))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// bodyMatches is the whole argument for keeping the digest in the chain.
func bodyMatches(raw []byte, digest string) bool {
	sum := sha256.Sum256(raw)
	return "sha256:"+hex.EncodeToString(sum[:]) == digest
}
