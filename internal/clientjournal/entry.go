// SPDX-License-Identifier: Apache-2.0

// Package clientjournal is the format of the client journal (ADR-0068): one
// model exchange the core could not record, written by the client service
// and imported by the core.
//
// An entry is sealed as the exact bytes that were signed, never
// re-serialised: the signature, the entry hash and the chain all cover those
// bytes, so the format needs no canonical serialisation of its own. The
// signature is ECDSA P-256 over SHA-256 of the bytes, by the installation's
// own key, the key its client certificate names.
//
// Every time in an entry is the client's claim. The core's events carry the
// core's own ts (doc 02 §2, LED-010); the signed entry, stored on the core as
// the recorded body, is where the client's times are kept (E4).
package clientjournal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Version is the entry format this build writes and reads.
const Version = 1

// Why an exchange was journaled.
const (
	// ReasonCoreUnreachable: the core did not answer (connect, TLS, timeout,
	// or a 5xx of its own); the client forwarded the request to the provider
	// directly.
	ReasonCoreUnreachable = "core-unreachable"
	// ReasonCoreNotRecorded: the core relayed the request but said it did
	// not record it (RecordedHeader "false").
	ReasonCoreNotRecorded = "core-not-recorded"
)

// RecordedHeader is the core's answer, on every reply it relays from the
// provider, to whether it recorded the exchange: "true", "false" (inside a
// repository, not recorded: the client journals it), or "none" (no
// repository: nothing to record). A reply without it was not relayed by the
// core at all.
const RecordedHeader = "X-Innsegl-Recorded"

// Values of RecordedHeader.
const (
	RecordedTrue  = "true"
	RecordedFalse = "false"
	RecordedNone  = "none"
)

// Errors Open answers.
var (
	// ErrSignature: the signature does not verify under the key given.
	ErrSignature = errors.New("clientjournal: the entry's signature does not verify under the installation's key")
	// ErrMalformed: the signed bytes are not an entry this build reads.
	ErrMalformed = errors.New("clientjournal: the signed bytes are not a journal entry")
)

// Entry is one exchange.
type Entry struct {
	Version int `json:"v"`
	// Seq is 1-based and strictly consecutive per installation; Prev is the
	// hash (Sealed.Hash) of entry Seq-1, empty for the first.
	Seq            uint64 `json:"seq"`
	Prev           string `json:"prev"`
	InstallationID string `json:"installation_id"`
	SessionID      string `json:"session_id"`
	AgentID        string `json:"agent_id,omitempty"`
	Reason         string `json:"reason"`
	// Statement is the session's statement in force (repository, branch,
	// task, working directory, agent type), as the session hook posted it.
	Statement json.RawMessage `json:"statement,omitempty"`
	Method    string          `json:"method"`
	Path      string          `json:"path"`
	Query     string          `json:"query,omitempty"`
	// RequestHeaders are KeptHeaders: never a credential.
	RequestHeaders  http.Header `json:"request_headers"`
	RequestBody     []byte      `json:"request_body"`
	ResponseStatus  int         `json:"response_status"`
	ResponseHeaders http.Header `json:"response_headers,omitempty"`
	// ResponseBody is the reply as it was streamed to the harness.
	ResponseBody []byte `json:"response_body"`
	// ResponseComplete is false when the stream ended early or the capture
	// bound was reached; ResponseBody then holds what was seen.
	ResponseComplete bool `json:"response_complete"`
	// StartedAt and EndedAt are the client's clock.
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

// Sealed is an entry as it is stored and sent: the signed bytes and the
// signature over them.
type Sealed struct {
	Entry     []byte `json:"entry"`
	Signature []byte `json:"signature"`
}

// Seal signs e with key. e.Version is set to Version.
func Seal(e Entry, key *ecdsa.PrivateKey) (Sealed, error) {
	e.Version = Version
	raw, err := json.Marshal(e)
	if err != nil {
		return Sealed{}, fmt.Errorf("clientjournal: encoding the entry: %w", err)
	}
	return sealRaw(raw, key)
}

func sealRaw(raw []byte, key *ecdsa.PrivateKey) (Sealed, error) {
	if key == nil {
		return Sealed{}, errors.New("clientjournal: no key to seal with")
	}
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return Sealed{}, fmt.Errorf("clientjournal: signing the entry: %w", err)
	}
	return Sealed{Entry: raw, Signature: sig}, nil
}

// Hash is the entry's identity and its link in the chain: "sha256:" and the
// lowercase hex of SHA-256 over the signed bytes.
func (s Sealed) Hash() string {
	sum := sha256.Sum256(s.Entry)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Open verifies the signature under pub and decodes the entry.
func (s Sealed) Open(pub crypto.PublicKey) (Entry, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec == nil {
		return Entry{}, ErrSignature
	}
	sum := sha256.Sum256(s.Entry)
	if !ecdsa.VerifyASN1(ec, sum[:], s.Signature) {
		return Entry{}, ErrSignature
	}
	var e Entry
	if err := json.Unmarshal(s.Entry, &e); err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if e.Version != Version || e.Seq == 0 {
		return Entry{}, fmt.Errorf("%w: version %d, sequence %d", ErrMalformed, e.Version, e.Seq)
	}
	return e, nil
}

// droppedHeaders never enter an entry: credentials, the connection's own
// headers, and the statement, which an entry carries decoded.
var droppedHeaders = map[string]bool{
	"Authorization": true, "X-Api-Key": true, "Cookie": true, "Set-Cookie": true,
	"Proxy-Authorization": true, "Proxy-Authenticate": true,
	"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
	"X-Innsegl-Statement": true,
}

// KeptHeaders is a copy of h without credentials, hop-by-hop headers or the
// statement.
func KeptHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		ck := http.CanonicalHeaderKey(k)
		if droppedHeaders[ck] || strings.Contains(strings.ToLower(ck), "api-key") {
			continue
		}
		out[ck] = append([]string(nil), vv...)
	}
	return out
}
