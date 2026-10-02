// SPDX-License-Identifier: Apache-2.0

package clientjournal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sampleEntry() Entry {
	return Entry{
		Seq: 1, InstallationID: "0123456789abcdef0123456789abcdef",
		SessionID: "33333333-3333-4333-8333-333333333333", Reason: ReasonCoreUnreachable,
		Statement: json.RawMessage(`{"session_id":"33333333-3333-4333-8333-333333333333","repo":"github.com/o/r"}`),
		Method:    http.MethodPost, Path: "/v1/messages",
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		RequestBody:    []byte(`{"messages":[]}`),
		ResponseStatus: http.StatusOK, ResponseBody: []byte("event: x\ndata: {}\n\n"),
		ResponseComplete: true,
		StartedAt:        time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		EndedAt:          time.Date(2026, 10, 2, 9, 0, 1, 0, time.UTC),
	}
}

// JRN-001: a sealed entry opens under the installation's key and under no
// other; a changed byte breaks it.
func TestJRN001SealOpensOnlyUnderTheInstallationKey(t *testing.T) {
	key := newKey(t)
	s, err := Seal(sampleEntry(), key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := s.Open(&key.PublicKey)
	if err != nil {
		t.Fatalf("Open under the sealing key: %v", err)
	}
	if got.SessionID != sampleEntry().SessionID || string(got.ResponseBody) != string(sampleEntry().ResponseBody) {
		t.Fatalf("opened entry differs: %+v", got)
	}
	if got.Version != Version {
		t.Fatalf("version = %d, want %d", got.Version, Version)
	}

	other := newKey(t)
	if _, err := s.Open(&other.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("Open under another key = %v, want ErrSignature", err)
	}

	tampered := Sealed{Entry: append([]byte(nil), s.Entry...), Signature: s.Signature}
	tampered.Entry[len(tampered.Entry)/2] ^= 1
	if _, err := tampered.Open(&key.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("Open of a changed entry = %v, want ErrSignature", err)
	}
	if tampered.Hash() == s.Hash() {
		t.Fatal("a changed entry hashes the same")
	}
	if !strings.HasPrefix(s.Hash(), "sha256:") || len(s.Hash()) != len("sha256:")+64 {
		t.Fatalf("hash %q is not sha256:<64 hex>", s.Hash())
	}
	if _, err := s.Open(nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("Open with no key = %v, want ErrSignature", err)
	}
}

// JRN-001: credentials never enter an entry.
func TestJRN001KeptHeadersDropCredentials(t *testing.T) {
	h := http.Header{
		"Authorization":            {"Bearer canary-token"},
		"X-Api-Key":                {"canary-key"},
		"Cookie":                   {"a=b"},
		"Proxy-Authorization":      {"x"},
		"Connection":               {"keep-alive"},
		"X-Innsegl-Statement":      {"abc"},
		"Anthropic-Version":        {"2023-06-01"},
		"X-Claude-Code-Session-Id": {"33333333-3333-4333-8333-333333333333"},
	}
	kept := KeptHeaders(h)
	for _, k := range []string{"Authorization", "X-Api-Key", "Cookie", "Proxy-Authorization", "Connection", "X-Innsegl-Statement"} {
		if kept.Get(k) != "" {
			t.Errorf("%s was kept", k)
		}
	}
	if kept.Get("Anthropic-Version") == "" || kept.Get("X-Claude-Code-Session-Id") == "" {
		t.Fatalf("ordinary headers were dropped: %v", kept)
	}
	if h.Get("Authorization") == "" {
		t.Fatal("KeptHeaders changed its input")
	}
}

// JRN-001: an entry of another version, or not an entry at all, is refused
// even under a valid signature.
func TestJRN001OpenRefusesWhatIsNotAnEntry(t *testing.T) {
	key := newKey(t)
	for name, raw := range map[string]string{
		"not json":      "not json",
		"other version": `{"v":2,"seq":1}`,
		"no sequence":   `{"v":1,"seq":0}`,
	} {
		s, err := sealRaw([]byte(raw), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Open(&key.PublicKey); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Open = %v, want ErrMalformed", name, err)
		}
	}
}
