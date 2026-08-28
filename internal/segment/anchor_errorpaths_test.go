// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// The error returns of the anchoring path.
//
// Everything here is a unit test and everything here uses a stub log, which
// doc 01 §2 permits: "Mocks are allowed for unit and contract tests." What it
// forbids is proving the *integration* against a fake, and that proof is
// SEG-003 next door, against a containerised Rekor. What this file establishes
// is the other half: that each way the anchor path can fail produces the error
// class the retry loop and the operator need, rather than a generic one.

// stubLog is a TransparencyLog with scripted answers.
type stubLog struct {
	anchor Anchor
	err    error
	calls  int

	proof    InclusionProof
	proofErr error
}

func (s *stubLog) AnchorRoot(context.Context, string) (Anchor, error) {
	s.calls++
	return s.anchor, s.err
}

func (s *stubLog) InclusionProof(context.Context, string) (InclusionProof, error) {
	return s.proof, s.proofErr
}

// sealedFixture is a valid segment_sealed record to hang error cases off.
func sealedFixture(t *testing.T) (*Sealed, event.Fields) {
	t.Helper()
	chain := &testChain{}
	return sealAndAppend(t, &Sealer{Store: newMemStore()}, chain, 1, 4, seg004SealedAt)
}

func TestAnchorSignerRejectsUnusableKeys(t *testing.T) {
	if _, err := NewECDSAAnchorSigner(nil); !errors.Is(err, ErrAnchorSigner) {
		t.Fatalf("NewECDSAAnchorSigner(nil) = %v, want ErrAnchorSigner", err)
	}

	p384, keyErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("GenerateKey: %v", keyErr)
	}
	if _, curveErr := NewECDSAAnchorSigner(p384); !errors.Is(curveErr, ErrAnchorSigner) {
		t.Fatalf("a P-384 anchoring key was accepted: %v", curveErr)
	}

	var nilSigner *ECDSAAnchorSigner
	if _, signErr := nilSigner.SignDigest(make([]byte, 32)); !errors.Is(signErr, ErrAnchorSigner) {
		t.Fatalf("SignDigest on a nil signer = %v, want ErrAnchorSigner", signErr)
	}
	if _, pubErr := nilSigner.PublicKeyPEM(); !errors.Is(pubErr, ErrAnchorSigner) {
		t.Fatalf("PublicKeyPEM on a nil signer = %v, want ErrAnchorSigner", pubErr)
	}

	signer, genErr := GenerateAnchorSigner()
	if genErr != nil {
		t.Fatalf("GenerateAnchorSigner: %v", genErr)
	}
	if _, shortErr := signer.SignDigest([]byte("short")); !errors.Is(shortErr, ErrAnchorSigner) {
		t.Fatalf("signing a 5-byte digest = %v, want ErrAnchorSigner", shortErr)
	}
	if _, signErr := signer.SignDigest(make([]byte, 32)); signErr != nil {
		t.Fatalf("signing a 32-byte digest: %v", signErr)
	}
	if _, pubErr := signer.PublicKeyPEM(); pubErr != nil {
		t.Fatalf("PublicKeyPEM: %v", pubErr)
	}
}

// brokenSigner fails on demand, so the signing error paths of AnchorRoot are
// reachable without breaking a key.
type brokenSigner struct{ signErr, pubErr error }

func (b brokenSigner) SignDigest([]byte) ([]byte, error) {
	if b.signErr != nil {
		return nil, b.signErr
	}
	return []byte("signature"), nil
}

func (b brokenSigner) PublicKeyPEM() ([]byte, error) {
	if b.pubErr != nil {
		return nil, b.pubErr
	}
	return []byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"), nil
}

// rekorStub serves a canned response for every request.
func rekorStub(t *testing.T, status int, body string) *RekorClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if _, werr := w.Write([]byte(body)); werr != nil {
			t.Errorf("writing the stub response: %v", werr)
		}
	}))
	t.Cleanup(server.Close)

	signer, err := GenerateAnchorSigner()
	if err != nil {
		t.Fatalf("GenerateAnchorSigner: %v", err)
	}
	return &RekorClient{BaseURL: server.URL, Signer: signer}
}

const validRoot = "sha256:" +
	"3bb8f833781dc29e374eac6b657745e240dcf6c8474287226cba97c82e53e03a"

func TestRekorClientErrorClasses(t *testing.T) {
	ctx := context.Background()

	t.Run("no base url", func(t *testing.T) {
		signer, err := GenerateAnchorSigner()
		if err != nil {
			t.Fatalf("GenerateAnchorSigner: %v", err)
		}
		c := &RekorClient{Signer: signer}
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("AnchorRoot with no base url = %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a base url that is not a url", func(t *testing.T) {
		signer, err := GenerateAnchorSigner()
		if err != nil {
			t.Fatalf("GenerateAnchorSigner: %v", err)
		}
		c := &RekorClient{BaseURL: "http://\x7f-control-characters", Signer: signer}
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("AnchorRoot against an unparseable url = %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("reading an entry with no base url", func(t *testing.T) {
		c := &RekorClient{}
		if _, err := c.InclusionProof(ctx, strings.Repeat("ab", 32)); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("InclusionProof with no base url = %v, want ErrAnchorUnavailable", err)
		}
		if _, err := c.PublicKey(ctx); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("PublicKey with no base url = %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("an entry response that is not json", func(t *testing.T) {
		c := rekorStub(t, http.StatusOK, "not json")
		if _, err := c.InclusionProof(ctx, strings.Repeat("ab", 32)); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("an unparseable entry response gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("no signer", func(t *testing.T) {
		c := &RekorClient{BaseURL: "http://127.0.0.1:1"}
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorSigner) {
			t.Fatalf("AnchorRoot with no signer = %v, want ErrAnchorSigner", err)
		}
	})

	t.Run("root that is not a digest", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, "{}")
		for _, root := range []string{"", "deadbeef", "sha256:zz", "sha512:" + strings.Repeat("a", 64)} {
			if _, err := c.AnchorRoot(ctx, root); !errors.Is(err, ErrAnchorMismatch) {
				t.Fatalf("AnchorRoot(%q) = %v, want ErrAnchorMismatch", root, err)
			}
		}
	})

	t.Run("a signer that cannot sign", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, "{}")
		c.Signer = brokenSigner{signErr: ErrAnchorSigner}
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorSigner) {
			t.Fatalf("AnchorRoot with a failing signer = %v, want ErrAnchorSigner", err)
		}
	})

	t.Run("a signer that cannot produce its public key", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, "{}")
		c.Signer = brokenSigner{pubErr: ErrAnchorSigner}
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorSigner) {
			t.Fatalf("AnchorRoot with an unreadable key = %v, want ErrAnchorSigner", err)
		}
	})

	t.Run("fetching an entry from a broken log", func(t *testing.T) {
		c := rekorStub(t, http.StatusServiceUnavailable, "down for maintenance")
		if _, err := c.InclusionProof(ctx, strings.Repeat("ab", 32)); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("a 503 on the entry endpoint gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a 4xx is a rejection, not an outage", func(t *testing.T) {
		c := rekorStub(t, http.StatusBadRequest, `{"message":"signature does not verify"}`)
		_, err := c.AnchorRoot(ctx, validRoot)
		if !errors.Is(err, ErrAnchorRejected) {
			t.Fatalf("a 400 gave %v, want ErrAnchorRejected", err)
		}
		if errors.Is(err, ErrAnchorUnavailable) {
			t.Fatal("a 400 was classed as an outage; the retry loop would spend its budget on it")
		}
	})

	t.Run("a 5xx is an outage", func(t *testing.T) {
		c := rekorStub(t, http.StatusBadGateway, "upstream is down")
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("a 502 gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("an overlong error body is truncated", func(t *testing.T) {
		c := rekorStub(t, http.StatusBadRequest, strings.Repeat("x", 4096))
		_, err := c.AnchorRoot(ctx, validRoot)
		if !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("a 4KB error body was not truncated: %d characters", len(err.Error()))
		}
	})

	t.Run("a response that is not a log entry map", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, "not json")
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("unparseable response gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a response holding two entries", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, `{"a":{"logIndex":1},"b":{"logIndex":2}}`)
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("a two-entry response gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a response holding no entries", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, `{}`)
		if _, err := c.AnchorRoot(ctx, validRoot); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("an empty response gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a uuid that is not one", func(t *testing.T) {
		c := rekorStub(t, http.StatusOK, "{}")
		for _, uuid := range []string{"", "abc", strings.Repeat("g", 64)} {
			if _, err := c.InclusionProof(ctx, uuid); !errors.Is(err, ErrAnchorRejected) {
				t.Fatalf("InclusionProof(%q) = %v, want ErrAnchorRejected", uuid, err)
			}
		}
	})

	t.Run("the log returns a different entry than the one asked for", func(t *testing.T) {
		other := strings.Repeat("ab", 32)
		c := rekorStub(t, http.StatusOK, `{"`+other+`":{"logIndex":1}}`)
		if _, err := c.InclusionProof(ctx, strings.Repeat("cd", 32)); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("a swapped entry gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("an entry that is accepted but not yet integrated", func(t *testing.T) {
		uuid := strings.Repeat("ab", 32)
		c := rekorStub(t, http.StatusOK, `{"`+uuid+`":{"logIndex":1,"body":"e30="}}`)
		if _, err := c.InclusionProof(ctx, uuid); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("an unintegrated entry gave %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("an entry body that is not base64", func(t *testing.T) {
		uuid := strings.Repeat("ab", 32)
		c := rekorStub(t, http.StatusOK, `{"`+uuid+`":{"body":"!!!","verification":`+
			`{"inclusionProof":{"logIndex":0,"treeSize":1,"rootHash":"ab","hashes":[],"checkpoint":"x"}}}}`)
		if _, err := c.InclusionProof(ctx, uuid); !errors.Is(err, ErrInclusionProof) {
			t.Fatalf("a non-base64 body gave %v, want ErrInclusionProof", err)
		}
	})

	t.Run("a cancelled context is not laundered into an outage", func(t *testing.T) {
		c := rekorStub(t, http.StatusCreated, "{}")
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.AnchorRoot(cancelled, validRoot)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a cancelled anchor gave %v, want context.Canceled", err)
		}
		if errors.Is(err, ErrAnchorUnavailable) {
			t.Fatal("cancellation was reported as the log being unavailable")
		}
	})

	t.Run("public key that is not a key", func(t *testing.T) {
		if _, err := rekorStub(t, http.StatusOK, "not pem").PublicKey(ctx); !errors.Is(err, ErrInclusionProof) {
			t.Fatalf("a non-PEM key gave %v, want ErrInclusionProof", err)
		}
		if _, err := rekorStub(t, http.StatusNotFound, "").PublicKey(ctx); !errors.Is(err, ErrAnchorRejected) {
			t.Fatalf("a 404 on the key endpoint gave %v, want ErrAnchorRejected", err)
		}
		bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("rubbish")})
		if _, err := ParseLogPublicKey(bad); !errors.Is(err, ErrInclusionProof) {
			t.Fatalf("unparseable DER gave %v, want ErrInclusionProof", err)
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if _, err := ParseLogPublicKey(rsaPEM); !errors.Is(err, ErrInclusionProof) {
			t.Fatalf("an RSA log key gave %v, want ErrInclusionProof", err)
		}
	})
}

func TestInclusionProofVerifyRejectsMalformedProofs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := []byte(`{"kind":"hashedrekord"}`)
	leaf := hashLeaf(body)
	uuid := hex.EncodeToString(leaf[:])

	base := InclusionProof{
		EntryUUID:  uuid,
		Body:       body,
		LogIndex:   0,
		TreeSize:   1,
		RootHash:   hex.EncodeToString(leaf[:]),
		Checkpoint: "origin\n1\n" + base64.StdEncoding.EncodeToString(leaf[:]) + "\n\n— origin " + base64.StdEncoding.EncodeToString([]byte("0000sig")) + "\n",
	}

	cases := []struct {
		name string
		key  *ecdsa.PublicKey
		edit func(InclusionProof) InclusionProof
	}{
		{"no log key", nil, func(p InclusionProof) InclusionProof { return p }},
		{"no body", &key.PublicKey, func(p InclusionProof) InclusionProof { p.Body = nil; return p }},
		{"empty tree", &key.PublicKey, func(p InclusionProof) InclusionProof { p.TreeSize = 0; return p }},
		{"negative index", &key.PublicKey, func(p InclusionProof) InclusionProof { p.LogIndex = -1; return p }},
		{"index past the tree", &key.PublicKey, func(p InclusionProof) InclusionProof { p.LogIndex = 5; return p }},
		{"uuid is not hex", &key.PublicKey, func(p InclusionProof) InclusionProof { p.EntryUUID = "zz"; return p }},
		{"uuid names another leaf", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.EntryUUID = strings.Repeat("ab", 32)
			return p
		}},
		{"path step is not hex", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Hashes = []string{"zz"}
			return p
		}},
		{"path step is the wrong length", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Hashes = []string{"abcd"}
			return p
		}},
		{"checkpoint has no signature block", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\n1\nroot\n"
			return p
		}},
		{"checkpoint body is too short", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\n1\n\n— origin AAAAAAAA\n"
			return p
		}},
		{"checkpoint size is not a number", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\nmany\nroot\n\n— origin AAAAAAAA\n"
			return p
		}},
		{"checkpoint root is not base64", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\n1\n!!!\n\n— origin AAAAAAAA\n"
			return p
		}},
		{"checkpoint root is the wrong length", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\n1\nAAAA\n\n— origin AAAAAAAA\n"
			return p
		}},
		{"checkpoint has no readable signature", &key.PublicKey, func(p InclusionProof) InclusionProof {
			p.Checkpoint = "origin\n1\n" + base64.StdEncoding.EncodeToString(leaf[:]) + "\n\n\n"
			return p
		}},
		{"checkpoint signature does not verify", &key.PublicKey, func(p InclusionProof) InclusionProof { return p }},
		{"an unreadable signature line among readable ones", &key.PublicKey, func(p InclusionProof) InclusionProof {
			// A note may carry signatures from several keys. One this build
			// cannot decode is skipped, not fatal — but a checkpoint whose
			// only readable signature does not verify still fails.
			p.Checkpoint = "origin\n1\n" + base64.StdEncoding.EncodeToString(leaf[:]) +
				"\n\n— origin !!!\n— origin " +
				base64.StdEncoding.EncodeToString([]byte("0000sig")) + "\n"
			return p
		}},
		{"the checkpoint is over another root", &key.PublicKey, func(p InclusionProof) InclusionProof {
			// The walk reaches the root the proof claims, and the checkpoint
			// — the only part of this the log actually signed — is over a
			// different tree.
			var other [32]byte
			other[0] = 0xff
			p.Checkpoint = "origin\n1\n" + base64.StdEncoding.EncodeToString(other[:]) +
				"\n\n— origin " + base64.StdEncoding.EncodeToString([]byte("0000sig")) + "\n"
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.edit(base).Verify(c.key); !errors.Is(err, ErrInclusionProof) {
				t.Fatalf("Verify = %v, want an error wrapping ErrInclusionProof", err)
			}
		})
	}
}

func TestInclusionProofMerkleRootRejectsForeignEntries(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not json", "{"},
		{"another entry kind", `{"kind":"intoto","apiVersion":"0.0.1"}`},
		{"another hash algorithm", `{"kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha512","value":"ab"}}}}`},
		{"a value that is not a digest", `{"kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha256","value":"nope"}}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := (InclusionProof{Body: []byte(c.body)}).MerkleRoot(); !errors.Is(err, ErrInclusionProof) {
				t.Fatalf("MerkleRoot = %v, want an error wrapping ErrInclusionProof", err)
			}
		})
	}
}

func TestRekorInclusionRootRejectsImpossibleShapes(t *testing.T) {
	var leaf [32]byte
	if _, err := rekorInclusionRoot(0, 0, leaf, nil); !errors.Is(err, ErrInclusionProof) {
		t.Fatalf("a tree of zero gave %v", err)
	}
	if _, err := rekorInclusionRoot(3, 3, leaf, nil); !errors.Is(err, ErrInclusionProof) {
		t.Fatalf("an index past the tree gave %v", err)
	}
	if _, err := rekorInclusionRoot(0, 4, leaf, [][32]byte{leaf}); !errors.Is(err, ErrInclusionProof) {
		t.Fatalf("a one-step path in a tree of four gave %v", err)
	}
	// The one-leaf tree: the root is the leaf, and the path is empty.
	root, err := rekorInclusionRoot(0, 1, leaf, nil)
	if err != nil {
		t.Fatalf("a single-leaf tree: %v", err)
	}
	if root != leaf {
		t.Fatal("the root of a single-leaf tree is not the leaf")
	}
}

func TestAnchorerRefusesWhatItCannotAnchor(t *testing.T) {
	ctx := context.Background()
	_, sealed := sealedFixture(t)

	t.Run("no log", func(t *testing.T) {
		a := &Anchorer{}
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("Anchor with no log = %v, want ErrAnchorUnavailable", err)
		}
	})

	t.Run("a record that is not a segment_sealed", func(t *testing.T) {
		a := &Anchorer{Log: &stubLog{}}
		other := event.Fields{}
		for k, v := range sealed {
			other[k] = v
		}
		other[event.FieldEventType] = event.EventTypeToolCall
		if _, err := a.Anchor(ctx, other); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("anchoring a tool_call = %v, want ErrAnchorMismatch", err)
		}
	})

	t.Run("a record missing what an anchor needs", func(t *testing.T) {
		for _, name := range []string{
			event.FieldEventType, event.FieldEventID, event.FieldSegmentID,
			event.FieldSegmentMerkleRoot, event.FieldFirstPosition,
			event.FieldLastPosition, event.FieldTS,
		} {
			short := event.Fields{}
			for k, v := range sealed {
				if k != name {
					short[k] = v
				}
			}
			a := &Anchorer{Log: &stubLog{}}
			if _, err := a.Anchor(ctx, short); err == nil {
				t.Fatalf("anchoring a record with no %s succeeded", name)
			}
		}
	})

	t.Run("a record whose ts is not a timestamp", func(t *testing.T) {
		bad := event.Fields{}
		for k, v := range sealed {
			bad[k] = v
		}
		bad[event.FieldTS] = "yesterday"
		a := &Anchorer{Log: &stubLog{}}
		if _, err := a.Anchor(ctx, bad); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("anchoring a record with an unreadable ts = %v, want ErrAnchorMismatch", err)
		}
	})

	t.Run("the log answers with another segment's root", func(t *testing.T) {
		log := &stubLog{anchor: Anchor{MerkleRoot: validRoot, EntryUUID: "x", LogIndex: 1}}
		a := &Anchorer{Log: log, Policy: RetryPolicy{Attempts: 3}}
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("a mismatched anchor = %v, want ErrAnchorMismatch", err)
		}
		if log.calls != 1 {
			t.Fatalf("%d submissions for a mismatch that a retry cannot fix, want 1", log.calls)
		}
	})

	t.Run("a rejection is not retried", func(t *testing.T) {
		log := &stubLog{err: ErrAnchorRejected}
		a := &Anchorer{
			Log:    log,
			Policy: RetryPolicy{Attempts: 9, Base: time.Nanosecond},
			Sleep:  func(context.Context, time.Duration) error { return nil },
		}
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, ErrAnchorRejected) {
			t.Fatalf("Anchor = %v, want ErrAnchorRejected", err)
		}
		if log.calls != 1 {
			t.Fatalf("%d submissions of an entry the log already refused, want 1", log.calls)
		}
	})

	t.Run("an unusable key is not retried", func(t *testing.T) {
		log := &stubLog{err: ErrAnchorSigner}
		a := &Anchorer{
			Log:    log,
			Policy: RetryPolicy{Attempts: 9, Base: time.Nanosecond},
			Sleep:  func(context.Context, time.Duration) error { return nil },
		}
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, ErrAnchorSigner) {
			t.Fatalf("Anchor = %v, want ErrAnchorSigner", err)
		}
		if log.calls != 1 {
			t.Fatalf("%d submissions with a key that cannot sign, want 1", log.calls)
		}
	})

	t.Run("an expired context is not retried", func(t *testing.T) {
		log := &stubLog{err: context.DeadlineExceeded}
		a := &Anchorer{Log: log, Policy: RetryPolicy{Attempts: 9, Base: time.Nanosecond}}
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Anchor = %v, want context.DeadlineExceeded", err)
		}
		if log.calls != 1 {
			t.Fatalf("%d submissions after the deadline passed, want 1", log.calls)
		}
	})

	t.Run("the default sleep actually waits between attempts", func(t *testing.T) {
		log := &stubLog{err: ErrAnchorUnavailable}
		a := &Anchorer{Log: log, Policy: RetryPolicy{Attempts: 3, Base: time.Millisecond, Max: time.Millisecond}}
		start := time.Now()
		if _, err := a.Anchor(ctx, sealed); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("Anchor = %v, want ErrAnchorUnavailable", err)
		}
		if log.calls != 3 {
			t.Fatalf("%d submissions, want the policy's 3", log.calls)
		}
		if elapsed := time.Since(start); elapsed < 2*time.Millisecond {
			t.Fatalf("three attempts took %v; the two backoffs were not waited out", elapsed)
		}
	})

	t.Run("the default sleep honours cancellation", func(t *testing.T) {
		log := &stubLog{err: ErrAnchorUnavailable}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		a := &Anchorer{Log: log, Policy: RetryPolicy{Attempts: 3, Base: time.Hour}}
		start := time.Now()
		if _, err := a.Anchor(cancelled, sealed); !errors.Is(err, context.Canceled) {
			t.Fatalf("Anchor = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("the default sleep waited %v for a cancelled context", elapsed)
		}
	})
}

func TestLagIsReportedBeforeAnythingIsSealed(t *testing.T) {
	a := &Anchorer{Log: &stubLog{}}
	snap := a.Lag()
	if snap.ObservedAt.IsZero() {
		t.Fatal("the heartbeat has no timestamp")
	}
	if snap.Anchored {
		t.Fatal("an anchorer that has anchored nothing reports itself current")
	}
	if snap.LagSeconds != 0 || snap.OverBound {
		t.Fatalf("a fresh anchorer reports lag %v over-bound %v", snap.LagSeconds, snap.OverBound)
	}
	// The default bound is a real number, so the header has something to
	// compare against even when nothing configured one (FD §3.1).
	if snap.Bound() != defaultAnchorBound {
		t.Fatalf("default bound is %v, want %v", snap.Bound(), defaultAnchorBound)
	}
}

func TestAnchorEventRefusesAnchorsThatDoNotBelong(t *testing.T) {
	_, sealed := sealedFixture(t)
	root, err := claimString(sealed, event.FieldSegmentMerkleRoot)
	if err != nil {
		t.Fatalf("reading the sealed root: %v", err)
	}
	segmentID, err := claimString(sealed, event.FieldSegmentID)
	if err != nil {
		t.Fatalf("reading the segment id: %v", err)
	}
	good := Anchor{SegmentID: segmentID, MerkleRoot: root, EntryUUID: strings.Repeat("ab", 32), LogIndex: 7}
	ts := mustTS(t, "2026-08-28T10:30:00.000Z")

	t.Run("a record that is not a segment_sealed", func(t *testing.T) {
		if _, err := AnchorEvent(EventMeta{EventID: newEventID(t), TS: ts},
			event.Fields{}, good); err == nil {
			t.Fatal("AnchorEvent accepted a record with no event_type")
		}
	})

	cases := []struct {
		name   string
		meta   EventMeta
		anchor Anchor
	}{
		{"another root", EventMeta{EventID: newEventID(t), TS: ts},
			Anchor{SegmentID: segmentID, MerkleRoot: validRoot, EntryUUID: "ab", LogIndex: 1}},
		{"another segment", EventMeta{EventID: newEventID(t), TS: ts},
			Anchor{SegmentID: "sha256:" + strings.Repeat("0", 64), MerkleRoot: root, EntryUUID: "ab", LogIndex: 1}},
		{"no entry uuid", EventMeta{EventID: newEventID(t), TS: ts},
			Anchor{SegmentID: segmentID, MerkleRoot: root, LogIndex: 1}},
		{"a negative log index", EventMeta{EventID: newEventID(t), TS: ts},
			Anchor{SegmentID: segmentID, MerkleRoot: root, EntryUUID: "ab", LogIndex: -1}},
		{"no event id", EventMeta{TS: ts}, good},
		{"an event id that is not a uuidv7", EventMeta{EventID: "nope", TS: ts}, good},
		{"no timestamp", EventMeta{EventID: newEventID(t)}, good},
		{"a source outside the enum", EventMeta{EventID: newEventID(t), TS: ts, Source: "somebody"}, good},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AnchorEvent(c.meta, sealed, c.anchor); err == nil {
				t.Fatal("AnchorEvent accepted it")
			}
		})
	}

	t.Run("an entry uuid too long for the schema", func(t *testing.T) {
		oversized := good
		oversized.EntryUUID = strings.Repeat("a", event.MaxReferenceBytes+1)
		if _, err := AnchorEvent(EventMeta{EventID: newEventID(t), TS: ts}, sealed, oversized); err == nil {
			t.Fatal("AnchorEvent accepted an entry uuid past the schema's bound")
		}
	})

	t.Run("a valid anchor is accepted", func(t *testing.T) {
		body, err := AnchorEvent(EventMeta{EventID: newEventID(t), TS: ts}, sealed, good)
		if err != nil {
			t.Fatalf("AnchorEvent: %v", err)
		}
		if got := body[event.FieldAnchorRekorLogIndex]; got != int64(7) {
			t.Fatalf("anchor_rekor_log_index is %v (%T), want int64(7)", got, got)
		}
	})
}

func TestAnchorAlertRefusesWhatItCannotExplain(t *testing.T) {
	_, sealed := sealedFixture(t)
	ts := mustTS(t, "2026-08-28T10:30:00.000Z")
	cause := errors.New("connection refused")

	if _, err := AnchorAlert(AlertMeta{EventID: newEventID(t), TS: ts}, sealed, nil); err == nil {
		t.Fatal("AnchorAlert accepted an alert with no cause")
	}
	if _, err := AnchorAlert(AlertMeta{EventID: newEventID(t), TS: ts}, event.Fields{}, cause); err == nil {
		t.Fatal("AnchorAlert accepted a record that is not a segment_sealed")
	}
	if _, err := AnchorAlert(AlertMeta{
		EventID:        newEventID(t),
		TS:             ts,
		SubjectEventID: newEventID(t),
	}, sealed, cause); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatal("AnchorAlert accepted an alert naming a different subject")
	}

	subject, err := claimString(sealed, event.FieldEventID)
	if err != nil {
		t.Fatalf("reading the sealed event id: %v", err)
	}
	body, err := AnchorAlert(AlertMeta{
		EventID:        newEventID(t),
		TS:             ts,
		SubjectEventID: subject,
		Source:         event.SourceReconciler,
	}, sealed, cause)
	if err != nil {
		t.Fatalf("AnchorAlert: %v", err)
	}
	if got := body[event.FieldSource]; got != event.SourceReconciler {
		t.Fatalf("alert source is %v, want the caller's %s", got, event.SourceReconciler)
	}
	reason, err := claimString(body, event.FieldReason)
	if err != nil {
		t.Fatalf("the alert carries no reason: %v", err)
	}
	if !strings.Contains(reason, "connection refused") {
		t.Fatalf("the alert does not say why: %q", reason)
	}
	if !strings.Contains(reason, "positions 1..4") {
		t.Fatalf("the alert does not name the segment's range: %q", reason)
	}
}
