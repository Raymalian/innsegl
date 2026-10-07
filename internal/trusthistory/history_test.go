// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real keys and real certificates throughout: a history whose key ids were
// computed by the test from the same helper as the code would agree with it
// by construction, so every key id here is recomputed from the DER by hand.

func caPEM(t *testing.T, name string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func logKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// spkiID is the key id, computed here independently of KeyIDOf.
func spkiID(t *testing.T, p []byte) string {
	t.Helper()
	block, _ := pem.Decode(p)
	var spki []byte
	if block.Type == "CERTIFICATE" {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		spki = c.RawSubjectPublicKeyInfo
	} else {
		spki = block.Bytes
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

var (
	day1 = time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	ten  = day1.AddDate(10, 0, 0)
)

func TestRecordSeedsAnEmptyHistoryFromTheCurrentRootAndLogKey(t *testing.T) {
	root := caPEM(t, "root B", day1, ten)
	logKey := logKeyPEM(t)
	now := day1.AddDate(0, 0, 21)

	h := New()
	added, err := h.Record(KindFulcioRoot, root, now)
	if err != nil || !added {
		t.Fatalf("Record(root) = %v, %v; want added", added, err)
	}
	added, err = h.Record(KindTransparencyLog, logKey, now)
	if err != nil || !added {
		t.Fatalf("Record(log) = %v, %v; want added", added, err)
	}
	if len(h.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(h.Entries))
	}
	r, l := h.Entries[0], h.Entries[1]
	if r.KeyID != spkiID(t, root) || l.KeyID != spkiID(t, logKey) {
		t.Errorf("key ids are not sha256 of the SubjectPublicKeyInfo: %s %s", r.KeyID, l.KeyID)
	}
	// A root's first use is its own NotBefore, not the day it was recorded:
	// an existing deployment's history must begin when its root did.
	if !r.FirstUsed.Equal(day1) {
		t.Errorf("root first_used = %s, want its NotBefore %s", r.FirstUsed, day1)
	}
	// On the first seed the log began with the root that was minted beside it.
	if !l.FirstUsed.Equal(day1) {
		t.Errorf("seeded log first_used = %s, want the root's %s", l.FirstUsed, day1)
	}
	if !h.Began().Equal(day1) {
		t.Errorf("Began = %s, want %s", h.Began(), day1)
	}

	// Recording the same material again is a no-op.
	if added, err := h.Record(KindFulcioRoot, root, now.Add(time.Hour)); err != nil || added {
		t.Errorf("a second Record of the same root = %v, %v; want not added", added, err)
	}
	// A log key first seen after the seed is dated when it was seen.
	later := logKeyPEM(t)
	if _, err := h.Record(KindTransparencyLog, later, now); err != nil {
		t.Fatal(err)
	}
	if got := h.Entries[2].FirstUsed; !got.Equal(now) {
		t.Errorf("a later log key's first_used = %s, want %s", got, now)
	}
}

func TestRecordRefusesMaterialThatIsNotItsKind(t *testing.T) {
	h := New()
	for _, c := range []struct {
		name string
		kind Kind
		pem  []byte
	}{
		{"a log key as a root", KindFulcioRoot, logKeyPEM(t)},
		{"a root as a log key", KindTransparencyLog, caPEM(t, "r", day1, ten)},
		{"not PEM", KindFulcioRoot, []byte("hello")},
		{"an unknown kind", Kind("ct_log"), logKeyPEM(t)},
		{"a broken certificate", KindGatewayCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{"a broken key", KindTransparencyLog, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})},
	} {
		if _, err := h.Record(c.kind, c.pem, day1); err == nil {
			t.Errorf("%s: Record accepted it", c.name)
		}
	}
	if len(h.Entries) != 0 {
		t.Errorf("a refused Record left %d entries behind", len(h.Entries))
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	h := New()
	if _, err := h.Record(KindFulcioRoot, caPEM(t, "A", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(KindTransparencyLog, logKeyPEM(t), day1); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, h); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Entries) != 2 || got.Entries[0].KeyID != h.Entries[0].KeyID {
		t.Errorf("round trip lost entries: %+v", got.Entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Public material only, readable by the services that verify with it.
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 0644", info.Mode().Perm())
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load of an absent file = %v, want os.ErrNotExist", err)
	}
}

// The file is append-only. Save is the one writer, and it refuses any history
// that drops, alters or un-revokes an entry the file already holds.
func TestSaveRefusesToRewriteHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	h := New()
	if _, err := h.Record(KindFulcioRoot, caPEM(t, "A", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(KindTransparencyLog, logKeyPEM(t), day1); err != nil {
		t.Fatal(err)
	}
	revoked := day1.AddDate(0, 1, 0)
	h.Entries[0].RevokedAt = &revoked
	if err := Save(path, h); err != nil {
		t.Fatal(err)
	}

	clone := func() *History {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := map[string]func(*History){
		"drops an entry":   func(c *History) { c.Entries = c.Entries[1:] },
		"moves first_used": func(c *History) { c.Entries[1].FirstUsed = c.Entries[1].FirstUsed.Add(time.Hour) },
		"swaps the key": func(c *History) {
			c.Entries[1].PublicPEM = string(logKeyPEM(t))
			c.Entries[1].KeyID = spkiID(t, []byte(c.Entries[1].PublicPEM))
		},
		"un-revokes a root":   func(c *History) { c.Entries[0].RevokedAt = nil },
		"moves a revocation":  func(c *History) { r := revoked.Add(time.Hour); c.Entries[0].RevokedAt = &r },
		"changes the tree id": func(c *History) { c.Entries[1].TreeID = "42" },
		"reorders entries":    func(c *History) { c.Entries[0], c.Entries[1] = c.Entries[1], c.Entries[0] },
	}
	for name, mutate := range cases {
		c := clone()
		mutate(c)
		if err := Save(path, c); !errors.Is(err, ErrRewrite) {
			t.Errorf("%s: Save = %v, want ErrRewrite", name, err)
		}
	}

	// What IS allowed: appending, and setting a retirement that was unset.
	c := clone()
	retired := day1.AddDate(0, 2, 0)
	c.Entries[1].RetiredAt = &retired
	c.Entries[1].RetiredReason = "rotated"
	if _, err := c.Record(KindFulcioRoot, caPEM(t, "B", retired, ten), retired); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, c); err != nil {
		t.Errorf("appending and retiring: Save = %v", err)
	}
	c = clone()
	c.Entries[1].RetiredAt = nil
	if err := Save(path, c); !errors.Is(err, ErrRewrite) {
		t.Errorf("un-retiring: Save = %v, want ErrRewrite", err)
	}
}

func TestParseRefusesAHistoryItCannotTrust(t *testing.T) {
	root := caPEM(t, "A", day1, ten)
	good := Entry{Kind: KindFulcioRoot, KeyID: spkiID(t, root), PublicPEM: string(root), FirstUsed: day1}
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := day1.Add(-time.Hour)
	cases := map[string][]byte{
		"not JSON":          []byte("{"),
		"wrong version":     encode(History{Version: 2, Entries: []Entry{good}}),
		"unknown member":    []byte(`{"version":1,"entries":[],"private_key":"x"}`),
		"trailing data":     append(encode(History{Version: 1, Entries: []Entry{good}}), []byte(" {}")...),
		"wrong key id":      encode(History{Version: 1, Entries: []Entry{{Kind: KindFulcioRoot, KeyID: strings.Repeat("0", 64), PublicPEM: string(root), FirstUsed: day1}}}),
		"no first_used":     encode(History{Version: 1, Entries: []Entry{{Kind: KindFulcioRoot, KeyID: good.KeyID, PublicPEM: string(root)}}}),
		"duplicate":         encode(History{Version: 1, Entries: []Entry{good, good}}),
		"revoked too early": encode(History{Version: 1, Entries: []Entry{{Kind: KindFulcioRoot, KeyID: good.KeyID, PublicPEM: string(root), FirstUsed: day1, RevokedAt: &before}}}),
		"retired too early": encode(History{Version: 1, Entries: []Entry{{Kind: KindFulcioRoot, KeyID: good.KeyID, PublicPEM: string(root), FirstUsed: day1, RetiredAt: &before}}}),
		"bad kind":          encode(History{Version: 1, Entries: []Entry{{Kind: "x", KeyID: good.KeyID, PublicPEM: string(root), FirstUsed: day1}}}),
		"a private key":     encode(History{Version: 1, Entries: []Entry{{Kind: KindTransparencyLog, KeyID: good.KeyID, PublicPEM: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", FirstUsed: day1}}}),
	}
	for name, raw := range cases {
		if _, err := Parse(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := Parse(encode(History{Version: 1, Entries: []Entry{good}})); err != nil {
		t.Errorf("the good history: %v", err)
	}
}

func TestAcceptsAtHonoursRetirementAndRevocation(t *testing.T) {
	skew := time.Minute
	retired := day1.AddDate(0, 1, 0)
	revoked := day1.AddDate(0, 2, 0)

	plain := Entry{FirstUsed: day1}
	if err := plain.AcceptsAt(day1.AddDate(5, 0, 0), skew); err != nil {
		t.Errorf("an entry with no end accepted nothing: %v", err)
	}

	ret := Entry{FirstUsed: day1, RetiredAt: &retired}
	if err := ret.AcceptsAt(retired.Add(-time.Hour), skew); err != nil {
		t.Errorf("retired root refused an entry from before its retirement: %v", err)
	}
	if err := ret.AcceptsAt(retired.Add(skew/2), skew); err != nil {
		t.Errorf("retired root refused an entry inside the skew bound: %v", err)
	}
	if err := ret.AcceptsAt(retired.Add(time.Hour), skew); err == nil {
		t.Error("a retired root accepted an entry integrated after it stopped issuing")
	}

	rev := Entry{FirstUsed: day1, RevokedAt: &revoked}
	if err := rev.AcceptsAt(revoked.Add(-time.Second), skew); err != nil {
		t.Errorf("a revoked root refused an entry integrated before revocation: %v", err)
	}
	// No skew for a revocation: it is a compromise, and the bound would be a
	// window for the attacker.
	if err := rev.AcceptsAt(revoked, skew); err == nil {
		t.Error("a revoked root accepted an entry integrated at its revocation")
	}
	if err := rev.AcceptsAt(revoked.Add(time.Second), skew); err == nil {
		t.Error("a revoked root accepted an entry integrated after its revocation")
	}
}

func TestLookupCurrentAndKinds(t *testing.T) {
	h := New()
	a := caPEM(t, "A", day1, ten)
	b := caPEM(t, "B", day1.AddDate(0, 0, 3), ten)
	if _, err := h.Record(KindFulcioRoot, a, day1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(KindFulcioRoot, b, day1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(KindGatewayCA, caPEM(t, "G", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	if got := len(h.OfKind(KindFulcioRoot)); got != 2 {
		t.Errorf("OfKind(fulcio_root) = %d, want 2", got)
	}
	if e, ok := h.Lookup(KindFulcioRoot, spkiID(t, a)); !ok || e.KeyID != spkiID(t, a) {
		t.Error("Lookup did not find root A")
	}
	if _, ok := h.Lookup(KindTransparencyLog, spkiID(t, a)); ok {
		t.Error("Lookup found a root under the log kind")
	}
	cur, ok := h.Current(KindFulcioRoot)
	if !ok || cur.KeyID != spkiID(t, b) {
		t.Errorf("Current(fulcio_root) = %s, want the later root B", cur.KeyID)
	}
	if _, ok := h.Current(KindSPIREUpstreamCA); ok {
		t.Error("Current found an upstream CA that was never recorded")
	}
	// The gateway CA is a CA in use; it does not move when the history began.
	if !h.Began().Equal(day1) {
		t.Errorf("Began = %s", h.Began())
	}
	if !New().Began().IsZero() {
		t.Error("an empty history has a beginning")
	}
	var nilHistory *History
	if len(nilHistory.OfKind(KindFulcioRoot)) != 0 || !nilHistory.Began().IsZero() {
		t.Error("a nil history is not empty")
	}
}

func TestTheEdgesOfReadingAndWriting(t *testing.T) {
	dir := t.TempDir()

	// KeyIDOf and Certificate refuse what is not their material.
	if _, err := KeyIDOf([]byte("junk")); !errors.Is(err, ErrInvalid) {
		t.Errorf("KeyIDOf(junk) = %v", err)
	}
	if _, err := (Entry{PublicPEM: "junk"}).Certificate(); err == nil {
		t.Error("Certificate of junk")
	}
	if _, err := (Entry{PublicPEM: string(logKeyPEM(t))}).Certificate(); err == nil {
		t.Error("Certificate of a log key")
	}

	// A history with no entries member is an empty one.
	h, err := Parse([]byte(`{"version":1}`))
	if err != nil || h.Entries == nil || len(h.Entries) != 0 {
		t.Errorf("Parse with no entries = %+v, %v", h, err)
	}

	// Load says which file was damaged.
	damaged := filepath.Join(dir, "damaged.json")
	if err := os.WriteFile(damaged, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(damaged); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), damaged) {
		t.Errorf("Load(damaged) = %v", err)
	}

	good := New()
	if _, err := good.Record(KindFulcioRoot, caPEM(t, "A", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	// Save refuses an invalid history, refuses to write over a file it cannot
	// read (that file may be the only record), and reports a place it cannot
	// write.
	if err := Save(filepath.Join(dir, "x.json"), &History{Version: 9}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Save(invalid) = %v", err)
	}
	if err := Save(damaged, good); !errors.Is(err, ErrInvalid) {
		t.Errorf("Save over a damaged file = %v, want it refused", err)
	}
	if raw, rerr := os.ReadFile(damaged); rerr != nil || string(raw) != "{" {
		t.Errorf("the damaged file was overwritten: %q, %v", raw, rerr)
	}
	if err := Save(filepath.Join(dir, "absent", FileName), good); err == nil {
		t.Error("Save into a directory that does not exist")
	}
	if err := Save(dir, good); err == nil {
		t.Error("Save over a directory")
	}
	root := caPEM(t, "A", day1, ten)
	if id, err := KeyIDOf(root); err != nil || id != spkiID(t, root) {
		t.Errorf("KeyIDOf(root) = %s, %v", id, err)
	}
}

func TestCurrentSkipsRevokedAndKeepsTheLatest(t *testing.T) {
	h := New()
	later := caPEM(t, "B", day1.AddDate(0, 0, 3), ten)
	if _, err := h.Record(KindFulcioRoot, later, day1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(KindFulcioRoot, caPEM(t, "A", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	if cur, _ := h.Current(KindFulcioRoot); cur.KeyID != spkiID(t, later) {
		t.Error("Current did not keep the later root when an earlier one followed it")
	}
	revoked := day1.AddDate(0, 0, 4)
	h.Entries[0].RevokedAt = &revoked
	if cur, _ := h.Current(KindFulcioRoot); cur.KeyID == spkiID(t, later) {
		t.Error("Current returned a revoked root")
	}
}

func TestExpiriesSkipsWhatIsAbsentOrUnreadable(t *testing.T) {
	h := New()
	if _, err := h.Record(KindFulcioRoot, caPEM(t, "A", day1, ten), day1); err != nil {
		t.Fatal(err)
	}
	// An in-memory entry whose material is not a certificate: never written
	// by Record, and never shown with an invented date.
	h.Entries = append(h.Entries, Entry{Kind: KindGatewayCA, KeyID: "x", PublicPEM: "junk", FirstUsed: day1})
	got := Expiries(h, day1)
	if len(got) != 1 || got[0].Kind != KindFulcioRoot {
		t.Errorf("Expiries = %+v, want the Fulcio root alone", got)
	}
}
