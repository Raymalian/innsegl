// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
)

// `innsegl trust-history` is what scripts/ca-rotate.sh runs inside the core
// to read and end entries in the trust history (#533). Its exit status is
// the script's only signal, so every outcome below is asserted by status.

func thRoot(t *testing.T, notBefore time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func runTH(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runTrustHistory(args, bytes.NewReader(stdin), &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestTrustHistoryRecordHasAndEnd(t *testing.T) {
	file := filepath.Join(t.TempDir(), trusthistory.FileName)
	began := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	root := thRoot(t, began)
	id, err := trusthistory.KeyIDOf(root)
	if err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := runTH(t, root, "has", "--file", file, "--kind", "fulcio_root"); code != exitTrustHistoryError {
		t.Fatalf("has with no history yet: exit %d (%s), want %d", code, stderr, exitTrustHistoryError)
	}
	code, out, stderr := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root")
	if code != exitOK || !strings.Contains(out, "recorded fulcio_root "+id) {
		t.Fatalf("record: exit %d out %q err %q", code, out, stderr)
	}
	if c, o, _ := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root"); c != exitOK ||
		!strings.Contains(o, "already holds fulcio_root "+id) {
		code, out = c, o
		t.Fatalf("a second record: exit %d out %q", code, out)
	}
	if c, o, _ := runTH(t, root, "has", "--file", file, "--kind", "fulcio_root"); c != exitOK || strings.TrimSpace(o) != id {
		code, out = c, o
		t.Fatalf("has: exit %d out %q; want 0 and the key id", code, out)
	}
	other := thRoot(t, began)
	if c, _, _ := runTH(t, other, "has", "--file", file, "--kind", "fulcio_root"); c != exitTrustHistoryAbsent {
		code = c
		t.Fatalf("has for a root it does not hold: exit %d, want %d", code, exitTrustHistoryAbsent)
	}

	at := began.AddDate(0, 1, 0).Format(time.RFC3339)
	code, out, stderr = runTH(t, nil, "end", "--file", file, "--kind", "fulcio_root", "--key-id", id,
		"--mode", "revoke", "--at", at, "--reason", "key may be exposed")
	if code != exitOK || !strings.Contains(out, "revoked fulcio_root "+id+" at "+at) {
		t.Fatalf("end: exit %d out %q err %q", code, out, stderr)
	}
	h, err := trusthistory.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := h.Lookup(trusthistory.KindFulcioRoot, id)
	if e.RevokedAt == nil || e.RevokedAt.Format(time.RFC3339) != at {
		t.Fatalf("the file holds revoked_at %v, want %s", e.RevokedAt, at)
	}
	// A second end is refused, and the file is left as it was.
	if code, _, _ := runTH(t, nil, "end", "--file", file, "--kind", "fulcio_root", "--key-id", id,
		"--mode", "revoke", "--at", at, "--reason", "again"); code != exitTrustHistoryError {
		t.Fatalf("a second revoke: exit %d, want %d", code, exitTrustHistoryError)
	}
}

func TestTrustHistoryReadsTheFileFromTheEnvironment(t *testing.T) {
	file := filepath.Join(t.TempDir(), trusthistory.FileName)
	root := thRoot(t, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	env := func(k string) string {
		if k == "INNSEGL_TRUST_HISTORY" {
			return file
		}
		return ""
	}
	var out, errb bytes.Buffer
	if code := runTrustHistory([]string{"record", "--kind", "fulcio_root"}, bytes.NewReader(root), &out, &errb, env); code != exitOK {
		t.Fatalf("record via INNSEGL_TRUST_HISTORY: exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("no history at $INNSEGL_TRUST_HISTORY: %v", err)
	}
}

func TestTrustHistoryRefusesWhatItCannotDo(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, trusthistory.FileName)
	root := thRoot(t, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if code, _, _ := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root"); code != exitOK {
		t.Fatal("seeding the history")
	}
	id := mustKeyID(t, root)
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := "2026-10-07T12:00:00Z"
	cases := []struct {
		name  string
		stdin []byte
		args  []string
		want  int
	}{
		{"no verb", nil, nil, exitUsage},
		{"help", nil, []string{"-h"}, exitOK},
		{"a verb's help", nil, []string{"end", "-h"}, exitOK},
		{"an unknown verb", nil, []string{"forget"}, exitUsage},
		{"an unknown flag", nil, []string{"has", "--nope"}, exitUsage},
		{"a stray argument", root, []string{"has", "--file", file, "--kind", "fulcio_root", "extra"}, exitUsage},
		{"no file", root, []string{"has", "--kind", "fulcio_root"}, exitUsage},
		{"no kind", root, []string{"has", "--file", file}, exitUsage},
		{"an unknown kind", root, []string{"record", "--file", file, "--kind", "nope"}, exitTrustHistoryError},
		{"stdin that is not PEM", []byte("hello"), []string{"has", "--file", file, "--kind", "fulcio_root"}, exitTrustHistoryError},
		{"record stdin that is not PEM", []byte("hello"), []string{"record", "--file", file, "--kind", "fulcio_root"}, exitTrustHistoryError},
		{"has on a history that does not parse", root, []string{"has", "--file", garbage, "--kind", "fulcio_root"}, exitTrustHistoryError},
		{"record into a history that does not parse", root, []string{"record", "--file", garbage, "--kind", "fulcio_root"}, exitTrustHistoryError},
		{"record where the file cannot be written", root, []string{"record", "--file", filepath.Join(dir, "no", "such", "dir", "h.json"), "--kind", "fulcio_root"}, exitTrustHistoryError},
		{"end with no key id", nil, []string{"end", "--file", file, "--kind", "fulcio_root", "--mode", "retire", "--at", at, "--reason", "r"}, exitUsage},
		{"end with a time that does not parse", nil, []string{"end", "--file", file, "--kind", "fulcio_root", "--key-id", id, "--mode", "retire", "--at", "yesterday", "--reason", "r"}, exitUsage},
		{"end with an unknown mode", nil, []string{"end", "--file", file, "--kind", "fulcio_root", "--key-id", id, "--mode", "forget", "--at", at, "--reason", "r"}, exitTrustHistoryError},
		{"end for a root it does not hold", nil, []string{"end", "--file", file, "--kind", "fulcio_root", "--key-id", "00", "--mode", "retire", "--at", at, "--reason", "r"}, exitTrustHistoryError},
		{"end on a history that does not parse", nil, []string{"end", "--file", garbage, "--kind", "fulcio_root", "--key-id", id, "--mode", "retire", "--at", at, "--reason", "r"}, exitTrustHistoryError},
		{"end on a history that does not exist", nil, []string{"end", "--file", filepath.Join(dir, "absent.json"), "--kind", "fulcio_root", "--key-id", id, "--mode", "retire", "--at", at, "--reason", "r"}, exitTrustHistoryError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, stderr := runTH(t, tc.stdin, tc.args...); code != tc.want {
				t.Fatalf("exit %d (%s), want %d", code, stderr, tc.want)
			}
		})
	}
}

// Save refuses a write that would rewrite history; `end` passes that refusal
// on as a refusal, not as success.
func TestTrustHistoryEndReportsAFailedSave(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, trusthistory.FileName)
	root := thRoot(t, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if code, _, _ := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root"); code != exitOK {
		t.Fatal("seeding the history")
	}
	id := mustKeyID(t, root)
	// The temporary file Save writes beside the history is a directory, so
	// the write fails after End itself succeeded.
	if err := os.Mkdir(file+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runTH(t, nil, "end", "--file", file, "--kind", "fulcio_root", "--key-id", id,
		"--mode", "retire", "--at", "2026-10-07T12:00:00Z", "--reason", "r"); code != exitTrustHistoryError {
		t.Fatalf("end with a failing save: exit %d, want %d", code, exitTrustHistoryError)
	}
}

func TestTrustHistoryIsASubcommand(t *testing.T) {
	if _, ok := commands["trust-history"]; !ok {
		t.Fatal("innsegl has no trust-history subcommand")
	}
}

func mustKeyID(t *testing.T, pemBytes []byte) string {
	t.Helper()
	id, err := trusthistory.KeyIDOf(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// errReader is stdin that fails, as a broken `docker exec -i` pipe would.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("the pipe broke") }

// A stdin that cannot be read is an error, never an empty answer.
func TestTrustHistoryRefusesAStdinItCannotRead(t *testing.T) {
	file := filepath.Join(t.TempDir(), trusthistory.FileName)
	root := thRoot(t, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if code, _, _ := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root"); code != exitOK {
		t.Fatal("seeding the history")
	}
	for _, verb := range []string{"has", "record"} {
		var out, errb bytes.Buffer
		code := runTrustHistory([]string{verb, "--file", file, "--kind", "fulcio_root"}, errReader{}, &out, &errb,
			func(string) string { return "" })
		if code != exitTrustHistoryError || !strings.Contains(errb.String(), "the pipe broke") {
			t.Errorf("%s with a broken stdin: exit %d (%s), want %d", verb, code, errb.String(), exitTrustHistoryError)
		}
	}
}

// A planned rotation retires, and says so.
func TestTrustHistoryEndRetires(t *testing.T) {
	file := filepath.Join(t.TempDir(), trusthistory.FileName)
	root := thRoot(t, time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	if code, _, _ := runTH(t, root, "record", "--file", file, "--kind", "fulcio_root"); code != exitOK {
		t.Fatal("seeding the history")
	}
	id := mustKeyID(t, root)
	code, out, stderr := runTH(t, nil, "end", "--file", file, "--kind", "fulcio_root", "--key-id", id,
		"--mode", "retire", "--at", "2026-10-07T12:00:00Z", "--reason", "planned")
	if code != exitOK || !strings.Contains(out, "retired fulcio_root "+id) {
		t.Fatalf("retire: exit %d out %q err %q", code, out, stderr)
	}
	e, _ := loadTH(t, file).Lookup(trusthistory.KindFulcioRoot, id)
	if e.RetiredAt == nil || e.RevokedAt != nil {
		t.Fatalf("retire wrote retired_at %v revoked_at %v", e.RetiredAt, e.RevokedAt)
	}
}

func loadTH(t *testing.T, file string) *trusthistory.History {
	t.Helper()
	h, err := trusthistory.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
