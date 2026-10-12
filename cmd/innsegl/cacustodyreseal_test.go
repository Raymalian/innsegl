// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
)

// ---------------------------------------------------------------------------
// CLI-053 (PROPOSED for doc 07's TC-CLI) — `innsegl ca-custody reseal` and
// `recipients` on the operator's machine (#614, ADR-0082 decision 7). The
// command shows the current set, the new set and its digest, and asks; on
// anything but yes nothing is opened and nothing is sent. It refuses an
// empty set and a set without this machine before any Touch ID. It refuses
// to confirm a staged copy sealed to another set than the one shown.
// ---------------------------------------------------------------------------

// stagingCustodian answers the custodian's reseal routes as the real one
// does, over a set it keeps: the material sealed to it, a staged copy with a
// check inside, and a confirm that swaps it in.
type stagingCustodian struct {
	mu        sync.Mutex
	m         cacustody.Material
	set       []string
	sealed    []byte
	fetches   int
	reseals   []cacustody.ResealRequest
	confirms  []cacustody.ResealConfirm
	staged    []string
	check     string
	stageSet  []string // when set, the staged copy claims this set instead
	recordSet bool
}

func newStagingCustodian(t *testing.T, ids ...*age.X25519Identity) *stagingCustodian {
	t.Helper()
	m := cacustody.Material{UnsealKey: "unseal-key-value", RoleID: "role", SecretID: "secret-id-value",
		BackupRoleID: "backup-role", BackupSecretID: "backup-secret-value"}
	var set []string
	var rs []age.Recipient
	for _, id := range ids {
		set = append(set, id.Recipient().String())
		rs = append(rs, id.Recipient())
	}
	sealed, err := cacustody.Seal(m, rs)
	if err != nil {
		t.Fatal(err)
	}
	return &stagingCustodian{m: m, set: set, sealed: sealed, recordSet: true}
}

func sealPlain(t *testing.T, v any, set []string) []byte {
	t.Helper()
	var rs []age.Recipient
	for _, s := range set {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (c *stagingCustodian) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(cacustody.PathStatus, func(w http.ResponseWriter, _ *http.Request) {
		writeCoreJSON(w, http.StatusOK, cacustody.Status{Initialized: true, CanSign: true})
	})
	mux.HandleFunc(cacustody.PathRecipients, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		writeCoreJSON(w, http.StatusOK, cacustody.RecipientSet{Recipients: c.set,
			Digest: cacustody.SetDigest(c.set), Recorded: c.recordSet})
	})
	mux.HandleFunc(cacustody.PathMaterial, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.fetches++
		if _, err := w.Write(c.sealed); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc(cacustody.PathReseal, func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		var req cacustody.ResealRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Material != c.m {
			writeCoreError(w, http.StatusForbidden, "ca custody: the unlock material was not accepted")
			return
		}
		c.reseals = append(c.reseals, req)
		c.staged, c.check = req.Recipients, "the-staged-check"
		claimed := req.Recipients
		if c.stageSet != nil {
			claimed = c.stageSet
		}
		sealed := sealPlain(t, struct {
			cacustody.Material
			Check string `json:"reseal_check"`
		}{c.m, c.check}, req.Recipients)
		writeCoreJSON(w, http.StatusOK, cacustody.ResealStaged{Sealed: sealed, Recipients: claimed,
			SetDigest: cacustody.SetDigest(claimed)})
	})
	mux.HandleFunc(cacustody.PathResealConfirm, func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		var req cacustody.ResealConfirm
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeCoreError(w, http.StatusBadRequest, "unreadable")
			return
		}
		c.confirms = append(c.confirms, req)
		if req.Check != c.check || req.Material != c.m || req.SetDigest != cacustody.SetDigest(c.staged) {
			writeCoreError(w, http.StatusForbidden, cacustody.ErrNotOpened.Error())
			return
		}
		c.set = c.staged
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// resealFixture is an enrolled, served operator machine whose core carries
// the custody routes to custodian, under the core's real custody limit: a
// reseal must fit in it.
func resealFixture(t *testing.T, custodian string) *connectFixture {
	t.Helper()
	return resealFixtureLimited(t, custodian, newCustodyLimiter(nil))
}

func resealFixtureLimited(t *testing.T, custodian string, limit *backupLimiter) *connectFixture {
	t.Helper()
	f := newConnectFixture(t)
	f.connectServed(t, nil)
	h := caCustodyHandler(custodian, operatorMachine(), limit, newServeLog(io.Discard))
	f.core.Mux.Handle(coreCACustodyPath, withInstallation("inst-1", h))
	f.core.Mux.Handle(coreCACustodyPath+"/", withInstallation("inst-1", h))
	return f
}

func identityFile(t *testing.T, id *age.X25519Identity) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func runReseal(t *testing.T, f *connectFixture, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runCACustodyIO(t.Context(), args, strings.NewReader(stdin), &out, &out, f.home)
	return code, out.String()
}

func TestCLI053ResealShowsTheSetsAndStopsOnNo(t *testing.T) {
	mine, second := newIdentity(t), newIdentity(t)
	c := newStagingCustodian(t, mine)
	f := resealFixture(t, c.server(t).URL)
	idFile := identityFile(t, mine)
	r1, r2 := mine.Recipient().String(), second.Recipient().String()

	code, out := runReseal(t, f, "", "recipients")
	if code != exitOK || !strings.Contains(out, r1) || !strings.Contains(out, cacustody.SetDigest([]string{r1})) {
		t.Fatalf("recipients: exit %d\n%s", code, out)
	}

	newSet := []string{r1, r2}
	code, out = runReseal(t, f, "n\n", "reseal", "--add", r2, "--identity", idFile)
	if code == exitOK {
		t.Fatalf("a declined reseal exited 0:\n%s", out)
	}
	for _, want := range []string{r1, r2, cacustody.SetDigest(newSet), cacustody.SetDigest([]string{r1}), "nothing changed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the declined reseal does not show %q:\n%s", want, out)
		}
	}
	if c.fetches != 0 || len(c.reseals) != 0 {
		t.Fatalf("a declined reseal fetched the material %d times and sent %d reseals", c.fetches, len(c.reseals))
	}

	// Refused before anything is opened: an empty set, a set without this
	// machine, a recipient that is none.
	setFile := filepath.Join(t.TempDir(), "set.txt")
	if err := os.WriteFile(setFile, []byte("# only the other one\n"+r2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"empty":         {"reseal", "--remove", r1, "--identity", idFile},
		"without me":    {"reseal", "--set", setFile, "--identity", idFile},
		"not a key":     {"reseal", "--add", "age1notarecipient", "--identity", idFile},
		"no change":     {"reseal", "--add", r1, "--identity", idFile},
		"add and set":   {"reseal", "--add", r2, "--set", setFile, "--identity", idFile},
		"nothing asked": {"reseal", "--identity", idFile},
	} {
		code, out := runReseal(t, f, "y\n", args...)
		if name == "no change" {
			if code != exitOK || !strings.Contains(out, "unchanged") {
				t.Errorf("%s: exit %d\n%s", name, code, out)
			}
		} else if code == exitOK {
			t.Errorf("%s: exit 0\n%s", name, out)
		}
	}
	if c.fetches != 0 || len(c.reseals) != 0 {
		t.Fatalf("a refused reseal fetched the material %d times and sent %d reseals", c.fetches, len(c.reseals))
	}
}

func TestCLI053ResealAppliesTheConfirmedSetAndNoOther(t *testing.T) {
	mine, second := newIdentity(t), newIdentity(t)
	c := newStagingCustodian(t, mine)
	f := resealFixture(t, c.server(t).URL)
	idFile := identityFile(t, mine)
	r1, r2 := mine.Recipient().String(), second.Recipient().String()

	// The custodian claims to have staged another set: no confirm is sent.
	c.stageSet = []string{r2}
	code, out := runReseal(t, f, "y\n", "reseal", "--add", r2, "--identity", idFile)
	if code == exitOK || len(c.confirms) != 0 || !strings.Contains(out, "not the one confirmed") {
		t.Fatalf("a staged copy for another set: exit %d, %d confirms\n%s", code, len(c.confirms), out)
	}

	c.stageSet = nil
	code, out = runReseal(t, f, "yes\n", "reseal", "--add", r2, "--identity", idFile)
	if code != exitOK {
		t.Fatalf("reseal: exit %d\n%s", code, out)
	}
	newSet := []string{r1, r2}
	last := c.reseals[len(c.reseals)-1]
	if last.Opener != r1 || last.SetDigest != cacustody.SetDigest(newSet) || last.Material != c.m {
		t.Fatalf("the reseal sent opener %q digest %q", last.Opener, last.SetDigest)
	}
	if len(c.confirms) != 1 || c.confirms[0].Check != "the-staged-check" {
		t.Fatalf("confirms: %+v", c.confirms)
	}
	if !strings.Contains(out, "resealed") || !strings.Contains(out, "backups") {
		t.Fatalf("the result does not say it resealed and what backups now do:\n%s", out)
	}
	for _, secret := range []string{c.m.UnsealKey, c.m.SecretID, "the-staged-check"} {
		if strings.Contains(out, secret) {
			t.Fatal("the command printed unlock material")
		}
	}
	if code, out = runReseal(t, f, "", "recipients"); !strings.Contains(out, r2) {
		t.Fatalf("recipients after the reseal: exit %d\n%s", code, out)
	}
}
