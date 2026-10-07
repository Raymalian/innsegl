// SPDX-License-Identifier: Apache-2.0

package trustwatch

import (
	"context"
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
	"innsegl.dev/innsegl/internal/verify"
)

var (
	began = time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	today = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
)

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

func keyPEM(t *testing.T) []byte {
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

func static(b []byte) Source {
	return func(context.Context) ([][]byte, error) { return [][]byte{b}, nil }
}

// world is one deployment's trust material and the commits it holds.
type world struct {
	root, logKey, gateway []byte
	dir                   string
	verdicts              map[string]verify.Verdict
	verifyErr             error
	seenHistory           *trusthistory.History
	verified              []string
	at                    time.Time
}

func (w *world) now() time.Time {
	if w.at.IsZero() {
		return today
	}
	return w.at
}

func (w *world) rootID() string {
	id, err := trusthistory.KeyIDOf(w.root)
	if err != nil {
		panic(err)
	}
	return id
}

func newWorld(t *testing.T) *world {
	return &world{
		root:     caPEM(t, "root B", began, time.Date(2036, 9, 13, 0, 0, 0, 0, time.UTC)),
		logKey:   keyPEM(t),
		gateway:  caPEM(t, "gateway", began, time.Date(2036, 9, 27, 0, 0, 0, 0, time.UTC)),
		dir:      t.TempDir(),
		verdicts: map[string]verify.Verdict{},
	}
}

func (w *world) config() Config {
	return Config{
		HistoryFile:   filepath.Join(w.dir, trusthistory.FileName),
		SentinelsFile: filepath.Join(w.dir, SentinelsFileName),
		Sources: map[trusthistory.Kind]Source{
			trusthistory.KindFulcioRoot:      static(w.root),
			trusthistory.KindTransparencyLog: static(w.logKey),
			trusthistory.KindGatewayCA:       static(w.gateway),
		},
		RepoDir: func(repo string) (string, error) {
			if repo == "github.com/o/gone" {
				return "", errors.New("not held")
			}
			return "/mirror/" + repo, nil
		},
		Verify: func(_ context.Context, h *trusthistory.History, dir, sha string) (Outcome, error) {
			w.seenHistory = h
			w.verified = append(w.verified, sha)
			if w.verifyErr != nil {
				return Outcome{}, w.verifyErr
			}
			out := Outcome{Verdict: w.verdicts[sha]}
			if out.Verdict == verify.VerdictVerified {
				out.RootKeyID = w.rootID()
			}
			return out, nil
		},
		Now: func() time.Time { return w.now() },
	}
}

func (w *world) sentinels(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.dir, SentinelsFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	shaOld = "1111111111111111111111111111111111111111"
	shaNew = "2222222222222222222222222222222222222222"
)

const twoEras = `{"version":1,"sentinels":[
 {"era":"before 2026-09-16","repo":"github.com/o/r","commit":"` + shaOld + `","expect":"pre-history"},
 {"era":"root B","repo":"github.com/o/r","commit":"` + shaNew + `","expect":"verified"}]}`

// The first pass on an existing deployment seeds its history from what it
// uses now. No step for the operator: the next start does it.
func TestTheFirstPassSeedsTheHistoryFromTheMaterialInUse(t *testing.T) {
	w := newWorld(t)
	w.sentinels(t, twoEras)
	w.verdicts[shaOld] = verify.VerdictPreHistory
	w.verdicts[shaNew] = verify.VerdictVerified

	res := New(w.config()).Pass(t.Context())
	if res.Err != nil {
		t.Fatalf("Pass: %v", res.Err)
	}
	if len(res.Recorded) != 3 {
		t.Fatalf("recorded %d entries, want the root, the log key and the gateway CA", len(res.Recorded))
	}
	h, err := trusthistory.Load(filepath.Join(w.dir, trusthistory.FileName))
	if err != nil {
		t.Fatalf("the history was not written: %v", err)
	}
	if !h.Began().Equal(began) {
		t.Errorf("the seeded history begins %s, want the root's NotBefore %s", h.Began(), began)
	}
	if w.seenHistory == nil || len(w.seenHistory.Entries) != 3 {
		t.Error("the sentinels were not verified against the history just written")
	}
	if alerts := res.Alerts(); len(alerts) != 0 {
		t.Errorf("a healthy deployment raised alerts: %q", alerts)
	}

	// The second pass records nothing new and rewrites nothing.
	again := New(w.config()).Pass(t.Context())
	if again.Err != nil || len(again.Recorded) != 0 {
		t.Errorf("second pass: recorded %d, err %v", len(again.Recorded), again.Err)
	}
}

// 2026-09-16, replayed: the root changes under a deployment that has sentinels.
// The old era's sentinel stops verifying, and the canary says so the same day.
func TestASentinelThatStopsVerifyingRaisesAnAlert(t *testing.T) {
	w := newWorld(t)
	w.sentinels(t, twoEras)
	w.verdicts[shaOld] = verify.VerdictPreHistory
	w.verdicts[shaNew] = verify.VerdictFailed

	res := New(w.config()).Pass(t.Context())
	alerts := strings.Join(res.Alerts(), "\n")
	if !strings.Contains(alerts, shaNew) || !strings.Contains(alerts, "root B") ||
		!strings.Contains(alerts, "failed") {
		t.Errorf("the alert does not name the sentinel, its era and its verdict:\n%s", alerts)
	}
	if strings.Contains(alerts, shaOld) {
		t.Errorf("the sentinel that matched its expectation was alerted on:\n%s", alerts)
	}
}

func TestASentinelThatCannotBeCheckedIsAnAlertToo(t *testing.T) {
	w := newWorld(t)
	w.sentinels(t, `{"version":1,"sentinels":[
	 {"era":"a","repo":"github.com/o/gone","commit":"`+shaOld+`","expect":"verified"},
	 {"era":"b","repo":"github.com/o/r","commit":"`+shaNew+`","expect":"verified"}]}`)
	w.verifyErr = errors.New("no such commit")
	alerts := strings.Join(New(w.config()).Pass(t.Context()).Alerts(), "\n")
	if !strings.Contains(alerts, "not held") || !strings.Contains(alerts, "no such commit") {
		t.Errorf("the alerts do not say why each sentinel could not be checked:\n%s", alerts)
	}
}

// No sentinel list is not an alarm: until one is auto-selected, each era
// without a sentinel is reported as information.
func TestNoSentinelsIsInformationNotAnAlert(t *testing.T) {
	w := newWorld(t)
	res := New(w.config()).Pass(t.Context())
	for _, a := range res.Alerts() {
		if strings.Contains(a, "sentinel") {
			t.Errorf("no sentinels raised an alert: %q", a)
		}
	}
	info := strings.Join(res.Info, "\n")
	if !strings.Contains(info, "no sentinel yet for era "+w.rootID()) {
		t.Errorf("the era without a sentinel is not named:\n%s", info)
	}
}

func TestABrokenSentinelsFileIsAnAlertNotASilentPass(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":       "{",
		"wrong version":  `{"version":2,"sentinels":[]}`,
		"unknown member": `{"version":1,"sentinels":[],"x":1}`,
		"bad commit":     `{"version":1,"sentinels":[{"era":"a","repo":"r","commit":"xyz","expect":"verified"}]}`,
		"no repo":        `{"version":1,"sentinels":[{"era":"a","repo":"","commit":"` + shaOld + `","expect":"verified"}]}`,
		"bad expect":     `{"version":1,"sentinels":[{"era":"a","repo":"r","commit":"` + shaOld + `","expect":"failed"}]}`,
		"trailing":       `{"version":1,"sentinels":[]} {}`,
	} {
		w := newWorld(t)
		w.sentinels(t, body)
		res := New(w.config()).Pass(t.Context())
		if !strings.Contains(strings.Join(res.Alerts(), "\n"), "sentinel") {
			t.Errorf("%s: no alert: %q", name, res.Alerts())
		}
	}
}

func TestAnExpiringCAIsWarnedAbout(t *testing.T) {
	w := newWorld(t)
	w.sentinels(t, twoEras)
	w.verdicts[shaOld] = verify.VerdictPreHistory
	w.verdicts[shaNew] = verify.VerdictVerified
	w.gateway = caPEM(t, "gateway", began, today.AddDate(0, 0, 60))
	res := New(w.config()).Pass(t.Context())
	alerts := strings.Join(res.Alerts(), "\n")
	if !strings.Contains(alerts, "gateway CA") || !strings.Contains(alerts, "90 days") {
		t.Errorf("no 90-day warning for the gateway CA:\n%s", alerts)
	}
}

func TestASourceThatFailsDoesNotStopTheOthers(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	cfg.Sources[trusthistory.KindSPIREUpstreamCA] = func(context.Context) ([][]byte, error) {
		return nil, errors.New("the workload API is not answering")
	}
	cfg.Sources[trusthistory.KindGatewayCA] = static([]byte("not pem"))
	res := New(cfg).Pass(t.Context())
	if len(res.Recorded) != 2 {
		t.Errorf("recorded %d, want the root and the log key", len(res.Recorded))
	}
	alerts := strings.Join(res.Alerts(), "\n")
	if !strings.Contains(alerts, "workload API") || !strings.Contains(alerts, "gateway_ca") {
		t.Errorf("the failing sources are not named:\n%s", alerts)
	}
}

func TestAHistoryThatCannotBeReadIsNeverOverwritten(t *testing.T) {
	w := newWorld(t)
	path := filepath.Join(w.dir, trusthistory.FileName)
	if err := os.WriteFile(path, []byte("{damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := New(w.config()).Pass(t.Context())
	if res.Err == nil {
		t.Fatal("a damaged history was not reported")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{damaged" {
		t.Errorf("the damaged history was overwritten: %q", raw)
	}
	if !strings.Contains(strings.Join(res.Alerts(), "\n"), "trust history") {
		t.Errorf("the alerts do not name the trust history: %q", res.Alerts())
	}

	// A history that cannot be written is reported too.
	w2 := newWorld(t)
	cfg := w2.config()
	cfg.HistoryFile = filepath.Join(w2.dir, "no-such-dir", trusthistory.FileName)
	if res := New(cfg).Pass(t.Context()); res.Err == nil {
		t.Error("an unwritable history was not reported")
	}
}

// The daily pass picks a sentinel for each era that has none: a recent commit
// that verifies under that era's root. It is kept, append-only, and checked on
// every pass after.
func TestTheFirstVerifiedCommitOfAnEraBecomesItsSentinel(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	cfg.AutoSentinelsFile = filepath.Join(w.dir, AutoSentinelsFileName)
	cfg.Candidates = func(context.Context) ([]Candidate, error) {
		return []Candidate{{Repo: "github.com/o/r", Commit: shaOld}, {Repo: "github.com/o/r", Commit: shaNew}}, nil
	}
	w.verdicts[shaOld] = verify.VerdictFailed
	w.verdicts[shaNew] = verify.VerdictVerified

	res := New(cfg).Pass(t.Context())
	if len(res.Selected) != 1 || res.Selected[0].Commit != shaNew || res.Selected[0].Era != w.rootID() {
		t.Fatalf("selected %+v, want %s for era %s", res.Selected, shaNew, w.rootID())
	}
	if len(res.Info) != 0 || len(res.Alerts()) != 0 {
		t.Errorf("info %q, alerts %q after an era got its sentinel", res.Info, res.Alerts())
	}
	auto, err := LoadSentinels(cfg.AutoSentinelsFile)
	if err != nil || len(auto.Sentinels) != 1 {
		t.Fatalf("the auto-selected sentinel was not kept: %+v, %v", auto, err)
	}

	// Next pass: the sentinel is checked, nothing new is selected, and a
	// sentinel that stops verifying is an alert.
	w.verified = nil
	w.verdicts[shaNew] = verify.VerdictFailed
	res = New(cfg).Pass(t.Context())
	if len(res.Selected) != 0 {
		t.Errorf("selected again: %+v", res.Selected)
	}
	if a := strings.Join(res.Alerts(), "\n"); !strings.Contains(a, shaNew) {
		t.Errorf("the auto-selected sentinel's failure is not an alert:\n%s", a)
	}

	// A list that cannot be read is never overwritten, and says so.
	if err := os.WriteFile(cfg.AutoSentinelsFile, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = New(cfg).Pass(t.Context())
	if raw, rerr := os.ReadFile(cfg.AutoSentinelsFile); rerr != nil || string(raw) != "{" {
		t.Errorf("a damaged auto-sentinel list was overwritten: %q", raw)
	}
	if a := strings.Join(res.Alerts(), "\n"); !strings.Contains(a, "sentinel") {
		t.Errorf("a damaged auto-sentinel list is not reported:\n%s", a)
	}
}

func TestASelectedSentinelThatCannotBeKeptIsSaid(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	cfg.AutoSentinelsFile = filepath.Join(w.dir, "absent", AutoSentinelsFileName)
	cfg.Candidates = func(context.Context) ([]Candidate, error) {
		return []Candidate{{Repo: "github.com/o/r", Commit: shaNew}}, nil
	}
	w.verdicts[shaNew] = verify.VerdictVerified
	res := New(cfg).Pass(t.Context())
	if !strings.Contains(strings.Join(res.Info, "\n"), "could not be kept") {
		t.Errorf("info = %q", res.Info)
	}
}

func TestCandidatesThatCannotBeListedOrVerifiedLeaveTheEraOpen(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	cfg.AutoSentinelsFile = filepath.Join(w.dir, AutoSentinelsFileName)
	cfg.Candidates = func(context.Context) ([]Candidate, error) { return nil, errors.New("mirror unreadable") }
	res := New(cfg).Pass(t.Context())
	if !strings.Contains(strings.Join(res.Info, "\n"), "mirror unreadable") {
		t.Errorf("the candidate error is not reported: %q", res.Info)
	}
	many := make([]Candidate, maxCandidates+5)
	for i := range many {
		many[i] = Candidate{Repo: "github.com/o/r", Commit: shaOld}
	}
	cfg.Candidates = func(context.Context) ([]Candidate, error) { return many, nil }
	w.verified = nil
	New(cfg).Pass(t.Context())
	if len(w.verified) != maxCandidates {
		t.Errorf("verified %d candidates, want the bound %d", len(w.verified), maxCandidates)
	}
	cfg.Candidates = func(context.Context) ([]Candidate, error) {
		return []Candidate{{Repo: "github.com/o/gone", Commit: shaOld}}, nil
	}
	if res := New(cfg).Pass(t.Context()); len(res.Selected) != 0 {
		t.Errorf("a candidate the mirror does not hold was selected")
	}
	w.verifyErr = errors.New("boom")
	cfg.Candidates = func(context.Context) ([]Candidate, error) {
		return []Candidate{{Repo: "github.com/o/r", Commit: shaOld}}, nil
	}
	if res := New(cfg).Pass(t.Context()); len(res.Selected) != 0 {
		t.Errorf("a candidate that could not be verified was selected")
	}
}

// The operator's lost-root seed is imported into the history, once.
func TestTheLostRootsSeedIsImportedIntoTheHistory(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	cfg.LostRootsFile = filepath.Join(w.dir, trusthistory.LostRootsFileName)
	if res := New(cfg).Pass(t.Context()); len(res.Alerts()) != 0 {
		t.Errorf("an absent seed raised alerts: %q", res.Alerts())
	}
	if err := os.WriteFile(cfg.LostRootsFile, []byte(`{"version":1,"lost_roots":[
	 {"key_id":"3A0C7D69AA674E40CDAC318BDE6FA82D98A3E15A","lost_at":"2026-09-16T00:00:00Z","reason":"used until 2026-09-16"},
	 {"key_id":"75D25436DC9703A9109CCD98C15989FB6B4024EC","lost_at":"2026-09-16T23:59:59Z","reason":"used on 2026-09-16 only"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res := New(cfg).Pass(t.Context())
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	h, err := trusthistory.Load(cfg.HistoryFile)
	if err != nil || len(h.OfKind(trusthistory.KindLostRoot)) != 2 {
		t.Fatalf("lost roots in the history: %+v, %v", h, err)
	}
	if again := New(cfg).Pass(t.Context()); len(again.Recorded) != 0 {
		t.Errorf("a second import recorded %d entries", len(again.Recorded))
	}
	for name, body := range map[string]string{"damaged": "{", "bad id": `{"version":1,"lost_roots":[{"key_id":"zz","lost_at":"2026-09-16T00:00:00Z","reason":"r"}]}`} {
		if err := os.WriteFile(cfg.LostRootsFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if a := strings.Join(New(cfg).Pass(t.Context()).Alerts(), "\n"); !strings.Contains(a, "lost") {
			t.Errorf("%s seed: no alert:\n%s", name, a)
		}
	}
}

// The pass's problems are written where /_core/status and the query API read
// them, each with the time it was first seen; a problem that clears is gone.
func TestTheStatusFileKeepsWhenEachProblemStarted(t *testing.T) {
	w := newWorld(t)
	w.sentinels(t, twoEras)
	w.verdicts[shaOld] = verify.VerdictPreHistory
	w.verdicts[shaNew] = verify.VerdictFailed
	cfg := w.config()
	cfg.StatusFile = filepath.Join(w.dir, StatusFileName)

	New(cfg).Pass(t.Context())
	w.at = today.Add(24 * time.Hour)
	New(cfg).Pass(t.Context())
	st, err := LoadStatus(cfg.StatusFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Problems) != 1 || !st.Problems[0].Since.Equal(today) || !st.CheckedAt.Equal(w.at) {
		t.Fatalf("status = %+v, want one problem seen since %s", st, today)
	}
	if !strings.Contains(st.Problems[0].Text, shaNew) {
		t.Errorf("the problem does not name the sentinel: %q", st.Problems[0].Text)
	}

	w.verdicts[shaNew] = verify.VerdictVerified
	New(cfg).Pass(t.Context())
	if st, lerr := LoadStatus(cfg.StatusFile); lerr != nil || len(st.Problems) != 0 {
		t.Errorf("a cleared problem is still reported: %+v", st.Problems)
	}
	if _, err := LoadStatus(filepath.Join(w.dir, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadStatus(absent) = %v", err)
	}
	if err := os.WriteFile(cfg.StatusFile, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStatus(cfg.StatusFile); err == nil {
		t.Error("a damaged status file was read")
	}
	New(cfg).Pass(t.Context()) // a damaged previous status is replaced
	if _, err := LoadStatus(cfg.StatusFile); err != nil {
		t.Errorf("the status was not rewritten: %v", err)
	}
	cfg.StatusFile = filepath.Join(w.dir, "absent", StatusFileName)
	if a := strings.Join(New(cfg).Pass(t.Context()).Alerts(), "\n"); !strings.Contains(a, "status") {
		t.Errorf("an unwritable status file is not reported:\n%s", a)
	}
}

func TestDueRunsOnTheFirstCallThenOncePerInterval(t *testing.T) {
	w := newWorld(t)
	cfg := w.config()
	now := today
	cfg.Now = func() time.Time { return now }
	watch := New(cfg)
	if !watch.Due() {
		t.Fatal("the first call is not due")
	}
	watch.Pass(t.Context())
	now = now.Add(23 * time.Hour)
	if watch.Due() {
		t.Error("due again after 23 hours")
	}
	now = now.Add(time.Hour)
	if !watch.Due() {
		t.Error("not due after 24 hours")
	}
	cfg.Interval = time.Hour
	if New(cfg).cfg.Interval != time.Hour {
		t.Error("an interval was not kept")
	}
	var none *Watch
	if none.Due() {
		t.Error("a nil watch is due")
	}
}

func TestNewFillsTheDefaults(t *testing.T) {
	w := New(Config{})
	if w.cfg.Interval != DefaultInterval || w.cfg.Now == nil {
		t.Errorf("defaults = %s, now set %v", w.cfg.Interval, w.cfg.Now != nil)
	}
}
