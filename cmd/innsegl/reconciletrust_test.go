// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
	"innsegl.dev/innsegl/internal/trustwatch"
	"innsegl.dev/innsegl/internal/verify"
)

// ADR-0073: the reconcile companion runs the trust watch on its first cycle
// and daily after, and every alert reaches the operator's log as an ALERT
// line. It never changes the reconcile exit status: that is about intents.
func TestReconcileRunsTheTrustWatchAndPrintsItsAlerts(t *testing.T) {
	dir := t.TempDir()
	watch := trustwatch.New(trustwatch.Config{
		HistoryFile:   filepath.Join(dir, trusthistory.FileName),
		SentinelsFile: filepath.Join(dir, trustwatch.SentinelsFileName),
		Sources: map[trusthistory.Kind]trustwatch.Source{
			trusthistory.KindFulcioRoot: func(context.Context) ([][]byte, error) {
				return nil, errors.New("fulcio is not answering")
			},
		},
		RepoDir: func(string) (string, error) { return dir, nil },
		Verify: func(context.Context, *trusthistory.History, string, string) (trustwatch.Outcome, error) {
			return trustwatch.Outcome{Verdict: verify.VerdictVerified}, nil
		},
	})
	code, _, stderr := runReconcileWithEngines(t, append(validReconcileArgs(t), "-once"),
		reconcileEngines{Rekor: &fakeCycles{}, Trust: watch}, nil)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	for _, want := range []string{"TRUST ALERT", "fulcio is not answering"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not carry %q:\n%s", want, stderr)
		}
	}
}

func TestReconcileTrustOptionsFallBackToTheEnvironment(t *testing.T) {
	t.Setenv(envTrustHistory, "/run/innsegl/trust/trust-history.json")
	t.Setenv(envFulcioURL, "http://fulcio:5555")
	var seen reconcileOptions
	var stdout, stderr bytes.Buffer
	code := runReconcileLoop(context.Background(), append(validReconcileArgs(t), "-once"), &stdout, &stderr, reconcileDeps{
		open: func(_ context.Context, o reconcileOptions) (reconcileEngines, func(), error) {
			seen = o
			return reconcileEngines{Rekor: &fakeCycles{}}, func() {}, nil
		},
	})
	if code != exitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr.String())
	}
	if seen.trustHistory != "/run/innsegl/trust/trust-history.json" || seen.fulcioURL != "http://fulcio:5555" {
		t.Errorf("trust options = %q, %q", seen.trustHistory, seen.fulcioURL)
	}
	if seen.trustSentinels != "/run/innsegl/trust/"+trustwatch.SentinelsFileName {
		t.Errorf("the sentinel list does not default beside the history: %q", seen.trustSentinels)
	}
}

// The production watch, against real files and an unreachable Fulcio and
// Rekor: it is built only when a history is configured, and its sources say
// what they could not read rather than failing the companion.
func TestOpenTrustWatchIsOffWithoutAHistoryAndHonestWithOne(t *testing.T) {
	if w, err := openTrustWatch(reconcileOptions{}); w != nil || err != nil {
		t.Fatalf("with no history configured: %v, %v; want off", w, err)
	}
	dir := t.TempDir()
	gw := filepath.Join(dir, "gateway-ca")
	if err := os.MkdirAll(gw, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := reconcileOptions{
		trustHistory:   filepath.Join(dir, trusthistory.FileName),
		trustSentinels: filepath.Join(dir, trustwatch.SentinelsFileName),
		fulcioURL:      unreachableFulcio, rekorURL: unreachableRekor,
		mirrorDir: dir, gatewayCADir: gw,
		workloadAPI: "unix://" + filepath.Join(dir, "no-such-socket"),
	}
	w, err := openTrustWatch(opts)
	if err != nil || w == nil {
		t.Fatalf("openTrustWatch: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	alerts := strings.Join(w.Pass(ctx).Alerts(), "\n")
	for _, want := range []string{"fulcio_root", "transparency_log", "gateway_ca"} {
		if !strings.Contains(alerts, want) {
			t.Errorf("the pass does not say %s could not be read:\n%s", want, alerts)
		}
	}
	if strings.Contains(alerts, "spire_upstream_ca") {
		t.Errorf("an absent workload API socket was treated as an outage:\n%s", alerts)
	}
	if _, err := openTrustWatch(reconcileOptions{trustHistory: "x", fulcioURL: "not a url"}); err == nil {
		t.Error("a Fulcio URL that cannot be used was accepted")
	}
}

// Only SPIRE's upstream root is recorded: self-signed and long-lived. SPIRE's
// own CAs rotate daily, and recording each would grow the history every day.
func TestOnlyTheLongLivedSelfSignedAuthorityIsTheUpstreamCA(t *testing.T) {
	now := time.Now()
	mk := func(name string, life time.Duration, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: now, NotAfter: now.Add(life), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key
	}
	upstream, upKey := mk("upstream", 10*365*24*time.Hour, nil, nil)
	rotating, _ := mk("spire own", 24*time.Hour, nil, nil)
	intermediate, _ := mk("intermediate", 10*365*24*time.Hour, upstream, upKey)

	got := upstreamRoots([]*x509.Certificate{rotating, intermediate, upstream})
	if len(got) != 1 {
		t.Fatalf("kept %d authorities, want the upstream root only", len(got))
	}
	block, _ := pem.Decode(got[0])
	if block == nil || !bytes.Equal(block.Bytes, upstream.Raw) {
		t.Error("the authority kept is not the upstream root")
	}
	if two := splitPEM(append(append([]byte{}, got[0]...), got[0]...)); len(two) != 2 {
		t.Errorf("splitPEM found %d blocks in two", len(two))
	}
	if got := splitPEM([]byte("nothing")); len(got) != 1 || string(got[0]) != "nothing" {
		t.Errorf("splitPEM of a document with no block = %q", got)
	}
	if socketPresent("") || !socketPresent("tcp://127.0.0.1:1") {
		t.Error("socketPresent misreads an empty or a non-unix address")
	}
}

// The core's status answer reads the CAs in use from the same history.
func TestTheCoreStatusReadsItsExpiriesFromTheTrustHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, trusthistory.FileName)
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	if coreTrustExpiries("", now) != nil || coreTrustExpiries(path, now) != nil {
		t.Fatal("expiries with no history")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gw"},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(0, 6, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	h := trusthistory.New()
	if _, err := h.Record(trusthistory.KindGatewayCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), now); err != nil {
		t.Fatal(err)
	}
	if err := trusthistory.Save(path, h); err != nil {
		t.Fatal(err)
	}
	got := coreTrustExpiries(path, now)
	if len(got) != 1 || got[0].Warning != trusthistory.WarningYear {
		t.Errorf("expiries = %+v, want the gateway CA within a year", got)
	}
}

// The core status reads the trust watch's problems from beside the history.
func TestTheCoreStatusReadsTheTrustWatchsProblems(t *testing.T) {
	dir := t.TempDir()
	history := filepath.Join(dir, trusthistory.FileName)
	if coreTrustProblems("") != nil || coreTrustProblems(history) != nil {
		t.Fatal("problems with no status file")
	}
	body := `{"checked_at":"2026-10-07T00:00:00Z","problems":[{"text":"sentinel x failed","since":"2026-10-06T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, trustwatch.StatusFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := coreTrustProblems(history)
	if len(got) != 1 || got[0].Text != "sentinel x failed" {
		t.Errorf("problems = %+v", got)
	}
}

// Sentinel candidates are the newest commits of every repository the mirror
// holds.
func TestSentinelCandidatesComeFromTheMirror(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "github.com", "o", "r.git")
	for _, args := range [][]string{
		{"init", "--bare", "-q", repo},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	work := t.TempDir()
	for _, args := range [][]string{
		{"-C", work, "init", "-q"},
		{"-C", work, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "one"},
		{"-C", work, "push", "-q", repo, "HEAD:refs/heads/main"},
	} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	got, err := sentinelCandidates(reconcileOptions{mirrorDir: root})(t.Context())
	if err != nil || len(got) != 1 || got[0].Repo != "github.com/o/r" || len(got[0].Commit) != 40 {
		t.Fatalf("candidates = %+v, %v", got, err)
	}
	if _, err := sentinelCandidates(reconcileOptions{mirrorDir: filepath.Join(root, "absent")})(t.Context()); err == nil {
		t.Error("an absent mirror listed candidates")
	}
	if got, err := sentinelCandidates(reconcileOptions{})(t.Context()); err != nil || got != nil {
		t.Errorf("no mirror: %+v, %v", got, err)
	}
}
