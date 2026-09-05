// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/spire"
)

// ---------------------------------------------------------------------------
// OPS-016 (PROPOSED for doc 07's TC-OPS) — #153/RM-096: internal/spire's
// reconciler had no caller outside its own tests, so the SPIRE drift it
// detects — spire_entry_missing, spire_entry_not_deleted, the replanted-entry
// case SPI-008 covers — was detected by code that never ran in a deployment.
//
// The issue's own measurement was:
//
//	grep -rn "spire\.Reconciler|spire\.NewReconciler" --include='*.go' cmd/ internal/ \
//	  | grep -v _test.go
//
// which came back empty. This test walks the same ground so the regression
// fails the same way if the caller openReconciler adds is ever deleted, moved
// into a _test.go file, or commented out. It needs no Docker and no SPIRE and
// takes microseconds, so it runs on every `go test ./...`, the same reasoning
// test/deploy's TestOPS007 gives for checking the compose files this way.
// ---------------------------------------------------------------------------

func TestOPS016TheSPIREReconcilerIsWiredIntoReconcile(t *testing.T) {
	root := reconcileWiringRepoRoot(t)
	// The opening paren matters: it is what distinguishes an actual call site
	// from a comment that merely names the type (this file has several, by
	// necessity — see the file comment above openSpireReconciler). Matching
	// only "spire.NewReconciler(" is what makes deleting the call, and
	// leaving the prose that talks about it, still fail this test.
	pattern := regexp.MustCompile(`spire\.NewReconciler\(`)

	var found []string
	for _, dir := range []string{"cmd", "internal"} {
		start := filepath.Join(root, dir)
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if pattern.Match(body) {
				found = append(found, strings.TrimPrefix(path, root+string(filepath.Separator)))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", start, err)
		}
	}

	if len(found) == 0 {
		t.Fatal("no non-test .go file under cmd/ or internal/ references spire.Reconciler or " +
			"spire.NewReconciler: the SPIRE identity reconciler has no caller again, and every " +
			"drift kind it detects (spire_entry_missing, spire_entry_not_deleted, " +
			"spire_entry_duplicated, spire_entry_unattributed) runs nowhere in a deployment " +
			"(#153, RM-096)")
	}
	t.Logf("spire.NewReconciler is wired from: %s", strings.Join(found, ", "))
}

func reconcileWiringRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// The operator surface: the identity pass's flags, and what the report says
// when it is on, off, and failing.
// ---------------------------------------------------------------------------

func TestReconcileHelpDocumentsTheIdentityPassFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reconcile", "-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("`innsegl reconcile -h` exited %d, want %d", code, exitOK)
	}
	for _, want := range []string{"-spire-address", "-spire-server-id", "-workload-api", "-timeout"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the usage block does not mention %s:\n%s", want, stderr.String())
		}
	}
}

// Without -spire-address, every cycle's report says the identity pass is OFF
// and why — never silently omitting it (#153, RM-096; see openReconciler's
// DisabledReason).
func TestReconcileReportsTheIdentityPassAsOffWhenNotConfigured(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{Intents: 1, Open: 0}}}
	engines := reconcileEngines{
		Rekor: cycles, SpireEnabled: false,
		DisabledReason: "-spire-address (or $INNSEGL_SPIRE_ADDRESS) is not set",
	}
	code, stdout, _ := runReconcileWithEngines(t, append(validReconcileArgs(t), "-once"), engines, nil)
	if code != exitOK {
		t.Fatalf("exit %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout, "spire: OFF") || !strings.Contains(stdout, "INNSEGL_SPIRE_ADDRESS") {
		t.Fatalf("the report does not say the identity pass is off and why:\n%s", stdout)
	}
}

// The JSON report carries `spire.enabled` unconditionally, so a monitor can
// tell "checked and clean" from "not being checked" without inferring it from
// a missing key.
func TestReconcileJSONReportsSpireEnabledEvenWhenOff(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{Intents: 1}}}
	engines := reconcileEngines{Rekor: cycles, SpireEnabled: false, DisabledReason: "not configured"}
	code, stdout, _ := runReconcileWithEngines(t,
		append(validReconcileArgs(t), "-once", "-json"), engines, nil)
	if code != exitOK {
		t.Fatalf("exit %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout, `"enabled": false`) {
		t.Fatalf("the JSON report does not carry spire.enabled=false:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"disabled_reason"`) {
		t.Fatalf("the JSON report does not say why the identity pass is off:\n%s", stdout)
	}
}

// With the identity pass on and clean, the cycle still exits 0: agreement is
// not a failure.
func TestReconcileReportsIdentityDriftWhenEnabled(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{Intents: 1}}}
	spireCycles := &fakeSpireCycles{results: []spire.Result{{
		LedgerRuns: 3, ActiveRuns: 2, SPIREEntries: 3,
		Drifts:   []spire.Drift{{Kind: spire.DriftEntryMissing, SPIFFEID: "spiffe://innsegl.dev/agent/x", RunID: "r1"}},
		Appended: []string{"evt-1"},
	}}}
	engines := reconcileEngines{Rekor: cycles, Spire: spireCycles, SpireEnabled: true}
	code, stdout, _ := runReconcileWithEngines(t, append(validReconcileArgs(t), "-once"), engines, nil)
	if code != exitOK {
		t.Fatalf("exit %d, want %d (drift found and recorded is not a failure)", code, exitOK)
	}
	for _, want := range []string{"spire_entry_missing", "spiffe://innsegl.dev/agent/x", "drift 1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not mention %q:\n%s", want, stdout)
		}
	}
	if spireCycles.calls != 1 {
		t.Fatalf("the identity pass ran %d times, want 1", spireCycles.calls)
	}
}

// A cycle where the identity pass cannot complete is UNRESOLVED, not a
// silent pass: the identity question this cycle asked went unanswered.
func TestReconcileFailsClosedWhenTheIdentityPassCannotRun(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{Intents: 1}}}
	spireCycles := &fakeSpireCycles{errs: []error{errors.New("SPIRE is unreachable")}}
	engines := reconcileEngines{Rekor: cycles, Spire: spireCycles, SpireEnabled: true}
	code, _, stderr := runReconcileWithEngines(t, append(validReconcileArgs(t), "-once"), engines, nil)
	if code != exitReconcileUnresolved {
		t.Fatalf("exit %d, want %d", code, exitReconcileUnresolved)
	}
	if !strings.Contains(stderr, "UNRESOLVED") || !strings.Contains(stderr, "SPIRE is unreachable") {
		t.Fatalf("the failure is not reported:\n%s", stderr)
	}
}

// A rekor-pass failure short-circuits the whole cycle: the identity pass must
// not run against a ledger the rekor pass just reported as unreadable.
func TestReconcileSkipsTheIdentityPassWhenTheRekorPassCannotRun(t *testing.T) {
	cycles := &fakeCycles{errs: []error{errors.New("postgres is down")}}
	spireCycles := &fakeSpireCycles{}
	engines := reconcileEngines{Rekor: cycles, Spire: spireCycles, SpireEnabled: true}
	code, _, stderr := runReconcileWithEngines(t, append(validReconcileArgs(t), "-once"), engines, nil)
	if code != exitReconcileInconclusive {
		t.Fatalf("exit %d, want %d", code, exitReconcileInconclusive)
	}
	if !strings.Contains(stderr, "INCONCLUSIVE") {
		t.Fatalf("the verdict is not named:\n%s", stderr)
	}
	if spireCycles.calls != 0 {
		t.Fatalf("the identity pass ran %d times against a cycle that never examined the "+
			"ledger, want 0", spireCycles.calls)
	}
}

// ---------------------------------------------------------------------------
// openSpireReconciler — the production wiring's two real branches, exercised
// without a Postgres or a SPIRE server the way TestOpenReaperFailsWithoutAnIdentity
// exercises openReaper's.
// ---------------------------------------------------------------------------

// With no -spire-address, openSpireReconciler must return instantly with no
// engine, no closer and no error — and, in particular, must not touch the
// ledger store or dial anything. Passing a nil *ledger.Store is the proof:
// this only compiles and passes if the disabled path never dereferences it.
func TestOpenSpireReconcilerIsOffWithoutAnAddress(t *testing.T) {
	engine, closer, err := openSpireReconciler(t.Context(), reconcileOptions{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil || closer != nil {
		t.Fatalf("openSpireReconciler with no -spire-address returned an engine or a closer")
	}
}

// Once -spire-address is set, the identity pass is no longer optional: with
// no Workload API to attest to, openSpireReconciler must refuse rather than
// return a half-built engine (internal/spire.NewReconciler's own doc: a
// reconciler missing one of its halves "is not a degraded reconciler").
func TestOpenSpireReconcilerFailsClosedOnceConfigured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	engine, closer, err := openSpireReconciler(ctx, reconcileOptions{
		spireAddress: "127.0.0.1:1",
		trustDomain:  "innsegl.dev",
		workloadAPI:  "unix:///nonexistent/innsegl-no-such-agent.sock",
	}, nil)
	if err == nil {
		if closer != nil {
			closer()
		}
		t.Fatal("openSpireReconciler succeeded with no Workload API to attest to")
	}
	if engine != nil || closer != nil {
		t.Error("openSpireReconciler returned an engine or a closer alongside its error")
	}
	if !strings.Contains(err.Error(), "Workload API") {
		t.Errorf("error %q does not say what could not be obtained", err)
	}
}
