// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/spire"
)

// `innsegl reconcile` — the flag handling, the exit statuses and the report.
// What the reconciler DOES is internal/reconciler's subject and REC-001/002/005
// prove it against a real Sigstore; this file is about the operator surface.

type fakeCycles struct {
	results []reconciler.Result
	errs    []error
	calls   int
}

func (f *fakeCycles) Reconcile(context.Context) (reconciler.Result, error) {
	i := f.calls
	f.calls++
	var (
		result reconciler.Result
		err    error
	)
	if i < len(f.results) {
		result = f.results[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return result, err
}

// fakeSpireCycles is spireCycler's test double, cycler's fakeCycles mirrored
// for the identity pass.
type fakeSpireCycles struct {
	results []spire.Result
	errs    []error
	calls   int
}

func (f *fakeSpireCycles) Reconcile(context.Context) (spire.Result, error) {
	i := f.calls
	f.calls++
	var (
		result spire.Result
		err    error
	)
	if i < len(f.results) {
		result = f.results[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return result, err
}

func runReconcile(t *testing.T, args []string, cycles *fakeCycles, openErr error) (int, string, string) {
	t.Helper()
	return runReconcileWithEngines(t, args, reconcileEngines{Rekor: cycles}, openErr)
}

// runReconcileWithEngines is runReconcile's general form, for tests that also
// need to fake the identity pass.
func runReconcileWithEngines(t *testing.T, args []string, engines reconcileEngines, openErr error) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runReconcileCommand(args, &stdout, &stderr, reconcileDeps{
		open: func(context.Context, reconcileOptions) (reconcileEngines, func(), error) {
			if openErr != nil {
				return reconcileEngines{}, nil, openErr
			}
			return engines, func() {}, nil
		},
	})
	return code, stdout.String(), stderr.String()
}

func TestReconcileIsNoLongerTheNotImplementedStub(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"reconcile", "-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("`innsegl reconcile -h` exited %d, want %d", code, exitOK)
	}
	if strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("`innsegl reconcile` is still the stub:\n%s", stderr.String())
	}
	for _, want := range []string{"-dsn", "-rekor-url", "-workspace", "-trust-domain", "-expire-after"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the usage block does not mention %s:\n%s", want, stderr.String())
		}
	}
}

func TestReconcileRequiresEveryHalfOfTheJoin(t *testing.T) {
	base := map[string]string{
		"-dsn":          "postgres://x/y",
		"-rekor-url":    "http://rekor.example",
		"-workspace":    t.TempDir(),
		"-trust-domain": "innsegl.dev",
	}
	for missing := range base {
		t.Run(strings.TrimPrefix(missing, "-"), func(t *testing.T) {
			var args []string
			for flagName, value := range base {
				if flagName == missing {
					continue
				}
				args = append(args, flagName, value)
			}
			code, _, stderr := runReconcile(t, args, &fakeCycles{}, nil)
			if code != exitUsage {
				t.Fatalf("without %s the command exited %d, want %d", missing, code, exitUsage)
			}
			if !strings.Contains(stderr, missing) {
				t.Fatalf("the refusal does not name %s:\n%s", missing, stderr)
			}
		})
	}
}

func TestReconcileRefusesAWindowThatWouldExpireInFlightSignatures(t *testing.T) {
	code, _, stderr := runReconcile(t, append(validReconcileArgs(t), "-expire-after", "0"),
		&fakeCycles{}, nil)
	if code != exitUsage {
		t.Fatalf("a zero window exited %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "expire-after") {
		t.Fatalf("the refusal does not name the flag:\n%s", stderr)
	}
}

func TestOneSweepReportsWhatItDidAndExitsZero(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{
		Intents: 3, Open: 2, Repaired: 1, Expired: 1,
		Appended: []string{"a", "b"},
		Findings: []reconciler.Finding{
			{Outcome: reconciler.OutcomeRepaired, IntentEventID: "i1", CommitSHA: "c1", Detail: "repaired"},
			{Outcome: reconciler.OutcomeExpired, IntentEventID: "i2", Detail: "expired"},
		},
	}}}
	code, stdout, stderr := runReconcile(t, append(validReconcileArgs(t), "-once"), cycles, nil)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitOK, stderr)
	}
	if cycles.calls != 1 {
		t.Fatalf("-once ran %d cycles", cycles.calls)
	}
	for _, want := range []string{"repaired 1", "expired 1", "i1", "i2"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not mention %q:\n%s", want, stdout)
		}
	}
}

// An intent the cycle could not rule on is the state doc 05 §4 wants an
// operator paged about, and a command that exits zero on it is a command
// nobody will notice.
func TestAnUnresolvedIntentIsNotASuccess(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{
		Intents: 1, Open: 1, Unresolved: 1,
		Findings: []reconciler.Finding{{
			Outcome: reconciler.OutcomeUnresolved, IntentEventID: "i1",
			Detail: "the transparency log could not be asked",
		}},
	}}}
	code, _, stderr := runReconcile(t, append(validReconcileArgs(t), "-once"), cycles, nil)
	if code != exitReconcileUnresolved {
		t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitReconcileUnresolved, stderr)
	}
	if !strings.Contains(stderr, "UNRESOLVED") {
		t.Fatalf("the verdict is not named:\n%s", stderr)
	}
}

func TestACycleThatCouldNotRunFailsClosed(t *testing.T) {
	cycles := &fakeCycles{errs: []error{errors.New("postgres is down")}}
	code, _, stderr := runReconcile(t, append(validReconcileArgs(t), "-once"), cycles, nil)
	if code != exitReconcileInconclusive {
		t.Fatalf("exit %d, want %d", code, exitReconcileInconclusive)
	}
	if !strings.Contains(stderr, "INCONCLUSIVE") || !strings.Contains(stderr, "postgres is down") {
		t.Fatalf("the failure is not reported:\n%s", stderr)
	}
}

func TestAConfigurationThatCannotBeOpenedFailsClosed(t *testing.T) {
	code, _, stderr := runReconcile(t, append(validReconcileArgs(t), "-once"),
		&fakeCycles{}, errors.New("no such workspace"))
	if code != exitReconcileInconclusive {
		t.Fatalf("exit %d, want %d", code, exitReconcileInconclusive)
	}
	if !strings.Contains(stderr, "no such workspace") {
		t.Fatalf("the failure is not reported:\n%s", stderr)
	}
}

func TestWithoutOnceItRunsContinuously(t *testing.T) {
	cycles := &fakeCycles{}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	code := runReconcileLoop(ctx, append(validReconcileArgs(t), "-interval", "20ms"),
		&stdout, &stderr, reconcileDeps{
			open: func(context.Context, reconcileOptions) (reconcileEngines, func(), error) {
				return reconcileEngines{Rekor: cycles}, func() {}, nil
			},
		})
	if code != exitOK {
		t.Fatalf("the loop exited %d on a cancelled context, want %d; stderr:\n%s",
			code, exitOK, stderr.String())
	}
	if cycles.calls < 2 {
		t.Fatalf("the loop ran %d cycles in 300ms at a 20ms interval", cycles.calls)
	}
}

func TestReconcileRefusesAnUnexpectedArgument(t *testing.T) {
	code, _, stderr := runReconcile(t, append(validReconcileArgs(t), "extra"), &fakeCycles{}, nil)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "extra") {
		t.Fatalf("the refusal does not name the argument:\n%s", stderr)
	}
}

func TestReconcileWritesJSONWhenAsked(t *testing.T) {
	cycles := &fakeCycles{results: []reconciler.Result{{Intents: 1, Open: 1, Expired: 1}}}
	code, stdout, _ := runReconcile(t,
		append(validReconcileArgs(t), "-once", "-json"), cycles, nil)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Fatalf("the report is not JSON:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"expired": 1`) {
		t.Fatalf("the JSON report does not carry the counts:\n%s", stdout)
	}
}

func validReconcileArgs(t *testing.T) []string {
	t.Helper()
	return []string{
		"-dsn", "postgres://user:pass@127.0.0.1:5432/innsegl",
		"-rekor-url", "http://rekor.example",
		"-workspace", t.TempDir(),
		"-trust-domain", "innsegl.dev",
	}
}

// The commit path's two reconciler passes (ADR-0059, E17) say what they saw,
// and say OFF when they cannot run: a silent line reads like agreement.
func TestReconcileReportNamesTheCommitPathPasses(t *testing.T) {
	on := renderReconcileResult(reconciler.Result{
		CommitWatch: reconciler.CommitWatchReport{Enabled: true, Checked: 4, Signed: 3, Unsigned: 1},
		Landing:     reconciler.LandingReport{Enabled: true, Checked: 4, Landed: 1, NotLanded: 2, Rewritten: 1},
	})
	for _, want := range []string{
		"commits: 4 checked  3 signed  1 UNSIGNED  0 unchecked",
		"landing: 4 checked  1 landed  1 rewritten by a merge  2 signed, not landed  0 not checked",
	} {
		if !strings.Contains(on, want) {
			t.Errorf("report lacks %q:\n%s", want, on)
		}
	}
	off := renderReconcileResult(reconciler.Result{})
	for _, want := range []string{"commits: OFF", "landing: OFF", "witness: OFF"} {
		if !strings.Contains(off, want) {
			t.Errorf("report lacks %q:\n%s", want, off)
		}
	}
}

// With the gateway's tool-call bodies named, both passes are on; without,
// the commit watch is off (it cannot read a result) and landing still reads
// the repository.
func TestReconcileConfigTurnsOnTheCommitPathPasses(t *testing.T) {
	with := commitPathPasses(reconcileOptions{toolBodyDir: "/agentlog"})
	if with.commitWatch == nil || with.commitWatch.LogDir != "/agentlog" || with.landing == nil || with.landing.LogDir != "/agentlog" ||
		with.witness == nil || with.witness.LogDir != "/agentlog" {
		t.Errorf("with a body dir: %+v", with)
	}
	without := commitPathPasses(reconcileOptions{})
	if without.commitWatch != nil || without.landing == nil || without.witness != nil {
		t.Errorf("without a body dir: %+v", without)
	}
}

// The second witness says whether telemetry is arriving at all: a
// deployment that never enabled it is not "every tool call corroborated".
func TestReconcileReportNamesTheTelemetryWitness(t *testing.T) {
	active := renderReconcileResult(reconciler.Result{Witness: reconciler.WitnessReport{
		Enabled: true, TelemetryActive: true, Checked: 5, Matched: 3, Pending: 1, Missing: 1, Orphaned: 2,
	}})
	if want := "witness: 5 checked  3 matched  1 pending  1 MISSING telemetry  2 telemetry never relayed"; !strings.Contains(active, want) {
		t.Errorf("report lacks %q:\n%s", want, active)
	}
	quiet := renderReconcileResult(reconciler.Result{Witness: reconciler.WitnessReport{Enabled: true}})
	if want := "witness: no telemetry received yet"; !strings.Contains(quiet, want) {
		t.Errorf("report lacks %q:\n%s", want, quiet)
	}
}

// P1: the reconciler reads repositories from the core's mirror (ADR-0065
// decision 1). -mirror-dir ($INNSEGL_MIRROR_DIR) is enough on its own, and
// when a working-tree root is also set — the MCP's environment carries both,
// and the companion reads it — the mirror is what is read.
func TestReconcileReadsTheMirrorWhenOneIsSet(t *testing.T) {
	mirrorDir, workspace := t.TempDir(), t.TempDir()
	var seen reconcileOptions
	var stdout, stderr bytes.Buffer
	code := runReconcileCommand([]string{
		"-dsn", "postgres://x/y", "-rekor-url", "http://rekor.example",
		"-trust-domain", "innsegl.dev", "-mirror-dir", mirrorDir, "-once",
	}, &stdout, &stderr, reconcileDeps{
		open: func(_ context.Context, o reconcileOptions) (reconcileEngines, func(), error) {
			seen = o
			return reconcileEngines{Rekor: &fakeCycles{}}, func() {}, nil
		},
	})
	if code != exitOK {
		t.Fatalf("with -mirror-dir and no -workspace the command exited %d; stderr:\n%s", code, stderr.String())
	}
	if seen.mirrorDir != mirrorDir {
		t.Fatalf("-mirror-dir did not reach the opener: %q", seen.mirrorDir)
	}
	repos, err := reconcileRepos(reconcileOptions{mirrorDir: mirrorDir, workspace: workspace})
	if err != nil {
		t.Fatalf("reconcileRepos: %v", err)
	}
	if _, ok := repos.(*reconciler.MirrorRepos); !ok {
		t.Fatalf("with both set the reconciler reads %T, want the mirror", repos)
	}
	repos, err = reconcileRepos(reconcileOptions{workspace: workspace})
	if err != nil {
		t.Fatalf("reconcileRepos: %v", err)
	}
	if _, ok := repos.(*reconciler.GitWorkspace); !ok {
		t.Fatalf("with only a working-tree root the reconciler reads %T", repos)
	}
	if _, err := reconcileRepos(reconcileOptions{mirrorDir: filepath.Join(mirrorDir, "absent")}); err == nil {
		t.Fatal("a mirror root that does not exist was accepted")
	}
}
