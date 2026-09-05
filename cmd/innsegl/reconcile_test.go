// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
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
