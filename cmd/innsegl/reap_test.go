// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/spire"
)

// The command around the reaper: flag handling, exit statuses, and what an
// operator or a monitor is told. Whether the reaper actually expires an
// orphaned entry is SPI-003's, against a real SPIRE and a real ledger; nothing
// here can prove that and nothing here pretends to.
//
// The seam is reapDeps.open, which is the whole of the wiring to SPIRE and
// Postgres. Replacing it is what lets the exit statuses below be exercised —
// including the two that only happen when something is broken, which is exactly
// where a command with an untested error path exits zero.

func minimalReapArgs(extra ...string) []string {
	return append([]string{
		"-spire-address", "127.0.0.1:8081",
		"-trust-domain", "innsegl.dev",
		"-dsn", "postgres://innsegl@127.0.0.1:5432/innsegl",
	}, extra...)
}

// stubSweeper answers with a fixed report.
type stubSweeper struct {
	report *spire.SweepReport
	err    error
	calls  int
}

func (s *stubSweeper) Sweep(context.Context) (*spire.SweepReport, error) {
	s.calls++
	return s.report, s.err
}

// stubOpen wires a stub sweeper in, and records whether the command released
// what it opened.
func stubOpen(sw sweeper, err error, closed *bool) func(context.Context, reapOptions) (sweeper, func(), error) {
	return func(context.Context, reapOptions) (sweeper, func(), error) {
		if err != nil {
			return nil, nil, err
		}
		return sw, func() {
			if closed != nil {
				*closed = true
			}
		}, nil
	}
}

func cleanReport() *spire.SweepReport {
	return &spire.SweepReport{
		StartedAt: time.Unix(0, 0).UTC(),
		Examined:  2,
		Live: []spire.Candidate{{
			Entry:    spire.Entry{ID: "e2", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-2"},
			Run:      spire.RunRef{AgentType: "demo", TaskID: "rm-017", RunID: "run-2"},
			Deadline: time.Unix(600, 0).UTC(),
		}},
		Expired: []spire.Expiry{{
			Candidate: spire.Candidate{
				Entry:    spire.Entry{ID: "e1", SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-1"},
				Run:      spire.RunRef{AgentType: "demo", TaskID: "rm-017", RunID: "run-1"},
				Deadline: time.Unix(60, 0).UTC(),
			},
			EventID:  "01a04a16-db86-7f2e-9bb5-23822b92285a",
			Recorded: true,
			Deleted:  true,
		}},
	}
}

func incompleteReport() *spire.SweepReport {
	r := cleanReport()
	r.Failures = []spire.Failure{{
		EntryID:  "e3",
		SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-017/run-3",
		Err:      errors.New("ledger unreachable"),
	}}
	return r
}

func TestReapExitStatusIsTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sweeper    *stubSweeper
		openErr    error
		want       int
		wantStderr string
	}{
		{
			name:    "a completed sweep exits zero",
			sweeper: &stubSweeper{report: cleanReport()},
			want:    exitOK,
		},
		{
			name:    "a sweep that found no entries at all still exits zero",
			sweeper: &stubSweeper{report: &spire.SweepReport{StartedAt: time.Unix(0, 0).UTC()}},
			want:    exitOK,
		},
		{
			// An orphan left unreaped is not a pass. Its entry is still live,
			// which means credentialing still works for a run that has none.
			name:       "an unreaped orphan is INCOMPLETE",
			sweeper:    &stubSweeper{report: incompleteReport()},
			want:       exitReapIncomplete,
			wantStderr: "INCOMPLETE",
		},
		{
			name:       "a sweep that could not run is INCONCLUSIVE",
			sweeper:    &stubSweeper{err: errors.New("spire-server unreachable")},
			want:       exitReapInconclusive,
			wantStderr: "INCONCLUSIVE",
		},
		{
			name:       "credentials that cannot be obtained are INCONCLUSIVE",
			openErr:    errors.New("no SVID from the Workload API"),
			want:       exitReapInconclusive,
			wantStderr: "INCONCLUSIVE",
		},
		{
			// A nil report alongside a nil error must not read as a clean
			// sweep: nothing was examined, so no orphan was ruled out.
			name:       "no report at all is INCONCLUSIVE",
			sweeper:    &stubSweeper{},
			want:       exitReapInconclusive,
			wantStderr: "no report",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			closed := false

			code := runReapCommand(minimalReapArgs(), &stdout, &stderr,
				reapDeps{open: stubOpen(tc.sweeper, tc.openErr, &closed)})

			if code != tc.want {
				t.Errorf("exit = %d, want %d (stdout %q, stderr %q)",
					code, tc.want, stdout.String(), stderr.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
			if tc.openErr == nil && !closed {
				t.Error("the command did not release the SPIRE and ledger connections it opened")
			}
		})
	}
}

func TestReapPrintsWhatItDeleted(t *testing.T) {
	// Reaping is destructive and irreversible at SPIRE. The identity of every
	// entry deleted has to reach the operator, on stdout, by name.
	var stdout, stderr bytes.Buffer
	code := runReapCommand(minimalReapArgs(), &stdout, &stderr,
		reapDeps{open: stubOpen(&stubSweeper{report: cleanReport()}, nil, nil)})

	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	for _, want := range []string{
		"spiffe://innsegl.dev/agent/demo/rm-017/run-1", "e1", "expired",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout.String())
		}
	}

	// A failed sweep's report goes to stderr, where a scheduled job's failure
	// mail will pick it up.
	stdout.Reset()
	stderr.Reset()
	code = runReapCommand(minimalReapArgs(), &stdout, &stderr,
		reapDeps{open: stubOpen(&stubSweeper{report: incompleteReport()}, nil, nil)})
	if code != exitReapIncomplete {
		t.Fatalf("exit = %d, want %d", code, exitReapIncomplete)
	}
	if !strings.Contains(stderr.String(), "ledger unreachable") {
		t.Errorf("stderr does not carry the failure reason:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("a failed sweep wrote to stdout: %q", stdout.String())
	}
}

func TestReapQuietStillReportsDeletions(t *testing.T) {
	// -quiet exists so a cron job that reaps nothing sends no mail. It must not
	// silence a sweep that deleted an identity.
	var stdout, stderr bytes.Buffer
	empty := &spire.SweepReport{StartedAt: time.Unix(0, 0).UTC(), Examined: 3}
	if code := runReapCommand(minimalReapArgs("-quiet"), &stdout, &stderr,
		reapDeps{open: stubOpen(&stubSweeper{report: empty}, nil, nil)}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("-quiet printed on a sweep that reaped nothing: stdout %q stderr %q",
			stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runReapCommand(minimalReapArgs("-quiet"), &stdout, &stderr,
		reapDeps{open: stubOpen(&stubSweeper{report: cleanReport()}, nil, nil)}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "run-1") {
		t.Errorf("-quiet suppressed a deletion:\n%s", stdout.String())
	}
}

func TestReapJSONReportIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runReapCommand(minimalReapArgs("-json"), &stdout, &stderr,
		reapDeps{open: stubOpen(&stubSweeper{report: incompleteReport()}, nil, nil)})
	if code != exitReapIncomplete {
		t.Fatalf("exit = %d, want %d", code, exitReapIncomplete)
	}

	var got reapReportJSON
	if err := json.Unmarshal(stderr.Bytes()[:strings.Index(stderr.String(), "\n}")+2], &got); err != nil {
		// The report and the trailing diagnostic share the stream; decode the
		// object rather than the whole buffer.
		t.Fatalf("the JSON report did not parse: %v\n%s", err, stderr.String())
	}
	if got.Examined != 2 {
		t.Errorf("examined = %d, want 2", got.Examined)
	}
	if got.Complete {
		t.Error("complete = true on a sweep that left an orphan")
	}
	if len(got.Expired) != 1 || got.Expired[0].RunID != "run-1" {
		t.Errorf("expired = %+v, want the one reaped run", got.Expired)
	}
	if !got.Expired[0].Recorded || !got.Expired[0].Deleted {
		t.Errorf("expired[0] = %+v, want recorded and deleted", got.Expired[0])
	}
	if len(got.Live) != 1 || got.Live[0].RunID != "run-2" {
		t.Errorf("live = %+v, want the one live run", got.Live)
	}
	// The reason an `error` does not get json tags: it would marshal to {} and
	// a monitor would read a failure as clean.
	if len(got.Failures) != 1 || got.Failures[0].Reason != "ledger unreachable" {
		t.Errorf("failures = %+v, want the failure reason carried through", got.Failures)
	}
}

func TestReapRefusesToRunWithoutItsConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no spire address", args: []string{"-trust-domain", "innsegl.dev", "-dsn", "x"}, want: "-spire-address"},
		{name: "no trust domain", args: []string{"-spire-address", "a:1", "-dsn", "x"}, want: "-trust-domain"},
		{name: "no dsn", args: []string{"-spire-address", "a:1", "-trust-domain", "innsegl.dev"}, want: "-dsn"},
		{
			// Caught here rather than inside the reaper, so the operator is
			// told which flag was wrong.
			name: "negative grace",
			args: minimalReapArgs("-grace", "-5m"),
			want: "negative",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opened := false
			deps := reapDeps{open: func(context.Context, reapOptions) (sweeper, func(), error) {
				opened = true
				return &stubSweeper{report: cleanReport()}, nil, nil
			}}

			code := runReapCommand(tc.args, &stdout, &stderr, deps)

			if code != exitUsage {
				t.Errorf("exit = %d, want %d (exitUsage)", code, exitUsage)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
			if opened {
				t.Error("the command dialled SPIRE before validating its configuration")
			}
		})
	}
}

func TestReapRejectsUnknownFlagsAndStrayArguments(t *testing.T) {
	for _, args := range [][]string{
		minimalReapArgs("-frobnicate"),
		minimalReapArgs("extra-argument"),
	} {
		var stdout, stderr bytes.Buffer
		if code := runReapCommand(args, &stdout, &stderr, reapDeps{}); code != exitUsage {
			t.Errorf("runReapCommand(%v) = %d, want %d", args, code, exitUsage)
		}
	}
}

func TestReapHelpExplainsTheExitStatuses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runReapCommand([]string{"-h"}, &stdout, &stderr, reapDeps{}); code != exitOK {
		t.Errorf("-h exit = %d, want %d", code, exitOK)
	}
	for _, want := range []string{"INCOMPLETE", "INCONCLUSIVE", "orphan", "single-active"} {
		if !strings.Contains(stderr.String(), want) && !strings.Contains(stdout.String(), want) {
			t.Errorf("help does not mention %q:\n%s", want, stderr.String())
		}
	}
}

// TestReapDefaultsComeFromTheEnvironment covers the path a scheduled job takes:
// no flags at all, everything from the environment, so the ledger DSN never
// reaches a command line the process table can read.
func TestReapDefaultsComeFromTheEnvironment(t *testing.T) {
	t.Setenv(envSPIREAddress, "spire:8081")
	t.Setenv(envTrustDomain, "innsegl.dev")
	t.Setenv(envLedgerDSN, "postgres://innsegl@db/innsegl")
	t.Setenv(envReapGrace, "90s")

	var seen reapOptions
	var stdout, stderr bytes.Buffer
	deps := reapDeps{open: func(_ context.Context, opts reapOptions) (sweeper, func(), error) {
		seen = opts
		return &stubSweeper{report: cleanReport()}, nil, nil
	}}

	if code := runReapCommand(nil, &stdout, &stderr, deps); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	if seen.spireAddress != "spire:8081" || seen.trustDomain != "innsegl.dev" {
		t.Errorf("options = %+v, want them read from the environment", seen)
	}
	if seen.dsn != "postgres://innsegl@db/innsegl" {
		t.Errorf("dsn = %q, want it read from $%s", seen.dsn, envLedgerDSN)
	}
	if seen.grace != 90*time.Second {
		t.Errorf("grace = %s, want 90s from $%s", seen.grace, envReapGrace)
	}
	if seen.workloadAPI != spire.DefaultWorkloadAPIAddress {
		t.Errorf("workload API = %q, want the default %q",
			seen.workloadAPI, spire.DefaultWorkloadAPIAddress)
	}
}

// TestReapGraceDefaultsToTheDocumentedSlack pins the operator-facing default.
// spire.ReaperConfig deliberately treats a zero Grace as zero, so if this
// command stopped applying DefaultReapGrace every run would be reaped the
// instant its TTL elapsed.
func TestReapGraceDefaultsToTheDocumentedSlack(t *testing.T) {
	var seen reapOptions
	var stdout, stderr bytes.Buffer
	deps := reapDeps{open: func(_ context.Context, opts reapOptions) (sweeper, func(), error) {
		seen = opts
		return &stubSweeper{report: cleanReport()}, nil, nil
	}}

	if code := runReapCommand(minimalReapArgs(), &stdout, &stderr, deps); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if seen.grace != spire.DefaultReapGrace {
		t.Errorf("grace = %s, want spire.DefaultReapGrace (%s)", seen.grace, spire.DefaultReapGrace)
	}
	if seen.grace == 0 {
		t.Error("the command applied a zero grace, which reaps every run the instant its TTL elapses")
	}
}

// TestReapIsReachableFromTheDispatchTable proves the subcommand is actually
// wired: `innsegl reap` must reach the reaper's own flag handling, not the
// not-implemented stub. Without configuration it is a usage error, which is a
// status the stub never returns.
func TestReapIsReachableFromTheDispatchTable(t *testing.T) {
	t.Setenv(envSPIREAddress, "")
	t.Setenv(envTrustDomain, "")
	t.Setenv(envLedgerDSN, "")

	var stdout, stderr bytes.Buffer
	code := run([]string{"reap"}, &stdout, &stderr)

	if code == exitNotImplemented {
		t.Fatal("`innsegl reap` still reaches the not-implemented stub")
	}
	if code != exitUsage {
		t.Errorf("run(\"reap\") = %d, want %d (exitUsage) (stderr %q)", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-spire-address") {
		t.Errorf("stderr = %q, want the reaper's own configuration error", stderr.String())
	}
}

// TestOpenReaperFailsWithoutAnIdentity walks the production wiring's first
// branch. The reaper is an attested workload: with no Workload API to attest to
// it holds no admin credential, and it must say so and open nothing rather than
// proceeding toward SPIRE with no identity (I1).
func TestOpenReaperFailsWithoutAnIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sw, closeAll, err := openReaper(ctx, reapOptions{
		spireAddress: "127.0.0.1:1",
		trustDomain:  "innsegl.dev",
		workloadAPI:  "unix:///nonexistent/innsegl-no-such-agent.sock",
		dsn:          "postgres://innsegl@127.0.0.1:1/innsegl",
	})
	if err == nil {
		if closeAll != nil {
			closeAll()
		}
		t.Fatal("openReaper succeeded with no Workload API to attest to")
	}
	if sw != nil || closeAll != nil {
		t.Error("openReaper returned a reaper or a closer alongside its error")
	}
	if !strings.Contains(err.Error(), "Workload API") {
		t.Errorf("error %q does not say what could not be obtained", err)
	}
}
