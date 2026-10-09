// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"innsegl.dev/innsegl/internal/segment"
)

// canaryDepsWith is stubDeps plus a scheduled canary whose runs are scripted.
func canaryDepsWith(c *stubCycler, runs *atomic.Int64, report func() *segment.CanaryReport,
	built *sealOptions) sealDeps {
	d := stubDeps(c)
	d.canary = func(opts sealOptions) *segment.CanarySchedule {
		if built != nil {
			*built = opts
		}
		return &segment.CanarySchedule{
			Interval:   opts.canaryInterval,
			StatusFile: opts.canaryStatusFile,
			Run: func(context.Context) (*segment.CanaryReport, error) {
				runs.Add(1)
				return report(), nil
			},
		}
	}
	return d
}

// runLoopUntil runs the seal loop until cond holds, then stops it.
func runLoopUntil(t *testing.T, args []string, deps sealDeps, cond func(stdout, stderr *syncBuffer) bool) (int, *syncBuffer, *syncBuffer) {
	t.Helper()
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- runSealLoop(ctx, args, stdout, stderr, deps) }()
	deadline := time.After(10 * time.Second)
	for !cond(stdout, stderr) {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("the condition never held; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case code := <-done:
		return code, stdout, stderr
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not stop")
	}
	return 0, nil, nil
}

// SEG-014 (proposed for doc 07), the sealer half — the seal loop runs the
// scheduled canary at its own interval and records each run where the
// core's health reads it.
func TestSEG014TheSealLoopRunsTheScheduledCanaryAtItsInterval(t *testing.T) {
	file := filepath.Join(t.TempDir(), "worm-canary.json")
	var runs atomic.Int64
	var built sealOptions
	cycler := &stubCycler{cycles: []stubCycle{{result: sealCycle{}}}}
	args := append(withoutFlag(minimalSealArgs(), "-once"), "-interval", "1ms",
		"-canary-interval", "20ms", "-canary-status-file", file, "-canary-probe-retention", "36h")

	code, stdout, _ := runLoopUntil(t, args, canaryDepsWith(cycler, &runs, passingReport, &built),
		func(out, _ *syncBuffer) bool {
			return runs.Load() >= 2 && strings.Contains(out.String(), "worm canary: PASS")
		})
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	// Twice in at least one interval, not once per seal cycle.
	if cycles := cycler.calls(); int64(cycles) <= runs.Load() {
		t.Errorf("%d canary runs in %d seal cycles: it is not on its own interval", runs.Load(), cycles)
	}
	if built.canaryProbeRetention != 36*time.Hour {
		t.Errorf("probe retention %s, want 36h", built.canaryProbeRetention)
	}
	rec, err := segment.LoadCanaryRecord(file)
	if err != nil || !rec.OK || rec.Interval != "20ms" {
		t.Fatalf("recorded %+v, %v", rec, err)
	}
	if !strings.Contains(stdout.String(), "worm canary: PASS") {
		t.Errorf("a passing run was not reported:\n%s", stdout)
	}
}

func TestSEG014AFailedScheduledCanaryIsReportedByCheckName(t *testing.T) {
	file := filepath.Join(t.TempDir(), "worm-canary.json")
	var runs atomic.Int64
	cycler := &stubCycler{cycles: []stubCycle{{result: sealCycle{}}}}
	args := append(withoutFlag(minimalSealArgs(), "-once"), "-interval", "1ms",
		"-canary-interval", "1h", "-canary-status-file", file, "-quiet")

	code, stdout, stderr := runLoopUntil(t, args, canaryDepsWith(cycler, &runs, failingReport, nil),
		func(_, errOut *syncBuffer) bool { return strings.Contains(errOut.String(), "worm canary: FAILED") })
	// A failed canary is a finding about the bucket, reported where the
	// operator looks; it does not stop the sealer or change its verdict.
	if code != exitOK {
		t.Errorf("a failed canary changed the sealer's exit to %d", code)
	}
	if strings.Contains(stdout.String(), "worm canary") {
		t.Errorf("-quiet still printed a canary line on stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr.String(), segment.CheckVersionDeleteRefused) {
		t.Errorf("stderr does not name the failed check:\n%s", stderr)
	}
	rec, err := segment.LoadCanaryRecord(file)
	if err != nil || rec.OK || len(rec.FailedChecks) != 1 {
		t.Fatalf("recorded %+v, %v", rec, err)
	}
}

func TestSEG014TheCanaryIsOffForOneCycleAndForAZeroInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"-once", minimalSealArgs("-canary-interval", "1h")},
		{"no interval", withoutFlag(minimalSealArgs(), "-once")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runs atomic.Int64
			built := false
			cycler := &stubCycler{cycles: []stubCycle{{result: sealCycle{}}}}
			deps := stubDeps(cycler)
			deps.canary = func(sealOptions) *segment.CanarySchedule { built = true; return nil }
			if tc.name == "-once" {
				var out, errOut bytes.Buffer
				if code := runSealLoop(t.Context(), tc.args, &out, &errOut, deps); code != exitOK {
					t.Fatalf("exit %d: %s", code, errOut.String())
				}
			} else {
				runLoopUntil(t, append(tc.args, "-interval", "1ms"), deps,
					func(_, _ *syncBuffer) bool { return cycler.calls() >= 3 })
			}
			if built || runs.Load() != 0 {
				t.Fatal("the canary was scheduled")
			}
		})
	}
}

func TestSEG014RefusesANegativeCanaryInterval(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runSealLoop(t.Context(), minimalSealArgs("-canary-interval", "-1h"), &out, &errOut,
		stubDeps(&stubCycler{cycles: []stubCycle{{}}}))
	if code != exitUsage || !strings.Contains(errOut.String(), "-canary-interval") {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut.String())
	}
}

func TestSEG014CanaryFlagsFallBackToTheEnvironment(t *testing.T) {
	t.Setenv(envCanaryInterval, "6h")
	t.Setenv(envCanaryStatusFile, "/run/x.json")
	t.Setenv(envProbeRetn, "24h")
	t.Setenv(envMinBucket, "48h")
	opts, _, _, code := parseSealFlags(minimalSealArgs(), io.Discard)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if opts.canaryInterval != 6*time.Hour || opts.canaryStatusFile != "/run/x.json" ||
		opts.canaryProbeRetention != 24*time.Hour || opts.canaryMinBucketRetention != 48*time.Hour {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestSealDepsDefaultsToTheProductionCanary(t *testing.T) {
	s := sealDeps{}.canaryBuilder()(sealOptions{canaryInterval: time.Hour, canaryStatusFile: "f"})
	if s == nil || s.Interval != time.Hour || s.StatusFile != "f" || s.Run == nil || s.Sweep == nil {
		t.Fatalf("schedule = %+v", s)
	}
}

// SEG-014, against a real object store: the production schedule writes its
// probe under the canary prefix even when the sealer writes segments under
// its own, passes on a locked bucket, fails on an unlocked one by check
// name, and records a store it cannot reach as a run that could not happen.
func TestSEG014TheProductionScheduleAgainstARealStore(t *testing.T) {
	c := requireObjectStoreForCLI(t)
	opts := func(bucket, endpoint string) sealOptions {
		return sealOptions{
			endpoint: endpoint, bucket: bucket, prefix: "segments/",
			accessKey: cliObjectStoreUser, secretKey: cliObjectStorePassword,
			mode: string(segment.RetentionCompliance), opTimeout: 30 * time.Second,
			canaryInterval: time.Hour, canaryStatusFile: filepath.Join(t.TempDir(), "c.json"),
			canaryProbeRetention: 2 * time.Minute,
		}
	}

	locked := opts(makeBucket(t, c, true), c.endpoint)
	rec, ran := newCanarySchedule(locked).RunIfDue(t.Context())
	if !ran || !rec.OK {
		t.Fatalf("locked bucket: ran=%v %+v", ran, rec)
	}
	if !strings.HasPrefix(rec.ProbeKey, segment.CanaryProbePrefix) {
		t.Errorf("probe %q is not under %s", rec.ProbeKey, segment.CanaryProbePrefix)
	}
	cl, err := c.client()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.StatObject(t.Context(), locked.bucket, rec.ProbeKey, minio.StatObjectOptions{}); err != nil {
		t.Errorf("the probe is not at %s itself (the segment prefix must not apply): %v", rec.ProbeKey, err)
	}

	unlocked := opts(makeBucket(t, c, false), c.endpoint)
	rec, _ = newCanarySchedule(unlocked).RunIfDue(t.Context())
	if rec.OK || len(rec.FailedChecks) == 0 {
		t.Fatalf("unlocked bucket recorded %+v", rec)
	}

	gone := opts("nowhere", "127.0.0.1:1")
	gone.opTimeout = 2 * time.Second
	rec, _ = newCanarySchedule(gone).RunIfDue(t.Context())
	if rec.OK || rec.Inconclusive == "" || rec.SweepError == "" {
		t.Fatalf("unreachable store recorded %+v", rec)
	}
}

// OPS-172 (proposed for doc 07), the status half — the scheduled canary's
// last result is a component of the core's status, so `innsegl status`
// names it DOWN, with the failing check, and exits 1.
func TestOPS172TheCoreReportsTheScheduledCanary(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	file := filepath.Join(t.TempDir(), "worm-canary.json")

	if canaryHealthReports("", clock) != nil {
		t.Fatal("no status file configured, yet a report was built")
	}
	reports := canaryHealthReports(file, clock)

	got := reports()
	if len(got) != 1 || got[0].Name != canaryComponent || got[0].OK || !strings.Contains(got[0].Detail, "no run recorded") {
		t.Fatalf("no record: %+v", got)
	}
	write := func(rec segment.CanaryRecord) {
		t.Helper()
		if err := segment.WriteCanaryRecord(file, rec); err != nil {
			t.Fatal(err)
		}
	}
	write(segment.CanaryRecord{FinishedAt: now.Add(-time.Hour), Interval: "24h0m0s", OK: true})
	if got := reports(); !got[0].OK {
		t.Fatalf("a recent pass: %+v", got)
	}
	write(segment.CanaryRecord{FinishedAt: now.Add(-49 * time.Hour), Interval: "24h0m0s", OK: true})
	if got := reports(); got[0].OK || !strings.Contains(got[0].Detail, "stale") {
		t.Fatalf("a stale pass: %+v", got)
	}
	write(segment.CanaryRecord{FinishedAt: now.Add(-time.Hour), Interval: "24h0m0s",
		FailedChecks: []string{segment.CheckVersionDeleteRefused}})
	failed := reports()
	if failed[0].OK || !strings.Contains(failed[0].Detail, segment.CheckVersionDeleteRefused) {
		t.Fatalf("a failed run: %+v", failed)
	}

	// The health listener carries it; the core's status turns it into a
	// component; the client prints it DOWN and exits 1.
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(map[string]any{
			"ready":        true,
			"dependencies": []map[string]any{{"dependency": "ledger", "reachable": true}},
			"reports":      failed,
		})
		if err != nil {
			t.Error(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(ready.Close)
	t.Setenv(envMCPHealthListen, strings.TrimPrefix(ready.URL, "http://"))
	components := coreReadiness(t.Context())
	if len(components) != 2 || components[1].Name != canaryComponent || components[1].Up {
		t.Fatalf("components = %+v", components)
	}
	raw, err := json.Marshal(components)
	if err != nil {
		t.Fatal(err)
	}
	deps := statusFixture(t, string(raw), true)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code == exitOK {
		t.Fatalf("exit 0 with the canary failed:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "down: "+canaryComponent) {
		t.Errorf("stderr does not name the canary:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), segment.CheckVersionDeleteRefused) {
		t.Errorf("stdout does not name the failed check:\n%s", out.String())
	}
}
