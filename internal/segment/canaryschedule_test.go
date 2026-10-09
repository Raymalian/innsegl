// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// fakeClock is a settable clock for the schedule's tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func passingReport() *CanaryReport {
	r := &CanaryReport{}
	for _, name := range canaryChecks {
		r.Checks = append(r.Checks, CanaryCheck{Name: name, Passed: true})
	}
	return r
}

func failingReport(failed string) *CanaryReport {
	r := passingReport()
	for i := range r.Checks {
		if r.Checks[i].Name == failed {
			r.Checks[i].Passed = false
			r.Checks[i].Detail = "the delete was ACCEPTED"
		}
	}
	return r
}

// SEG-014 (proposed for doc 07) — the scheduled canary runs at its interval
// and records every run, pass or fail, where the core's health reads it.
//
// doc 05 §2: "SEG-005's deletion canary runs as a scheduled job in
// production, not only at deploy." The schedule is due on its first look,
// then once per interval, and that interval is measured from the RECORDED
// run, so a process restarted an hour after a run does not run another.
func TestSEG014ScheduledCanaryRunsAtItsIntervalAndRecordsEveryRun(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	t.Run("due at first, then once per interval, and the record carries the interval", func(t *testing.T) {
		clock := &fakeClock{t: start}
		file := filepath.Join(t.TempDir(), "worm-canary.json")
		runs := 0
		s := &CanarySchedule{
			Interval:   time.Hour,
			StatusFile: file,
			Now:        clock.now,
			Run: func(context.Context) (*CanaryReport, error) {
				runs++
				return passingReport(), nil
			},
		}

		rec, ran := s.RunIfDue(ctx)
		if !ran || runs != 1 {
			t.Fatalf("first look: ran=%v runs=%d, want one run", ran, runs)
		}
		if !rec.OK || rec.Interval != "1h0m0s" || !rec.FinishedAt.Equal(start) {
			t.Fatalf("record = %+v, want OK, interval 1h0m0s, finished at %s", rec, start)
		}
		got, err := LoadCanaryRecord(file)
		if err != nil {
			t.Fatalf("the run was not recorded: %v", err)
		}
		if !got.OK || got.FinishedAt.IsZero() {
			t.Fatalf("recorded %+v", got)
		}

		clock.t = start.Add(59 * time.Minute)
		if _, ran := s.RunIfDue(ctx); ran || runs != 1 {
			t.Fatalf("ran again inside the interval (runs=%d)", runs)
		}
		clock.t = start.Add(time.Hour)
		if _, ran := s.RunIfDue(ctx); !ran || runs != 2 {
			t.Fatalf("did not run once the interval had passed (runs=%d)", runs)
		}
	})

	t.Run("a restarted process reads the last run and does not run early", func(t *testing.T) {
		clock := &fakeClock{t: start}
		file := filepath.Join(t.TempDir(), "worm-canary.json")
		runs := 0
		run := func(context.Context) (*CanaryReport, error) { runs++; return passingReport(), nil }
		first := &CanarySchedule{Interval: 24 * time.Hour, StatusFile: file, Now: clock.now, Run: run}
		first.RunIfDue(ctx)

		clock.t = start.Add(time.Hour)
		restarted := &CanarySchedule{Interval: 24 * time.Hour, StatusFile: file, Now: clock.now, Run: run}
		if _, ran := restarted.RunIfDue(ctx); ran {
			t.Fatal("a restart an hour after a recorded run ran the canary again")
		}
		clock.t = start.Add(24 * time.Hour)
		if _, ran := restarted.RunIfDue(ctx); !ran {
			t.Fatal("the restarted schedule did not run once the recorded run was an interval old")
		}
		if runs != 2 {
			t.Fatalf("runs = %d, want 2", runs)
		}
	})

	t.Run("a failed check is recorded by name", func(t *testing.T) {
		clock := &fakeClock{t: start}
		file := filepath.Join(t.TempDir(), "worm-canary.json")
		s := &CanarySchedule{Interval: time.Hour, StatusFile: file, Now: clock.now,
			Run: func(context.Context) (*CanaryReport, error) {
				return failingReport(CheckVersionDeleteRefused), nil
			}}
		rec, _ := s.RunIfDue(ctx)
		if rec.OK {
			t.Fatal("a failing report was recorded as OK")
		}
		if len(rec.FailedChecks) != 1 || rec.FailedChecks[0] != CheckVersionDeleteRefused {
			t.Fatalf("failed checks = %v, want [%s]", rec.FailedChecks, CheckVersionDeleteRefused)
		}
		got, err := LoadCanaryRecord(file)
		if err != nil || got.OK || len(got.FailedChecks) != 1 {
			t.Fatalf("recorded %+v, %v", got, err)
		}
	})

	t.Run("a canary that could not run is recorded as a failure, never skipped", func(t *testing.T) {
		clock := &fakeClock{t: start}
		file := filepath.Join(t.TempDir(), "worm-canary.json")
		s := &CanarySchedule{Interval: time.Hour, StatusFile: file, Now: clock.now,
			Run: func(context.Context) (*CanaryReport, error) {
				return nil, errors.New("dial tcp: connection refused")
			}}
		rec, ran := s.RunIfDue(ctx)
		if !ran || rec.OK || !strings.Contains(rec.Inconclusive, "connection refused") {
			t.Fatalf("record = %+v, want a recorded inconclusive failure", rec)
		}
		// A nil report from a nil error is no report: it fails closed.
		s.Run = func(context.Context) (*CanaryReport, error) { return nil, nil }
		clock.t = start.Add(time.Hour)
		if rec, _ := s.RunIfDue(ctx); rec.OK || rec.Inconclusive == "" {
			t.Fatalf("a nil report was recorded as %+v", rec)
		}
	})

	t.Run("no status file still runs and returns the record", func(t *testing.T) {
		s := &CanarySchedule{Interval: time.Hour, Now: (&fakeClock{t: start}).now,
			Run: func(context.Context) (*CanaryReport, error) { return passingReport(), nil }}
		if rec, ran := s.RunIfDue(ctx); !ran || !rec.OK {
			t.Fatalf("ran=%v rec=%+v", ran, rec)
		}
		if _, ran := s.RunIfDue(ctx); ran {
			t.Fatal("without a file the schedule forgot its own last run")
		}
	})

	t.Run("an unwritable status file is reported on the record", func(t *testing.T) {
		dir := t.TempDir()
		s := &CanarySchedule{Interval: time.Hour, StatusFile: filepath.Join(dir, "missing", "x.json"),
			Now: (&fakeClock{t: start}).now,
			Run: func(context.Context) (*CanaryReport, error) { return passingReport(), nil }}
		rec, _ := s.RunIfDue(ctx)
		if rec.StatusErr == nil {
			t.Fatal("a status file that could not be written was not reported")
		}
	})

	t.Run("the sweep runs before the canary and is recorded, and never fails it", func(t *testing.T) {
		var order []string
		s := &CanarySchedule{Interval: time.Hour, Now: (&fakeClock{t: start}).now,
			Sweep: func(context.Context) (int, error) {
				order = append(order, "sweep")
				return 3, errors.New("listing stopped")
			},
			Run: func(context.Context) (*CanaryReport, error) {
				order = append(order, "run")
				return passingReport(), nil
			}}
		rec, _ := s.RunIfDue(ctx)
		if strings.Join(order, ",") != "sweep,run" {
			t.Fatalf("order = %v", order)
		}
		if !rec.OK || rec.Swept != 3 || rec.SweepError != "listing stopped" {
			t.Fatalf("record = %+v", rec)
		}
	})

	t.Run("a report missing checks is a failure even with none failed", func(t *testing.T) {
		s := &CanarySchedule{Interval: time.Hour, Now: (&fakeClock{t: start}).now,
			Run: func(context.Context) (*CanaryReport, error) { return &CanaryReport{}, nil }}
		if rec, _ := s.RunIfDue(ctx); rec.OK || rec.Inconclusive == "" {
			t.Fatalf("an empty report was recorded as %+v", rec)
		}
	})

	t.Run("a nil schedule never runs", func(t *testing.T) {
		var s *CanarySchedule
		if _, ran := s.RunIfDue(ctx); ran {
			t.Fatal("a nil schedule ran")
		}
	})

	t.Run("defaults: zero interval is a day, nil clock is the wall clock", func(t *testing.T) {
		s := &CanarySchedule{Run: func(context.Context) (*CanaryReport, error) { return passingReport(), nil }}
		rec, ran := s.RunIfDue(ctx)
		if !ran || rec.Interval != (24*time.Hour).String() {
			t.Fatalf("ran=%v interval=%q, want a run with a 24h interval", ran, rec.Interval)
		}
		if time.Since(rec.FinishedAt) > time.Minute {
			t.Fatalf("finished at %s, not the wall clock", rec.FinishedAt)
		}
	})
}

// SEG-015 (proposed for doc 07) — what the core's health says about the
// scheduled canary: up only for a recent passing run; down, naming the
// failing check, for a failed one; down for a run that could not happen;
// down for no record at all; and down for a record older than twice its
// interval, because a canary that stopped running proves nothing however
// green its last result was.
func TestSEG015CanaryHealthIsDownForAFailureAStaleRunOrNoRun(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	ok := &CanaryRecord{FinishedAt: now.Add(-time.Hour), Interval: "24h0m0s", OK: true}

	cases := []struct {
		name   string
		rec    *CanaryRecord
		err    error
		up     bool
		detail string
	}{
		{"a recent pass is up", ok, nil, true, "passed"},
		{"exactly two intervals old is still up",
			&CanaryRecord{FinishedAt: now.Add(-48 * time.Hour), Interval: "24h0m0s", OK: true}, nil, true, "passed"},
		{"older than two intervals is stale",
			&CanaryRecord{FinishedAt: now.Add(-48*time.Hour - time.Second), Interval: "24h0m0s", OK: true},
			nil, false, "stale"},
		{"a failed check is down and named",
			&CanaryRecord{FinishedAt: now.Add(-time.Hour), Interval: "24h0m0s",
				FailedChecks: []string{CheckVersionDeleteRefused, CheckProbeIntact}}, nil, false,
			"failed: " + CheckVersionDeleteRefused + ", " + CheckProbeIntact},
		{"a run that could not happen is down",
			&CanaryRecord{FinishedAt: now.Add(-time.Hour), Interval: "24h0m0s",
				Inconclusive: "dial tcp: connection refused"}, nil, false, "could not run: dial tcp"},
		{"no record is down", nil, os.ErrNotExist, false, "no run recorded"},
		{"an unreadable record is down", nil, errors.New("bad json"), false, "unreadable: bad json"},
		{"an unparseable interval falls back to a day",
			&CanaryRecord{FinishedAt: now.Add(-30 * time.Hour), Interval: "soon", OK: true}, nil, true, "passed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AssessCanary(tc.rec, tc.err, now)
			if got.OK != tc.up {
				t.Errorf("OK = %v, want %v (%s)", got.OK, tc.up, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.detail) {
				t.Errorf("detail %q does not say %q", got.Detail, tc.detail)
			}
		})
	}

	t.Run("a record round-trips through the file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "c.json")
		if err := WriteCanaryRecord(file, *ok); err != nil {
			t.Fatal(err)
		}
		got, err := LoadCanaryRecord(file)
		if err != nil || !got.OK || !got.FinishedAt.Equal(ok.FinishedAt) {
			t.Fatalf("got %+v, %v", got, err)
		}
		if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCanaryRecord(file); err == nil {
			t.Fatal("a damaged record loaded")
		}
	})
}

// SEG-016 (proposed for doc 07) — the scheduled canary's probes stay
// bounded, against a real object store with object lock.
//
// Every run leaves one retained probe version that nothing can delete until
// its retention passes, and after that nothing would. The sweep removes the
// probe versions whose retention has expired, and only those: a probe still
// retained is refused anyway, and a segment is outside the prefix it lists.
func TestSEG016ScheduledCanarySweepsExpiredProbesOnly(t *testing.T) {
	c := requireObjectStore(t)
	ctx := context.Background()
	bucket := freshBucket(t, c, true)
	w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

	// A probe that expires within the test, and one that does not.
	// Long enough that the run's own checks finish inside it on a loaded
	// machine (4s expired mid-run under -race, measured), short enough to wait out.
	short, err := RunCanary(ctx, w, CanaryOptions{ProbeRetention: 30 * time.Second})
	if err != nil || !short.OK() {
		t.Fatalf("the short-retention canary did not pass: %v\n%s", err, short)
	}
	long, err := RunCanary(ctx, w, CanaryOptions{ProbeRetention: time.Hour})
	if err != nil || !long.OK() {
		t.Fatalf("the long-retention canary did not pass: %v\n%s", err, long)
	}
	// A segment object, retained the same short time, outside the probe prefix.
	segName := "sha256:" + strings.Repeat("ab", 32)
	if err = w.PutContext(ctx, segName, []byte("segment")); err != nil {
		t.Fatalf("writing a segment: %v", err)
	}

	// Wait out the short probe's own retain-until, as the store recorded it.
	time.Sleep(time.Until(short.RetainUntil) + time.Second)

	swept, err := SweepCanaryProbes(ctx, w, time.Now())
	if err != nil {
		t.Fatalf("SweepCanaryProbes: %v", err)
	}
	if swept != 1 {
		t.Errorf("swept %d probe versions, want exactly the expired one", swept)
	}

	cl, err := c.client()
	if err != nil {
		t.Fatal(err)
	}
	left := map[string]int{}
	for o := range cl.ListObjects(ctx, bucket, minio.ListObjectsOptions{WithVersions: true, Recursive: true}) {
		if o.Err != nil {
			t.Fatalf("listing: %v", o.Err)
		}
		left[o.Key]++
	}
	if left[short.ProbeKey] != 0 {
		t.Errorf("the expired probe %s is still there", short.ProbeKey)
	}
	if left[long.ProbeKey] != 1 {
		t.Errorf("the retained probe %s was touched: %d versions left", long.ProbeKey, left[long.ProbeKey])
	}
	if left[segName] != 1 {
		t.Errorf("the segment %s was touched by a probe sweep: %d versions left", segName, left[segName])
	}

	// A second sweep finds nothing more to do.
	if again, err := SweepCanaryProbes(ctx, w, time.Now()); err != nil || again != 0 {
		t.Errorf("second sweep: %d, %v; want 0, nil", again, err)
	}

	t.Run("a nil store is an error, not a silent zero", func(t *testing.T) {
		if _, err := SweepCanaryProbes(ctx, nil, time.Now()); err == nil {
			t.Fatal("no error for a nil store")
		}
	})
}
