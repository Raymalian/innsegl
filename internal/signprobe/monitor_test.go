// SPDX-License-Identifier: Apache-2.0

package signprobe

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// scripted is a probe whose answers a case sets.
type scripted struct {
	mu      sync.Mutex
	answers []Result
	calls   int
}

func (s *scripted) Probe(context.Context) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	r := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	return r
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var t0 = time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)

// SIG-015 — the readiness report: a pass is ok; a failure is failed with
// the time it started failing and the reason; the time is the FIRST failure,
// not the latest; and a pass clears it.
func TestSIG015TheReportSaysFailingSinceTheFirstFailure(t *testing.T) {
	c := &clock{t: t0}
	s := &scripted{answers: []Result{{OK: true}}}
	m := NewMonitor(s, time.Minute, c.now)

	m.Check(t.Context())
	if st := m.State(); !st.OK || !strings.Contains(st.Detail(), "a certificate was issued at 2026-10-11T09:00:00Z") {
		t.Fatalf("after a pass: %+v %q", st, st.Detail())
	}

	c.add(time.Minute)
	s.answers = []Result{{Reason: "HTTP 500: error communicating with CA backend"}}
	m.Check(t.Context())
	c.add(time.Minute)
	s.answers = []Result{{Reason: "HTTP 500: still broken"}}
	m.Check(t.Context())
	st := m.State()
	if st.OK {
		t.Fatal("ok after two failures")
	}
	want := "FAILING since 2026-10-11T09:01:00Z — HTTP 500: still broken"
	if st.Detail() != want {
		t.Fatalf("detail %q, want %q", st.Detail(), want)
	}
	if !st.Since.Equal(t0.Add(time.Minute)) {
		t.Fatalf("since %v", st.Since)
	}

	c.add(time.Minute)
	s.answers = []Result{{OK: true}}
	m.Check(t.Context())
	if st := m.State(); !st.OK || !st.Since.IsZero() {
		t.Fatalf("a pass did not clear the failure: %+v", st)
	}
}

// SIG-015 — a result older than two intervals is a failure: a probe that
// stopped running must not leave its last pass standing.
func TestSIG015AResultOlderThanTwoIntervalsIsAFailure(t *testing.T) {
	c := &clock{t: t0}
	s := &scripted{answers: []Result{{OK: true}}}
	m := NewMonitor(s, 5*time.Minute, c.now)
	m.Check(t.Context())

	c.add(10 * time.Minute)
	if st := m.State(); !st.OK {
		t.Fatalf("exactly two intervals is not yet stale: %+v", st)
	}
	c.add(time.Second)
	st := m.State()
	if st.OK {
		t.Fatal("a pass ten minutes and a second old is still ok")
	}
	if want := "FAILING since 2026-10-11T09:00:00Z — no probe has finished since then; the probe is not running"; st.Detail() != want {
		t.Fatalf("detail %q, want %q", st.Detail(), want)
	}

	// Stale after a failure keeps the first failure's time.
	s.answers = []Result{{Reason: "refused"}}
	m.Check(t.Context())
	failedAt := c.now()
	c.add(11 * time.Minute)
	if st := m.State(); st.OK || !st.Since.Equal(failedAt) || !strings.Contains(st.Reason, "not running") {
		t.Fatalf("stale after a failure: %+v", st)
	}
}

// SIG-015 — before any probe has finished, the report is not a pass: a
// result nobody measured is not "signing works".
func TestSIG015NoResultYetIsNotAPass(t *testing.T) {
	c := &clock{t: t0}
	m := NewMonitor(&scripted{answers: []Result{{OK: true}}}, 5*time.Minute, c.now)
	st := m.State()
	if st.OK || !strings.Contains(st.Detail(), "the first probe has not finished") {
		t.Fatalf("%+v %q", st, st.Detail())
	}
	c.add(11 * time.Minute)
	if st := m.State(); st.OK || !strings.Contains(st.Detail(), "not running") {
		t.Fatalf("%+v %q", st, st.Detail())
	}
}

// Run probes at once, then every interval, until its context ends.
func TestRunProbesAtOnceAndThenOnSchedule(t *testing.T) {
	s := &scripted{answers: []Result{{OK: true}}}
	m := NewMonitor(s, 20*time.Millisecond, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 110*time.Millisecond)
	defer cancel()
	m.Run(ctx)
	s.mu.Lock()
	n := s.calls
	s.mu.Unlock()
	if n < 3 || n > 7 {
		t.Fatalf("%d probes in 110ms at a 20ms interval", n)
	}
	if !m.State().OK {
		t.Fatal("not ok after passes")
	}
}

// A non-positive interval is the default, never a busy loop.
func TestNewMonitorDefaultsTheInterval(t *testing.T) {
	m := NewMonitor(&scripted{answers: []Result{{OK: true}}}, 0, nil)
	if m.Interval() != DefaultInterval {
		t.Fatalf("interval %v", m.Interval())
	}
}

// SIG-015, JRN-011 (#584): what a refusal says while signing is down is read
// back from the report line, so the line and its reading change together.
func TestSIG015TheDetailReadsBackSinceAndReason(t *testing.T) {
	since := time.Date(2026, 10, 11, 9, 5, 0, 0, time.UTC)
	failing := State{Since: since, Reason: "the CA refused the certificate: HTTP 500"}
	gotSince, reason, ok := ParseFailing(failing.Detail())
	if !ok || !gotSince.Equal(since) || reason != failing.Reason {
		t.Fatalf("ParseFailing(%q) = %v %q %v", failing.Detail(), gotSince, reason, ok)
	}
	for _, d := range []string{
		State{OK: true, CheckedAt: since}.Detail(),
		"",
		"FAILING since yesterday — x",
		"FAILING since 2026-10-11T09:05:00Z",
	} {
		if _, _, ok := ParseFailing(d); ok {
			t.Errorf("ParseFailing(%q) read an outage", d)
		}
	}
}

// CLI-023 (PROPOSED) — `innsegl doctor` reads a passing Detail back to know
// the probe passed after its repair (#588).
func TestCLI023APassingDetailReadsBackItsTime(t *testing.T) {
	at := time.Date(2026, 10, 11, 9, 5, 0, 0, time.UTC)
	got, ok := ParsePassing(State{OK: true, CheckedAt: at}.Detail())
	if !ok || !got.Equal(at) {
		t.Fatalf("ParsePassing = %v %v; want %v", got, ok, at)
	}
	for _, d := range []string{
		State{Since: at, Reason: "x"}.Detail(),
		"",
		"a certificate was issued at yesterday",
	} {
		if _, ok := ParsePassing(d); ok {
			t.Errorf("ParsePassing(%q) read a pass", d)
		}
	}
}
