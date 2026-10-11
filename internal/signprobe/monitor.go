// SPDX-License-Identifier: Apache-2.0

package signprobe

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ReportName is the probe's name in the core's readiness reports and in
// `innsegl status`.
const ReportName = "signing"

// staleAfter is how many intervals a result stays current. Past it the
// probe is not running, and a probe that is not running proves nothing.
const staleAfter = 2

// Probe is what a Monitor runs. *Prober is the shipped one.
type Probe interface {
	Probe(ctx context.Context) Result
}

// Monitor runs a probe on a schedule and keeps what readiness reports.
type Monitor struct {
	probe    Probe
	interval time.Duration
	now      func() time.Time
	started  time.Time

	mu           sync.Mutex
	last         Result
	checked      bool
	failingSince time.Time
}

// NewMonitor builds a Monitor. A non-positive interval is DefaultInterval;
// nil now is time.Now.
func NewMonitor(p Probe, interval time.Duration, now func() time.Time) *Monitor {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if now == nil {
		now = time.Now
	}
	return &Monitor{probe: p, interval: interval, now: now, started: now()}
}

// Interval is the schedule's period.
func (m *Monitor) Interval() time.Duration { return m.interval }

// Run probes at once and then every interval until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		m.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check runs one probe now and records it. The time recorded is the
// monitor's clock when the probe finished.
func (m *Monitor) Check(ctx context.Context) Result {
	r := m.probe.Probe(ctx)
	at := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	r.At = at
	switch {
	case r.OK:
		m.failingSince = time.Time{}
	case m.failingSince.IsZero():
		m.failingSince = at
	}
	m.last, m.checked = r, true
	return r
}

// State is the probe's standing, as readiness reports it.
type State struct {
	// OK is true when the last probe passed and is current.
	OK bool
	// CheckedAt is when the last probe finished; zero before the first.
	CheckedAt time.Time
	// Since is when signing started failing; zero while it works.
	Since time.Time
	// Reason is why, in an operator's words; empty while it works.
	Reason string
}

// Detail is the one line readiness and `innsegl status` show:
// "FAILING since <time> — <reason>", or when the last certificate was
// issued.
func (s State) Detail() string {
	if s.OK {
		return passingPrefix + stamp(s.CheckedAt)
	}
	return failingPrefix + stamp(s.Since) + failingSep + s.Reason
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// failingPrefix and failingSep frame a failing Detail; passingPrefix a
// passing one.
const (
	passingPrefix = "a certificate was issued at "
	failingPrefix = "FAILING since "
	failingSep    = " — "
)

// ParseFailing reads a failing Detail back: since when, and why. ok is
// false for a passing Detail or a line it cannot read.
func ParseFailing(detail string) (since time.Time, reason string, ok bool) {
	rest, found := strings.CutPrefix(detail, failingPrefix)
	if !found {
		return time.Time{}, "", false
	}
	at, reason, found := strings.Cut(rest, failingSep)
	if !found {
		return time.Time{}, "", false
	}
	since, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return time.Time{}, "", false
	}
	return since, reason, true
}

// ParsePassing reads a passing Detail back: when the certificate was
// issued. ok is false for a failing Detail or a line it cannot read.
func ParsePassing(detail string) (at time.Time, ok bool) {
	rest, found := strings.CutPrefix(detail, passingPrefix)
	if !found {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, rest)
	return at, err == nil
}

// State answers what readiness reports now.
func (m *Monitor) State() State {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	stale := m.interval * staleAfter
	if !m.checked {
		st := State{Since: m.started, Reason: "the first probe has not finished"}
		if now.Sub(m.started) > stale {
			st.Reason = "no probe has finished; the probe is not running"
		}
		return st
	}
	st := State{OK: m.last.OK, CheckedAt: m.last.At, Since: m.failingSince, Reason: m.last.Reason}
	if now.Sub(m.last.At) > stale {
		st.OK = false
		if st.Since.IsZero() {
			st.Since = m.last.At
		}
		st.Reason = "no probe has finished since then; the probe is not running"
		if !m.last.OK {
			st.Reason = "no probe has finished since " + stamp(m.last.At) + " (" + m.last.Reason + "); the probe is not running"
		}
	}
	return st
}
