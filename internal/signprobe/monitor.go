// SPDX-License-Identifier: Apache-2.0

package signprobe

import (
	"context"
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
		return "a certificate was issued at " + stamp(s.CheckedAt)
	}
	return "FAILING since " + stamp(s.Since) + " — " + s.Reason
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

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
