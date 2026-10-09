// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// The scheduled deletion canary.
//
// doc 05 §2: "SEG-005's deletion canary runs as a scheduled job in
// production, not only at deploy. The scheduled canary is a required control,
// not monitoring: it is what detects a downgraded bucket rule, within one run,
// and a deployment that is not running it should fail its own readiness
// reporting rather than report healthy."
//
// A CanarySchedule is that job's clock and its record. The sealer's loop owns
// one, because the sealer is the long-running component that already holds
// the object store credential the canary uses. Each run is written to a
// status file, and AssessCanary is how the core's health reads it back: up
// only for a recent pass.

// DefaultCanaryInterval is how often the scheduled canary runs when no
// interval is given. One run proves one moment; a day bounds how long a
// downgraded bucket rule goes unseen.
const DefaultCanaryInterval = 24 * time.Hour

// canaryStaleFactor is how many intervals may pass without a run before the
// record is stale. One late run is jitter; two is a canary that stopped.
const canaryStaleFactor = 2

// CanaryRecord is one scheduled run, as written to the status file.
type CanaryRecord struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	// Interval is the schedule the run belongs to, so a reader can tell a
	// stale record without being configured with the same number.
	Interval string `json:"interval"`
	OK       bool   `json:"ok"`
	// FailedChecks names every check that did not hold.
	FailedChecks []string `json:"failed_checks,omitempty"`
	// Inconclusive is why the canary could not run at all. Not empty means
	// failed: nothing was proved.
	Inconclusive string `json:"inconclusive,omitempty"`
	// ProbeKey is the probe this run wrote.
	ProbeKey string `json:"probe_key,omitempty"`
	// Swept is how many expired probe versions this run removed, and
	// SweepError why the sweep stopped, if it did. Neither changes OK: the
	// sweep keeps the probes bounded, it proves nothing about the lock.
	Swept      int    `json:"swept,omitempty"`
	SweepError string `json:"sweep_error,omitempty"`

	// StatusErr is a status file that could not be written. Not recorded.
	StatusErr error `json:"-"`
}

// CanarySchedule runs the canary once per Interval and records each run.
type CanarySchedule struct {
	// Interval between runs. Zero means DefaultCanaryInterval.
	Interval time.Duration
	// StatusFile is where each run is recorded. Empty records nothing, and
	// the schedule then counts from its own last run.
	StatusFile string
	// Run is one canary run. Required.
	Run func(context.Context) (*CanaryReport, error)
	// Sweep removes expired probes before each run, and says how many. Nil
	// sweeps nothing.
	Sweep func(context.Context) (int, error)
	// Now is the clock. Nil is time.Now.
	Now func() time.Time

	last time.Time
}

func (s *CanarySchedule) interval() time.Duration {
	if s.Interval <= 0 {
		return DefaultCanaryInterval
	}
	return s.Interval
}

func (s *CanarySchedule) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// due reports whether a run is due: when there is no last run, or the last
// one is an interval old. The last run is the recorded one when there is a
// record, so a restarted process does not run early.
func (s *CanarySchedule) due(now time.Time) bool {
	last := s.last
	if s.StatusFile != "" {
		if rec, err := LoadCanaryRecord(s.StatusFile); err == nil && rec.FinishedAt.After(last) {
			last = rec.FinishedAt
		}
	}
	return last.IsZero() || !now.Before(last.Add(s.interval()))
}

// RunIfDue runs the canary when it is due and records the result. It
// returns the record and whether a run happened.
func (s *CanarySchedule) RunIfDue(ctx context.Context) (CanaryRecord, bool) {
	if s == nil || s.Run == nil {
		return CanaryRecord{}, false
	}
	started := s.now()
	if !s.due(started) {
		return CanaryRecord{}, false
	}
	rec := CanaryRecord{StartedAt: started, Interval: s.interval().String()}
	if s.Sweep != nil {
		n, err := s.Sweep(ctx)
		rec.Swept = n
		if err != nil {
			rec.SweepError = err.Error()
		}
	}
	report, err := s.Run(ctx)
	switch {
	case err != nil:
		rec.Inconclusive = err.Error()
	case report == nil:
		rec.Inconclusive = "the canary returned no report; nothing was proved"
	default:
		rec.ProbeKey = report.ProbeKey
		for _, c := range report.Checks {
			if !c.Passed {
				rec.FailedChecks = append(rec.FailedChecks, c.Name)
			}
		}
		rec.OK = report.OK()
		if !rec.OK && len(rec.FailedChecks) == 0 {
			rec.Inconclusive = "the report did not run every check"
		}
	}
	rec.FinishedAt = s.now()
	s.last = rec.FinishedAt
	if s.StatusFile != "" {
		rec.StatusErr = WriteCanaryRecord(s.StatusFile, rec)
	}
	return rec, true
}

// WriteCanaryRecord writes a record atomically: a reader never sees half.
func WriteCanaryRecord(path string, rec CanaryRecord) error {
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	//nolint:gosec // G306: a pass/fail record, read by the services that report it
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCanaryRecord reads the status file.
func LoadCanaryRecord(path string) (*CanaryRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec CanaryRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rec, nil
}

// CanaryHealth is the scheduled canary as the core's health reports it.
type CanaryHealth struct {
	OK     bool
	Detail string
}

// AssessCanary turns the last record, or the error reading it, into health.
// Only a passing run younger than twice its interval is up.
func AssessCanary(rec *CanaryRecord, readErr error, now time.Time) CanaryHealth {
	switch {
	case errors.Is(readErr, os.ErrNotExist):
		return CanaryHealth{Detail: "no run recorded; the scheduled canary has not run (doc 05 §2)"}
	case readErr != nil:
		return CanaryHealth{Detail: "the last run's record is unreadable: " + readErr.Error()}
	case rec == nil:
		return CanaryHealth{Detail: "no run recorded"}
	}
	at := rec.FinishedAt.UTC().Format(time.RFC3339)
	interval, err := time.ParseDuration(rec.Interval)
	if err != nil || interval <= 0 {
		interval = DefaultCanaryInterval
	}
	if age := now.Sub(rec.FinishedAt); age > canaryStaleFactor*interval {
		return CanaryHealth{Detail: fmt.Sprintf("stale: the last run was %s, more than %d intervals of %s ago",
			at, canaryStaleFactor, interval)}
	}
	switch {
	case rec.Inconclusive != "":
		return CanaryHealth{Detail: "could not run: " + rec.Inconclusive + " (" + at + ")"}
	case !rec.OK:
		return CanaryHealth{Detail: "failed: " + strings.Join(rec.FailedChecks, ", ") + " (" + at + ")"}
	}
	return CanaryHealth{OK: true, Detail: "passed " + at + ", every " + interval.String()}
}

// SweepCanaryProbes permanently removes the probe versions whose retention
// has passed, and returns how many it removed.
//
// Every canary run leaves one retained probe, which nothing can delete until
// its retention passes and nothing else ever would after. A run a day would
// grow the probe prefix without bound; this keeps it to roughly one probe per
// run inside the probe retention. It lists only the probe prefix, so a
// segment is never a candidate, and it asks for a version's retention before
// deleting it, so a probe still retained is left alone rather than refused.
func SweepCanaryProbes(ctx context.Context, w *WORM, now time.Time) (int, error) {
	if w == nil {
		return 0, fmt.Errorf("%w: no object store", ErrCanary)
	}
	opCtx, cancel := w.op(ctx)
	defer cancel()

	prefix := w.key(CanaryProbePrefix)
	swept := 0
	for object := range w.client.ListObjects(opCtx, w.bucket, minio.ListObjectsOptions{
		Prefix: prefix, WithVersions: true, Recursive: true,
	}) {
		if object.Err != nil {
			return swept, object.Err
		}
		if !strings.HasPrefix(object.Key, prefix) {
			continue
		}
		if !object.IsDeleteMarker {
			_, until, err := w.client.GetObjectRetention(opCtx, w.bucket, object.Key, object.VersionID)
			if err != nil {
				return swept, err
			}
			if until != nil && until.After(now) {
				continue
			}
		}
		if err := w.client.RemoveObject(opCtx, w.bucket, object.Key,
			minio.RemoveObjectOptions{VersionID: object.VersionID}); err != nil {
			return swept, err
		}
		swept++
	}
	return swept, nil
}
