// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/segment"
)

// The scheduled deletion canary (doc 05 §2), run from the sealer's loop.
//
// The sealer is the long-running component that already holds the object
// store credential the canary uses, on the network the store is on, so the
// schedule lives in its loop rather than in a container of its own. Each run
// is recorded to a status file; the core's health reads it back as a report
// (never a reason to be unready), and `innsegl status` names it.

const (
	envCanaryInterval   = "INNSEGL_CANARY_INTERVAL"
	envCanaryStatusFile = "INNSEGL_CANARY_STATUS_FILE"

	// canaryComponent is the scheduled canary's name in the core's health
	// and in `innsegl status`.
	canaryComponent = "worm canary"
)

// newCanarySchedule is the production schedule: each run opens the store,
// removes expired probes, and runs SEG-005.
//
// The store is opened WITHOUT the sealer's segment prefix. Probes live under
// segment.CanaryProbePrefix at the bucket's root, which is the second prefix
// the scoped identity may write (deploy/compose/innsegl/s3-identities.sh),
// and which keeps them out of every ledger backup. Opening per run means a
// store that was down at start-up is measured when it comes back, and one
// that is down at run time is recorded as a run that could not happen.
func newCanarySchedule(opts sealOptions) *segment.CanarySchedule {
	cfg := segment.WORMConfig{
		Endpoint:  opts.endpoint,
		AccessKey: opts.accessKey,
		SecretKey: opts.secretKey,
		UseTLS:    opts.useTLS,
		Region:    opts.region,
		Bucket:    opts.bucket,
		Mode:      segment.RetentionMode(opts.mode),
		Retention: opts.retention,
		OpTimeout: opts.opTimeout,
	}
	return &segment.CanarySchedule{
		Interval:   opts.canaryInterval,
		StatusFile: opts.canaryStatusFile,
		Sweep: func(ctx context.Context) (int, error) {
			w, err := segment.NewWORM(ctx, cfg)
			if err != nil {
				return 0, err
			}
			return segment.SweepCanaryProbes(ctx, w, time.Now())
		},
		Run: func(ctx context.Context) (*segment.CanaryReport, error) {
			w, err := segment.NewWORM(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return segment.RunCanary(ctx, w, segment.CanaryOptions{
				RequiredMode:       segment.RetentionMode(opts.mode),
				ProbeRetention:     opts.canaryProbeRetention,
				MinBucketRetention: opts.canaryMinBucketRetention,
			})
		},
	}
}

// canary writes one scheduled run to the loop's log: a pass on stdout unless
// -quiet, anything else on stderr always.
func (r sealReporter) canary(rec segment.CanaryRecord) {
	switch {
	case rec.Inconclusive != "":
		fprintf(r.stderr, "innsegl seal: worm canary: INCONCLUSIVE - %s\n", rec.Inconclusive)
	case !rec.OK:
		fprintf(r.stderr, "innsegl seal: worm canary: FAILED - %s did not hold; the object store "+
			"may permit deletion of a sealed record (IP §6.4)\n", strings.Join(rec.FailedChecks, ", "))
	case !r.quiet:
		fprintf(r.stdout, "worm canary: PASS  probe %s  swept %d\n", rec.ProbeKey, rec.Swept)
	}
	if rec.SweepError != "" {
		fprintf(r.stderr, "innsegl seal: worm canary: the probe sweep stopped: %s\n", rec.SweepError)
	}
	if rec.StatusErr != nil {
		fprintf(r.stderr, "innsegl seal: worm canary: the result could not be recorded: %v\n", rec.StatusErr)
	}
}

// canaryHealthReports is the core's health report of the scheduled canary,
// read from its status file. No file configured reports nothing.
func canaryHealthReports(statusFile string, now func() time.Time) func() []mcp.HealthReport {
	if statusFile == "" {
		return nil
	}
	return func() []mcp.HealthReport {
		rec, err := segment.LoadCanaryRecord(statusFile)
		h := segment.AssessCanary(rec, err, now())
		return []mcp.HealthReport{{Name: canaryComponent, OK: h.OK, Detail: h.Detail}}
	}
}
