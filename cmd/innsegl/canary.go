// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strconv"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// `innsegl canary` — the WORM deletion canary as an operator-runnable command.
//
// IP §6.4 requires "a deploy-time check that attempts to delete a canary object
// and must be refused by the storage layer; deployment fails if deletion
// succeeds". Doc 05 §2 requires the same check to run "as a scheduled job in
// production, not only at deploy".
//
// Those are one requirement with two callers, and a subcommand whose exit
// status is the verdict serves both without either of them having to parse
// anything: a deploy step runs it and stops on non-zero, a cron or Kubernetes
// CronJob runs it and alerts on non-zero. There is no "warn" outcome. IP §6.4
// says the deployment fails, so the command has no mode in which a permitted
// deletion exits zero.

// Exit statuses for `innsegl canary`, continuing cli.go's contract.
//
// Any non-zero status fails the gate. The distinction below exists so an
// operator can tell "the store let me delete a sealed record" from "I never
// got far enough to find out" — both are failures, and treating the second as
// a pass is the failure mode this command exists to prevent.
const (
	// exitCanaryFailed: the canary ran and at least one check did not hold.
	exitCanaryFailed = 3
	// exitCanaryInconclusive: the canary could not be run — bad configuration,
	// an unreachable store, absent credentials. Nothing was proved, so it
	// fails closed.
	exitCanaryInconclusive = 4
)

// Every flag falls back to an environment variable, so a scheduled job can be
// configured entirely by environment and never put a secret on a command line
// where the process table can read it.
const (
	envEndpoint  = "INNSEGL_OBJECT_STORE_ENDPOINT"
	envBucket    = "INNSEGL_OBJECT_STORE_BUCKET"
	envAccessKey = "INNSEGL_OBJECT_STORE_ACCESS_KEY"
	//nolint:gosec // the name of an environment variable, not a credential
	envSecretKey  = "INNSEGL_OBJECT_STORE_SECRET_KEY"
	envRegion     = "INNSEGL_OBJECT_STORE_REGION"
	envPrefix     = "INNSEGL_OBJECT_STORE_PREFIX"
	envTLS        = "INNSEGL_OBJECT_STORE_TLS"
	envMode       = "INNSEGL_OBJECT_STORE_RETENTION_MODE"
	envRetention  = "INNSEGL_OBJECT_STORE_RETENTION"
	envProbeRetn  = "INNSEGL_CANARY_PROBE_RETENTION"
	envMinBucket  = "INNSEGL_CANARY_MIN_BUCKET_RETENTION"
	envTimeoutVar = "INNSEGL_OBJECT_STORE_TIMEOUT"
)

// canaryDeps are the seams the command's tests replace. Production wiring is
// the zero value.
type canaryDeps struct {
	// open builds the store. Replaced in tests that check exit statuses
	// without a container.
	open func(context.Context, segment.WORMConfig) (*segment.WORM, error)
	// run executes the canary.
	run func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error)
}

func (d canaryDeps) opener() func(context.Context, segment.WORMConfig) (*segment.WORM, error) {
	if d.open != nil {
		return d.open
	}
	return segment.NewWORM
}

func (d canaryDeps) runner() func(context.Context, *segment.WORM, segment.CanaryOptions) (*segment.CanaryReport, error) {
	if d.run != nil {
		return d.run
	}
	return segment.RunCanary
}

// canaryCommand is the subcommand body wired into cli.go's dispatch table.
func canaryCommand(args []string, stdout, stderr io.Writer) int {
	return runCanaryCommand(args, stdout, stderr, canaryDeps{})
}

func runCanaryCommand(args []string, stdout, stderr io.Writer, deps canaryDeps) int {
	fs := flag.NewFlagSet("innsegl canary", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		endpoint  = fs.String("endpoint", os.Getenv(envEndpoint), "object store endpoint, host:port without a scheme ($"+envEndpoint+")")
		bucket    = fs.String("bucket", os.Getenv(envBucket), "bucket holding sealed segments ($"+envBucket+")")
		accessKey = fs.String("access-key", os.Getenv(envAccessKey), "object store access key ($"+envAccessKey+")")
		secretKey = fs.String("secret-key", os.Getenv(envSecretKey), "object store secret key — prefer the environment variable ($"+envSecretKey+")")
		region    = fs.String("region", os.Getenv(envRegion), "object store region, if the store needs one ($"+envRegion+")")
		prefix    = fs.String("prefix", os.Getenv(envPrefix), "key prefix for segment objects ($"+envPrefix+")")
		useTLS    = fs.Bool("tls", envBool(envTLS, true), "use https ($"+envTLS+")")
		mode      = fs.String("mode", envOr(envMode, string(segment.RetentionCompliance)),
			"required retention mode, COMPLIANCE or GOVERNANCE ($"+envMode+")")
		retention = fs.Duration("retention", envDuration(envRetention, 0),
			"retention the writer applies to objects; 0 relies on the bucket's default rule ($"+envRetention+")")
		probeRetention = fs.Duration("probe-retention", envDuration(envProbeRetn, 0),
			"retention for the canary's own probe; 0 uses -retention ($"+envProbeRetn+")")
		minBucketRetention = fs.Duration("min-bucket-retention", envDuration(envMinBucket, 0),
			"require the bucket's default retention to be at least this long; 0 does not check ($"+envMinBucket+")")
		timeout  = fs.Duration("timeout", envDuration(envTimeoutVar, 60*time.Second), "bound on one object store request ($"+envTimeoutVar+")")
		asJSON   = fs.Bool("json", false, "write the report as JSON")
		quietRun = fs.Bool("quiet", false, "print nothing on success; failures are always reported")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl canary - prove the object store refuses to delete a sealed segment (SEG-005)\n\n")
		fprintf(stderr, "Usage:\n  innsegl canary [flags]\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  every check held\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  a check failed - the store permits deletion; fail the deploy\n", exitCanaryFailed)
		fprintf(stderr, "  %d  the canary could not run; nothing was proved, so it fails closed\n", exitCanaryInconclusive)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl canary: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	missing := ""
	switch {
	case *endpoint == "":
		missing = "-endpoint (or $" + envEndpoint + ")"
	case *bucket == "":
		missing = "-bucket (or $" + envBucket + ")"
	case *accessKey == "":
		missing = "-access-key (or $" + envAccessKey + ")"
	case *secretKey == "":
		missing = "-secret-key (or $" + envSecretKey + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl canary: %s is required\n", missing)
		return exitUsage
	}

	ctx := context.Background()

	store, err := deps.opener()(ctx, segment.WORMConfig{
		Endpoint:  *endpoint,
		AccessKey: *accessKey,
		SecretKey: *secretKey,
		UseTLS:    *useTLS,
		Region:    *region,
		Bucket:    *bucket,
		Prefix:    *prefix,
		Mode:      segment.RetentionMode(*mode),
		Retention: *retention,
		OpTimeout: *timeout,
	})
	if err != nil {
		fprintf(stderr, "innsegl canary: %v\n", err)
		fprintf(stderr, "innsegl canary: INCONCLUSIVE - nothing was proved about %s/%s\n", *endpoint, *bucket)
		return exitCanaryInconclusive
	}

	report, err := deps.runner()(ctx, store, segment.CanaryOptions{
		RequiredMode:       segment.RetentionMode(*mode),
		ProbeRetention:     *probeRetention,
		MinBucketRetention: *minBucketRetention,
	})
	if err != nil {
		fprintf(stderr, "innsegl canary: %v\n", err)
		fprintf(stderr, "innsegl canary: INCONCLUSIVE - nothing was proved about %s/%s\n", *endpoint, *bucket)
		return exitCanaryInconclusive
	}

	// A nil report from a nil error would make the gate depend on a nil check
	// somewhere further down. It fails closed here instead.
	if report == nil {
		fprintf(stderr, "innsegl canary: the canary returned no report; nothing was proved\n")
		return exitCanaryInconclusive
	}

	passed := report.OK()
	out := stdout
	if !passed {
		out = stderr
	}
	switch {
	case *asJSON:
		writeCanaryJSON(out, stderr, report)
	case passed && *quietRun:
	default:
		fprintf(out, "%s", report.String())
	}

	if !passed {
		fprintf(stderr,
			"innsegl canary: FAILED - the object store did not refuse deletion of a sealed record (IP §6.4, I4).\n"+
				"Fail this deploy. A bucket's object lock can only be enabled at creation, "+
				"so a bucket without it has to be replaced, not reconfigured.\n")
		return exitCanaryFailed
	}
	return exitOK
}

// writeCanaryJSON emits the report for a scheduled job that feeds a monitor.
// A report that cannot be encoded is still a failure to report, so the error
// goes to stderr rather than changing the verdict.
func writeCanaryJSON(out, stderr io.Writer, report *segment.CanaryReport) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fprintf(stderr, "innsegl canary: the report could not be encoded as JSON: %v\n", err)
		fprintf(out, "%s", report.String())
		return
	}
	fprintf(out, "%s\n", encoded)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envDuration reads a duration from the environment. An unparseable value
// falls back rather than failing: the flag it defaults is still explicit on
// the command line, and flag.Parse reports a bad -flag value itself.
func envDuration(name string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return v
}

func envBool(name string, fallback bool) bool {
	v, err := strconv.ParseBool(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return v
}
