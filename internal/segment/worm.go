// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// The WORM writer and its deletion canary.
//
// IP §1 requires sealed segments to be "written to object storage with
// WORM/object-lock", and IP §6.4 requires the configuration to be *proved*
// rather than assumed: "a deploy-time check that attempts to delete a canary
// object and must be refused by the storage layer; deployment fails if
// deletion succeeds". Doc 05 §2 adds that the check runs "as a scheduled job
// in production, not only at deploy", and that the mode is compliance.
//
// # What object lock does and does not protect against
//
// Stating this narrowly matters more than stating it reassuringly. S3 object
// lock, in compliance mode, refuses to permanently delete or overwrite a
// specific object *version* until its retain-until date passes. That is the
// whole of the guarantee. In particular:
//
//   - **It expires.** After retain-until, the version is ordinary and can be
//     deleted by anyone with delete permission. A retention window shorter
//     than the audit horizon is a deletion scheduled in advance. The canary
//     reports the bucket's configured window; it cannot know your horizon.
//   - **Governance mode is bypassable.** A caller holding
//     s3:BypassGovernanceRetention deletes a governance-locked version at
//     will. This is why doc 05 §2 says compliance, and why the canary attempts
//     a bypassing delete and requires *that* to be refused too, rather than
//     trusting the mode string the bucket reports.
//   - **Keys are not protected, versions are.** An ordinary DELETE on a locked
//     key still succeeds: it writes a delete marker, and the object stops
//     being visible to readers that do not ask for a version. Nothing is
//     destroyed — the marker itself can be removed — but a segment can be
//     hidden. The ledger's segment_sealed events remain the ordered index that
//     makes such a gap detectable (ADR-0006), and detection is the claim here,
//     not prevention.
//   - **It is an API-level control.** It says nothing about someone who
//     destroys the storage itself: wiping the volume, deleting the tenancy,
//     or a provider acting on the account. Immutability of records against
//     an operator with API credentials is the threat it addresses (doc 04
//     AB-02), not durability.
//   - **A canary run is evidence about one moment.** It proves that this
//     bucket, with these credentials, refused a deletion just now. A later
//     configuration change, a different credential, or an object written by a
//     path that sets no retention are all outside what it saw. That is the
//     entire reason doc 05 §2 makes it a scheduled job rather than a
//     deploy-time ritual.
//
// This is the same honesty RM-009 recorded about the ledger's append-only
// triggers, which a Postgres superuser can disable. Neither control is a
// guarantee against the platform operator. Both are guarantees that a deletion
// leaves evidence.

// RetentionMode is an S3 object-lock retention mode.
type RetentionMode string

const (
	// RetentionCompliance is what doc 05 §2 requires in production: no
	// principal, including the account root, can shorten the retention or
	// delete the version before it expires.
	RetentionCompliance RetentionMode = "COMPLIANCE"

	// RetentionGovernance refuses deletion only by callers without
	// s3:BypassGovernanceRetention. It is accepted by this package so an
	// operator can configure it knowingly; the canary's default required mode
	// is compliance, and the bypass check fails against a governance bucket
	// whose bypass privilege the canary's own credentials hold.
	RetentionGovernance RetentionMode = "GOVERNANCE"
)

func (m RetentionMode) valid() bool {
	return m == RetentionCompliance || m == RetentionGovernance
}

// The canary's checks. Each is a named, separately reported gate: an operator
// reading a failure has to be able to see *which* property did not hold, and a
// test asserting the canary bites has to be able to name the one it expects to
// fail.
const (
	// CheckBucketObjectLock is the bucket's own object-lock configuration.
	CheckBucketObjectLock = "bucket_object_lock_enabled"
	// CheckProbeWritten is whether the probe could be stored at all. Every
	// later check depends on it, so a failure here fails them all rather than
	// leaving them unreported.
	CheckProbeWritten = "probe_written"
	// CheckProbeRetained is whether the stored probe carries a retention that
	// has not already expired.
	CheckProbeRetained = "probe_carries_retention"
	// CheckRetentionMode is whether that retention is in the required mode.
	CheckRetentionMode = "retention_mode"
	// CheckVersionDeleteRefused is SEG-005 itself: a permanent delete of the
	// probe's version must be refused.
	CheckVersionDeleteRefused = "version_delete_refused"
	// CheckBypassDeleteRefused repeats it asking the store to bypass
	// governance retention. Compliance mode ignores the request; governance
	// mode honours it for a privileged caller, which is the difference doc 05
	// §2 cares about.
	CheckBypassDeleteRefused = "privileged_bypass_delete_refused"
	// CheckProbeIntact reads the probe back after both attempts. "Refused" is
	// only true if the bytes are still there and unchanged.
	CheckProbeIntact = "probe_bytes_intact"
	// CheckCredentialsCanDelete is the anti-vacuity control. A refusal proves
	// nothing about object lock if these credentials could not have deleted
	// anything in this bucket in the first place, so the canary permanently
	// deletes a version it is allowed to delete and requires that to succeed.
	CheckCredentialsCanDelete = "credentials_can_delete_versions"
)

// canaryChecks is every check, in the order the canary runs them. A check that
// is not reached is still reported — as a failure — so the set of names in a
// report never depends on how far the canary got.
var canaryChecks = []string{
	CheckBucketObjectLock,
	CheckProbeWritten,
	CheckProbeRetained,
	CheckRetentionMode,
	CheckVersionDeleteRefused,
	CheckBypassDeleteRefused,
	CheckProbeIntact,
	CheckCredentialsCanDelete,
}

// CanaryCheckNames returns every check a canary run reports, in order.
//
// A report is only a gate if its shape is fixed: "no check failed" must not be
// reachable by running fewer checks. This is that list, exported so a caller
// or a test can assert against the whole of it.
func CanaryCheckNames() []string {
	out := make([]string, len(canaryChecks))
	copy(out, canaryChecks)
	return out
}

var (
	// ErrWORMConfig reports a WORM store that cannot be built from the
	// configuration given.
	ErrWORMConfig = errors.New("worm object store is misconfigured")

	// ErrWriteOnce reports a second write of a name that already holds
	// different bytes. Names are content addresses (ADR-0006), so this is
	// either corruption or a claim that two byte strings share a digest.
	ErrWriteOnce = errors.New("object store name already holds different bytes")

	// ErrCanary reports a canary that could not be run at all, as distinct
	// from one that ran and failed — which is a report, not an error.
	ErrCanary = errors.New("worm deletion canary could not run")
)

const (
	// defaultOpTimeout bounds one object-store request. Store's Get and Put
	// take no context (seal.go), so the bound has to live here.
	defaultOpTimeout = 60 * time.Second

	// segmentContentType is what a sealed segment object is: the canonical
	// JSON of ADR-0006's format.
	segmentContentType = "application/json"

	// canaryProbePrefix keeps probes out of the segment namespace. Segment
	// names are `sha256:`-prefixed digests, so nothing can collide with this.
	canaryProbePrefix = "innsegl-worm-canary/"
)

// WORMConfig is everything needed to write segments to an S3-compatible
// object store with object lock.
type WORMConfig struct {
	// Endpoint is host:port, without a scheme.
	Endpoint string
	// AccessKey and SecretKey are the store credentials.
	AccessKey string
	SecretKey string
	// UseTLS selects https. It is off only for a local test server.
	UseTLS bool
	// Region is the S3 region, if the store needs one.
	Region string
	// Bucket must already exist with object lock enabled. This package does
	// not create it: a bucket's object-lock configuration can only be set at
	// creation, and a writer that silently creates one is a writer that can
	// silently create one without a lock.
	Bucket string
	// Prefix is prepended to every object name. Empty keeps a segment's key
	// exactly equal to its segment_id, which is what ADR-0006 describes.
	Prefix string
	// Mode is the retention mode applied to written objects. Defaults to
	// compliance (doc 05 §2).
	Mode RetentionMode
	// Retention is the retention applied to every object written. Zero means
	// this writer sets none and relies on the bucket's own default
	// object-lock configuration — which the canary then reports, so that
	// "nothing sets a retention anywhere" cannot pass unnoticed.
	Retention time.Duration
	// OpTimeout bounds a single request. Zero means defaultOpTimeout.
	OpTimeout time.Duration
}

// WORM is a Store backed by S3-compatible object storage with object lock.
type WORM struct {
	client    *minio.Client
	endpoint  string
	bucket    string
	prefix    string
	mode      RetentionMode
	retention time.Duration
	timeout   time.Duration
}

// WORM is the Store the sealer writes segments through.
var _ Store = (*WORM)(nil)

// NewWORM connects to the object store and checks the bucket is there.
func NewWORM(ctx context.Context, cfg WORMConfig) (*WORM, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, fmt.Errorf("%w: no endpoint", ErrWORMConfig)
	case cfg.Bucket == "":
		return nil, fmt.Errorf("%w: no bucket", ErrWORMConfig)
	case cfg.Retention < 0:
		return nil, fmt.Errorf("%w: retention %s is negative", ErrWORMConfig, cfg.Retention)
	}
	mode := cfg.Mode
	if mode == "" {
		mode = RetentionCompliance
	}
	if !mode.valid() {
		return nil, fmt.Errorf("%w: retention mode %q is not %s or %s",
			ErrWORMConfig, cfg.Mode, RetentionCompliance, RetentionGovernance)
	}
	timeout := cfg.OpTimeout
	if timeout <= 0 {
		timeout = defaultOpTimeout
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseTLS,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWORMConfig, err)
	}

	w := &WORM{
		client:    client,
		endpoint:  cfg.Endpoint,
		bucket:    cfg.Bucket,
		prefix:    cfg.Prefix,
		mode:      mode,
		retention: cfg.Retention,
		timeout:   timeout,
	}

	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("%w: reaching bucket %s: %w", ErrWORMConfig, cfg.Bucket, err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: bucket %s does not exist; "+
			"create it with object lock enabled, which can only be done at creation",
			ErrWORMConfig, cfg.Bucket)
	}
	return w, nil
}

// key maps a Store name to an object key.
func (w *WORM) key(name string) string { return w.prefix + name }

// op bounds one request, for the Store methods that are handed no context.
func (w *WORM) op(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, w.timeout)
}

// Get reads an object. An absent name returns ErrObjectNotFound, which is how
// the sealer tells "not written yet" from "the store is broken" (seal.go).
func (w *WORM) Get(name string) ([]byte, error) {
	ctx, cancel := w.op(context.Background())
	defer cancel()
	return w.GetContext(ctx, name)
}

// GetContext is Get for a caller that has a context.
func (w *WORM) GetContext(ctx context.Context, name string) ([]byte, error) {
	return w.getVersion(ctx, w.key(name), "")
}

func (w *WORM) getVersion(ctx context.Context, key, version string) ([]byte, error) {
	object, err := w.client.GetObject(ctx, w.bucket, key, minio.GetObjectOptions{VersionID: version})
	if err != nil {
		return nil, w.readError(key, err)
	}
	defer func() { _ = object.Close() }()

	// minio-go defers the request to the first read, so this is where an
	// absent object actually surfaces.
	data, err := io.ReadAll(object)
	if err != nil {
		return nil, w.readError(key, err)
	}
	return data, nil
}

// readError maps an S3 error to this package's vocabulary.
//
// Only a missing object or version becomes ErrObjectNotFound. A missing
// *bucket* deliberately does not: the sealer treats ErrObjectNotFound as "go
// ahead and write", and a broken store must not be mistaken for an empty one.
func (w *WORM) readError(key string, err error) error {
	resp := minio.ToErrorResponse(err)
	if resp.Code == "NoSuchKey" || resp.Code == "NoSuchVersion" {
		return fmt.Errorf("%w: %s/%s", ErrObjectNotFound, w.bucket, key)
	}
	if resp.Code == "" && resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s/%s", ErrObjectNotFound, w.bucket, key)
	}
	return fmt.Errorf("read %s/%s: %w", w.bucket, key, err)
}

// Put stores an object under a content-addressed name, write-once.
//
// The three cases are seal.go's, enforced a second time at the storage
// boundary rather than trusted from the caller: absent, so write; present and
// identical, so adopt; present and different, so refuse. The last case is not
// a race the store can resolve — under a content address it means the bytes
// and the name disagree.
func (w *WORM) Put(name string, data []byte) error {
	ctx, cancel := w.op(context.Background())
	defer cancel()
	return w.PutContext(ctx, name, data)
}

// PutContext is Put for a caller that has a context.
func (w *WORM) PutContext(ctx context.Context, name string, data []byte) error {
	existing, err := w.GetContext(ctx, name)
	switch {
	case err == nil:
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("%w: %s/%s", ErrWriteOnce, w.bucket, w.key(name))
		}
		return nil
	case errors.Is(err, ErrObjectNotFound):
	default:
		return err
	}

	if _, err := w.write(ctx, w.key(name), data, w.mode, w.retention); err != nil {
		return err
	}
	return nil
}

// write is the one place an object is uploaded, so the canary's probe travels
// the same code path as a sealed segment. A probe written some other way would
// prove something about that other way.
func (w *WORM) write(
	ctx context.Context, key string, data []byte, mode RetentionMode, retention time.Duration,
) (minio.UploadInfo, error) {
	opts := minio.PutObjectOptions{ContentType: segmentContentType}
	if retention > 0 {
		opts.Mode = minio.RetentionMode(mode)
		// Second precision: S3 carries retain-until as RFC 3339.
		opts.RetainUntilDate = time.Now().UTC().Add(retention).Truncate(time.Second)
	}
	info, err := w.client.PutObject(ctx, w.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		return minio.UploadInfo{}, fmt.Errorf("write %s/%s: %w", w.bucket, key, err)
	}
	return info, nil
}

// CanaryCheck is one named gate and its outcome.
type CanaryCheck struct {
	Name   string
	Passed bool
	Detail string
}

// CanaryOptions configures one canary run.
type CanaryOptions struct {
	// RequiredMode is the retention mode the bucket must apply. Empty means
	// compliance (doc 05 §2).
	RequiredMode RetentionMode
	// ProbeRetention is the retention put on the probe object. Zero uses the
	// store's own.
	//
	// A probe cannot be deleted for as long as it is retained, so in
	// production a shorter probe retention than the segment retention keeps
	// scheduled runs from accumulating undeletable objects. It does not weaken
	// the check: compliance mode refuses a deletion the same way whatever the
	// window, and the window that matters for the audit horizon is the
	// *bucket's*, which is reported separately.
	ProbeRetention time.Duration
	// MinBucketRetention, when set, requires the bucket's default retention
	// configuration to be at least this long. Zero does not check it: doc 05
	// §2 pins the window to "the organization's audit horizon" and names no
	// number, and this package does not invent one.
	MinBucketRetention time.Duration
}

// BucketLock is the bucket's own object-lock configuration, as observed.
type BucketLock struct {
	// Enabled reports that the bucket was created with object lock.
	Enabled bool
	// DefaultMode, DefaultValidity and DefaultUnit are the bucket's default
	// retention rule, if it has one. A bucket can have object lock enabled and
	// no default rule, in which case objects are protected only if the writer
	// sets retention itself.
	DefaultMode     RetentionMode
	DefaultValidity uint
	DefaultUnit     string
	// Detail carries the store's own words when the configuration could not
	// be read.
	Detail string
}

// Duration renders the bucket's default retention window, or zero when it has
// no default rule. Months are not a unit S3 uses, so only days and years occur.
//
// A validity too large for a time.Duration saturates rather than wrapping. A
// window of nine hundred years is a misconfiguration either way, and a
// silently negative one would turn "longer than required" into "shorter".
func (b BucketLock) Duration() time.Duration {
	var unit time.Duration
	switch strings.ToUpper(b.DefaultUnit) {
	case "DAYS":
		unit = 24 * time.Hour
	case "YEARS":
		unit = 365 * 24 * time.Hour
	default:
		return 0
	}
	validity := uint64(b.DefaultValidity)
	if validity > uint64(math.MaxInt64)/uint64(unit) {
		return time.Duration(math.MaxInt64)
	}
	// Bounded immediately above: validity * unit fits in an int64.
	return time.Duration(validity) * unit //nolint:gosec // bounded on the line above
}

// CanaryReport is the result of one canary run.
//
// It is always returned, complete, whatever happened: a canary that fails
// half-way still has to say which half.
type CanaryReport struct {
	Endpoint string
	Bucket   string
	// ProbeKey is the probe's Store name — what to hand WORM.Get, not the
	// object key, which carries the store's prefix.
	ProbeKey     string
	ProbeVersion string
	// RequiredMode is what this run demanded.
	RequiredMode RetentionMode
	// Mode and RetainUntil are what the store actually applied to the probe.
	Mode        RetentionMode
	RetainUntil time.Time
	// BucketLock is the bucket's configuration as read back.
	BucketLock BucketLock
	Checks     []CanaryCheck
	StartedAt  time.Time
	FinishedAt time.Time
}

// OK reports whether every check passed. It is the whole gate: a caller has
// one boolean to consult, and a check that never ran counts as failed.
func (r *CanaryReport) OK() bool {
	if len(r.Checks) != len(canaryChecks) {
		return false
	}
	for _, c := range r.Checks {
		if !c.Passed {
			return false
		}
	}
	return true
}

// Check returns one named check.
func (r *CanaryReport) Check(name string) (CanaryCheck, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return CanaryCheck{}, false
}

// CheckNames returns the checks the run reported, in order.
func (r *CanaryReport) CheckNames() []string {
	out := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		out = append(out, c.Name)
	}
	return out
}

// String renders the report for an operator or a job log.
func (r *CanaryReport) String() string {
	var b strings.Builder
	verdict := "FAIL"
	if r.OK() {
		verdict = "PASS"
	}
	fmt.Fprintf(&b, "WORM deletion canary (SEG-005): %s\n", verdict)
	fmt.Fprintf(&b, "  store        %s bucket %s\n", r.Endpoint, r.Bucket)
	fmt.Fprintf(&b, "  probe        %s", r.ProbeKey)
	if r.ProbeVersion != "" {
		fmt.Fprintf(&b, " version %s", r.ProbeVersion)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "  required     %s retention\n", r.RequiredMode)
	if r.Mode != "" {
		fmt.Fprintf(&b, "  observed     %s until %s\n", r.Mode, r.RetainUntil.UTC().Format(time.RFC3339))
	} else {
		b.WriteString("  observed     no retention on the probe\n")
	}
	if r.BucketLock.Enabled {
		if r.BucketLock.DefaultMode != "" {
			fmt.Fprintf(&b, "  bucket rule  object lock on, default %s for %d %s\n",
				r.BucketLock.DefaultMode, r.BucketLock.DefaultValidity, r.BucketLock.DefaultUnit)
		} else {
			b.WriteString("  bucket rule  object lock on, no default retention rule\n")
		}
	} else {
		fmt.Fprintf(&b, "  bucket rule  object lock NOT enabled (%s)\n", r.BucketLock.Detail)
	}
	fmt.Fprintf(&b, "  ran          %s\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	b.WriteString("  checks\n")
	for _, c := range r.Checks {
		mark := "FAIL"
		if c.Passed {
			mark = "ok  "
		}
		fmt.Fprintf(&b, "    %s %-32s %s\n", mark, c.Name, c.Detail)
	}
	return b.String()
}

// canaryRun is the state of one run.
type canaryRun struct {
	w *WORM
	// minBucketHold is CanaryOptions.MinBucketRetention: zero does not check.
	minBucketHold time.Duration
	report        *CanaryReport
	// results holds each check as it is decided; unreached checks are filled
	// in as failures at the end, so the report's shape never varies.
	results map[string]CanaryCheck
}

func (c *canaryRun) record(name string, passed bool, format string, a ...any) {
	c.results[name] = CanaryCheck{Name: name, Passed: passed, Detail: fmt.Sprintf(format, a...)}
}

// RunCanary is SEG-005.
//
// It writes a probe through the WORM writer, then requires the store to refuse
// to destroy it, and returns a report whose OK() is the gate: false means the
// deployment or the scheduled job must fail.
//
// The polarity is inverted relative to an ordinary test, and that is the whole
// difficulty. "The deletion was refused" is also true when the deletion never
// happened — when the request was malformed, the key was wrong, or the
// credentials could not delete anything at all. So this run does not conclude
// from the absence of a deletion. It:
//
//  1. deletes something it is *allowed* to delete, with the same credentials
//     against the same bucket, and fails if it cannot (CheckCredentialsCanDelete);
//  2. reads the probe back afterwards and compares its bytes (CheckProbeIntact);
//  3. asks a second time with a governance bypass, so a bucket whose retention
//     a privileged caller can lift is not certified by a refusal it earned
//     from an unprivileged request (CheckBypassDeleteRefused).
//
// An error return means the canary could not be run at all. Every other
// failure, including one reaching the store, is a failed check — so a caller
// that consults only report.OK() cannot accidentally pass.
func RunCanary(ctx context.Context, w *WORM, opts CanaryOptions) (*CanaryReport, error) {
	if w == nil {
		return &CanaryReport{}, fmt.Errorf("%w: no object store", ErrCanary)
	}
	required := opts.RequiredMode
	if required == "" {
		required = RetentionCompliance
	}
	if !required.valid() {
		return &CanaryReport{}, fmt.Errorf("%w: required mode %q is not %s or %s",
			ErrCanary, required, RetentionCompliance, RetentionGovernance)
	}
	probeRetention := opts.ProbeRetention
	if probeRetention <= 0 {
		probeRetention = w.retention
	}

	run := &canaryRun{
		w:             w,
		minBucketHold: opts.MinBucketRetention,
		report: &CanaryReport{
			Endpoint:     w.endpoint,
			Bucket:       w.bucket,
			RequiredMode: required,
			StartedAt:    time.Now().UTC(),
		},
		results: map[string]CanaryCheck{},
	}

	name, err := probeName()
	if err != nil {
		return run.finish(), fmt.Errorf("%w: %w", ErrCanary, err)
	}
	run.report.ProbeKey = name

	run.checkBucketLock(ctx)
	if run.writeProbe(ctx, probeRetention) {
		run.checkRetention(ctx, required)
		refused := run.attemptDelete(ctx, CheckVersionDeleteRefused, false)
		// The control runs before the bypass attempt, because a bypass that
		// succeeds destroys the probe and there would be no version left to
		// tell a refusal from a missing permission.
		run.checkCredentials(ctx, refused)
		run.attemptDelete(ctx, CheckBypassDeleteRefused, true)
		run.checkIntact(ctx)
	}
	return run.finish(), nil
}

// finish fills in anything unreached as a failure and orders the checks.
func (c *canaryRun) finish() *CanaryReport {
	for _, name := range canaryChecks {
		got, ok := c.results[name]
		if !ok {
			got = CanaryCheck{
				Name:   name,
				Passed: false,
				Detail: "not reached: an earlier step failed, so this property is unproven",
			}
		}
		c.report.Checks = append(c.report.Checks, got)
	}
	c.report.FinishedAt = time.Now().UTC()
	return c.report
}

// probeName is a fresh name for one run's probe, so concurrent canaries and
// successive scheduled runs never contend for the same object.
func probeName() (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate a probe name: %w", err)
	}
	return canaryProbePrefix + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(nonce[:]), nil
}

// probeBody is what the probe object contains: enough for whoever finds one in
// a bucket months later to know what it is and why it cannot be deleted.
func probeBody(name string) []byte {
	return []byte("innsegl WORM deletion canary (SEG-005, IP §6.4)\n" +
		"probe: " + name + "\n" +
		"written to prove this bucket refuses deletion; it is not a ledger segment\n")
}

func (c *canaryRun) checkBucketLock(ctx context.Context) {
	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	enabled, mode, validity, unit, err := c.w.client.GetObjectLockConfig(opCtx, c.w.bucket)
	if err != nil {
		c.report.BucketLock.Detail = err.Error()
		c.record(CheckBucketObjectLock, false,
			"the bucket's object-lock configuration could not be read: %v", err)
		return
	}
	lock := BucketLock{Enabled: strings.EqualFold(enabled, "Enabled")}
	if mode != nil {
		lock.DefaultMode = RetentionMode(*mode)
	}
	if validity != nil {
		lock.DefaultValidity = *validity
	}
	if unit != nil {
		lock.DefaultUnit = string(*unit)
	}
	c.report.BucketLock = lock

	if !lock.Enabled {
		lock.Detail = "the bucket reports object lock " + enabled
		c.report.BucketLock = lock
		c.record(CheckBucketObjectLock, false,
			"object lock is %q on bucket %s; it can only be enabled at bucket creation, "+
				"so this bucket has to be replaced, not reconfigured", enabled, c.w.bucket)
		return
	}
	if lock.DefaultMode == "" {
		if c.minBucketHold > 0 {
			c.record(CheckBucketObjectLock, false,
				"object lock is enabled but the bucket has no default retention rule, "+
					"and a minimum of %s was required; an object written by any path that "+
					"sets no retention itself would be unprotected", c.minBucketHold)
			return
		}
		c.record(CheckBucketObjectLock, true,
			"object lock is enabled with no default retention rule; "+
				"objects are protected only by the retention the writer sets")
		return
	}
	if held := lock.Duration(); c.minBucketHold > 0 && held < c.minBucketHold {
		c.record(CheckBucketObjectLock, false,
			"the bucket's default retention is %d %s (%s), short of the %s required; "+
				"a window shorter than the audit horizon is a deletion scheduled in advance",
			lock.DefaultValidity, lock.DefaultUnit, held, c.minBucketHold)
		return
	}
	c.record(CheckBucketObjectLock, true,
		"object lock is enabled, default %s for %d %s",
		lock.DefaultMode, lock.DefaultValidity, lock.DefaultUnit)
}

// writeProbe stores the probe and captures its version. It returns whether
// there is a probe to go on with, which is not the same question as whether
// the check passed.
//
// A store with no object lock refuses the retained write outright — MinIO
// answers "Bucket is missing ObjectLockConfiguration" — and stopping there
// would leave the most important sentence in a misconfiguration report
// unwritten. So the probe is written again without retention, purely so the
// run can go on to attempt the deletion and report what actually happens: that
// an object in this bucket was deleted and nothing refused it. The check still
// fails; what changes is that the report says why it matters.
func (c *canaryRun) writeProbe(ctx context.Context, retention time.Duration) bool {
	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	name := c.report.ProbeKey
	info, err := c.w.write(opCtx, c.w.key(name), probeBody(name), c.w.mode, retention)
	if err == nil {
		c.report.ProbeVersion = info.VersionID
		if info.VersionID == "" {
			// Object lock requires versioning. Without a version id the delete
			// below is an ordinary delete, which is exactly the finding.
			c.record(CheckProbeWritten, true,
				"probe written, but the store returned no version id: the bucket is not versioned, "+
					"and object lock requires versioning")
			return true
		}
		c.record(CheckProbeWritten, true, "probe written as version %s", info.VersionID)
		return true
	}

	unretained, uerr := c.w.write(opCtx, c.w.key(name), probeBody(name), "", 0)
	if uerr != nil {
		c.record(CheckProbeWritten, false,
			"the probe could not be written with %s retention (%v) and could not be written "+
				"without it either (%v)", c.w.mode, err, uerr)
		return false
	}
	c.report.ProbeVersion = unretained.VersionID
	c.record(CheckProbeWritten, false,
		"the store REFUSED to write a %s-retained object (%v). "+
			"The probe was rewritten with no retention so this run can show what that means",
		c.w.mode, err)
	return true
}

func (c *canaryRun) checkRetention(ctx context.Context, required RetentionMode) {
	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	mode, until, err := c.w.client.GetObjectRetention(
		opCtx, c.w.bucket, c.w.key(c.report.ProbeKey), c.report.ProbeVersion)
	if err != nil {
		c.record(CheckProbeRetained, false, "the probe's retention could not be read: %v", err)
		c.record(CheckRetentionMode, false, "no retention to check the mode of")
		return
	}
	if mode == nil || until == nil {
		c.record(CheckProbeRetained, false,
			"the stored probe carries no retention at all; nothing is protecting it")
		c.record(CheckRetentionMode, false, "no retention to check the mode of")
		return
	}
	c.report.Mode = RetentionMode(*mode)
	c.report.RetainUntil = *until

	if !until.After(time.Now()) {
		c.record(CheckProbeRetained, false,
			"the probe's retention expired at %s; an expired lock protects nothing",
			until.UTC().Format(time.RFC3339))
	} else {
		c.record(CheckProbeRetained, true, "retained until %s", until.UTC().Format(time.RFC3339))
	}

	if c.report.Mode != required {
		c.record(CheckRetentionMode, false,
			"the store applied %s retention, doc 05 §2 requires %s here",
			c.report.Mode, required)
		return
	}
	c.record(CheckRetentionMode, true, "%s", c.report.Mode)
}

// attemptDelete asks the store to permanently destroy the probe's version and
// requires it to refuse. It returns whether the store refused.
func (c *canaryRun) attemptDelete(ctx context.Context, check string, bypass bool) bool {
	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	how := "a permanent delete of the probe's version"
	if bypass {
		how = "the same delete asking to bypass governance retention"
	}

	err := c.w.client.RemoveObject(opCtx, c.w.bucket, c.w.key(c.report.ProbeKey),
		minio.RemoveObjectOptions{VersionID: c.report.ProbeVersion, GovernanceBypass: bypass})
	if err == nil {
		c.record(check, false,
			"%s was ACCEPTED: the object was deleted. "+
				"This storage layer does not refuse deletion (IP §6.4, I4)", how)
		return false
	}
	resp := minio.ToErrorResponse(err)
	c.record(check, true, "%s was refused: %s %s", how, resp.Code, strings.TrimSpace(resp.Message))
	return true
}

// checkIntact reads the probe back and compares the bytes. A refusal that left
// the object changed or gone is not a refusal.
func (c *canaryRun) checkIntact(ctx context.Context) {
	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	got, err := c.w.getVersion(opCtx, c.w.key(c.report.ProbeKey), c.report.ProbeVersion)
	if err != nil {
		c.record(CheckProbeIntact, false, "the probe could not be read back: %v", err)
		return
	}
	if !bytes.Equal(got, probeBody(c.report.ProbeKey)) {
		c.record(CheckProbeIntact, false,
			"the probe read back as %d bytes that are not what was written", len(got))
		return
	}
	c.record(CheckProbeIntact, true, "%d bytes, unchanged after both delete attempts", len(got))
}

// checkCredentials is the anti-vacuity control.
//
// A refusal is only evidence about object lock if the same credentials could
// have deleted something in the same bucket. So the canary deletes a version
// it is entitled to delete — a delete marker, which carries no retention — and
// requires that to succeed. If it cannot, the run is inconclusive, and an
// inconclusive canary fails.
//
// When the probe delete already succeeded the point is moot and proved: the
// canary destroyed a real object with these credentials moments ago.
func (c *canaryRun) checkCredentials(ctx context.Context, refused bool) {
	if !refused {
		c.record(CheckCredentialsCanDelete, true,
			"proved directly: the delete attempt above succeeded, so these credentials delete")
		return
	}
	if c.report.ProbeVersion == "" {
		c.record(CheckCredentialsCanDelete, false,
			"the bucket is not versioned, so there is no version this run may delete "+
				"and no way to tell a refusal from a missing permission")
		return
	}

	opCtx, cancel := c.w.op(ctx)
	defer cancel()

	key := c.w.key(c.report.ProbeKey)

	// A DELETE with no version id writes a delete marker. Object lock does not
	// prevent that — it protects versions, not keys — so this must succeed.
	if err := c.w.client.RemoveObject(opCtx, c.w.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		c.record(CheckCredentialsCanDelete, false,
			"these credentials could not even create a delete marker: %v; "+
				"the refusal above cannot be attributed to object lock", err)
		return
	}

	marker, err := c.latestDeleteMarker(opCtx, key)
	if err != nil {
		c.record(CheckCredentialsCanDelete, false,
			"the delete marker just written could not be found: %v", err)
		return
	}

	// Permanently removing that marker is the same API call, the same
	// permission and the same bucket as the delete the lock refused. It has to
	// succeed, or the refusal proves nothing.
	if err := c.w.client.RemoveObject(opCtx, c.w.bucket, key,
		minio.RemoveObjectOptions{VersionID: marker}); err != nil {
		c.record(CheckCredentialsCanDelete, false,
			"these credentials could not permanently delete version %s, which carries no retention: %v; "+
				"the refusal above may be a missing permission rather than object lock", marker, err)
		return
	}
	c.record(CheckCredentialsCanDelete, true,
		"permanently deleted version %s (an unretained delete marker) in the same bucket "+
			"with the same credentials, so the refusal above is the lock", marker)
}

// latestDeleteMarker finds the version id of the newest delete marker on a key.
func (c *canaryRun) latestDeleteMarker(ctx context.Context, key string) (string, error) {
	for object := range c.w.client.ListObjects(ctx, c.w.bucket, minio.ListObjectsOptions{
		Prefix:       key,
		WithVersions: true,
		Recursive:    true,
	}) {
		if object.Err != nil {
			return "", object.Err
		}
		if object.Key == key && object.IsDeleteMarker {
			return object.VersionID, nil
		}
	}
	return "", errors.New("no delete marker on " + key)
}
