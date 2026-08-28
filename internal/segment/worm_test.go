// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// probeRetention is the lock the canary puts on its own probe object in these
// tests. It only has to outlast the test: compliance mode refuses a deletion
// the same way for a minute as for a decade, and the length of the *bucket's*
// retention is a separate check on the bucket configuration.
const probeRetention = 2 * time.Minute

func newTestWORM(t *testing.T, c *minioContainer, bucket string, mode RetentionMode, retention time.Duration) *WORM {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	w, err := NewWORM(ctx, WORMConfig{
		Endpoint:  c.endpoint,
		AccessKey: minioRootUser,
		SecretKey: minioRootPassword,
		Bucket:    bucket,
		Mode:      mode,
		Retention: retention,
	})
	if err != nil {
		t.Fatalf("NewWORM against %s/%s: %v", c.endpoint, bucket, err)
	}
	return w
}

// checkResult returns one named check from a report, failing the test if the
// canary never ran it. A check that is silently absent is the vacuous pass this
// whole test exists to avoid: "no check failed" must not be reachable by not
// checking.
func checkResult(t *testing.T, r *CanaryReport, name string) CanaryCheck {
	t.Helper()
	got, ok := r.Check(name)
	if !ok {
		t.Fatalf("the canary report has no %q check; it ran %v", name, r.CheckNames())
	}
	return got
}

func mustPass(t *testing.T, r *CanaryReport, name string) {
	t.Helper()
	if c := checkResult(t, r, name); !c.Passed {
		t.Errorf("check %q failed: %s", name, c.Detail)
	}
}

func mustFail(t *testing.T, r *CanaryReport, name string) {
	t.Helper()
	if c := checkResult(t, r, name); c.Passed {
		t.Errorf("check %q passed, want it to fail: %s", name, c.Detail)
	}
}

// SEG-005 — the WORM deletion canary (IP §6.4, doc 07).
//
//	"WORM canary: attempt object deletion in deploy check.
//	 Storage refuses; deploy gate fails if deletion succeeds."
//
// The polarity is the opposite of most tests, and that inverts the usual
// failure mode: a check that asserts "deletion was refused" passes whenever the
// deletion did not happen, *including* when it did not happen for a reason that
// has nothing to do with WORM — a typo in the key, a client that never sent the
// request, credentials with no delete permission at all. Three things guard
// against that here, and all three are assertions rather than commentary:
//
//  1. The same canary is pointed at a bucket with object lock *off*. There it
//     must report failure. A canary that cannot fail is not a gate.
//  2. Inside the locked bucket the canary must have proved its own credentials
//     can permanently delete a version in that bucket — it deletes one — before
//     it is allowed to attribute a refusal to the lock.
//  3. The probe's bytes are read back and compared after the refusal. "Refused"
//     is only true if the object is still there and unchanged.
func TestSEG005DeletionCanaryRequiresTheStoreToRefuseDeletion(t *testing.T) {
	c := requireMinIO(t)
	ctx := context.Background()

	t.Run("object lock on: the store refuses and the canary passes", func(t *testing.T) {
		bucket := freshBucket(t, c, true)
		w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		t.Logf("canary report:\n%s", report)

		if !report.OK() {
			t.Fatalf("the canary failed against a bucket with object lock in compliance mode:\n%s", report)
		}

		// The refusal is only attributable to the lock if the credentials
		// could have deleted something. This check is the anti-vacuity guard:
		// the canary permanently deletes a version in the same bucket with the
		// same credentials, and only then calls a refusal a refusal.
		mustPass(t, report, CheckCredentialsCanDelete)
		mustPass(t, report, CheckBucketObjectLock)
		mustPass(t, report, CheckProbeRetained)
		mustPass(t, report, CheckRetentionMode)
		mustPass(t, report, CheckVersionDeleteRefused)
		mustPass(t, report, CheckBypassDeleteRefused)
		mustPass(t, report, CheckProbeIntact)

		if report.RetainUntil.Before(time.Now()) {
			t.Errorf("probe retain-until is %s, already in the past", report.RetainUntil)
		}
		if report.Mode != RetentionCompliance {
			t.Errorf("probe retention mode = %q, want %q", report.Mode, RetentionCompliance)
		}
	})

	// Prove the gate bites. Same canary, same credentials, same code path —
	// only the bucket's object-lock configuration differs.
	t.Run("object lock off: the store permits deletion and the canary fails", func(t *testing.T) {
		bucket := freshBucket(t, c, false)
		w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		t.Logf("canary report:\n%s", report)

		if report.OK() {
			t.Fatalf("the canary PASSED against a bucket with no object lock. "+
				"It is not a gate; deletion is permitted there:\n%s", report)
		}
		mustFail(t, report, CheckBucketObjectLock)
		mustFail(t, report, CheckVersionDeleteRefused)
		mustFail(t, report, CheckProbeIntact)

		// The delete has to have actually happened, not merely "not been
		// refused". If the probe is still readable the canary is describing
		// something other than a deletion.
		deleted := checkResult(t, report, CheckVersionDeleteRefused)
		if !strings.Contains(deleted.Detail, "deleted") {
			t.Errorf("the failing detail is %q; want it to say the object was deleted", deleted.Detail)
		}
		if _, err := w.Get(report.ProbeKey); err == nil {
			t.Errorf("the probe is still readable after the canary reported it deleted")
		}
	})

	// Governance mode is the honest limit made testable: it refuses an ordinary
	// deletion exactly like compliance mode, and yields to a caller holding
	// s3:BypassGovernanceRetention. Doc 05 §2 requires compliance mode in
	// production, so the canary must be able to tell the two apart even when
	// the ordinary delete is refused in both.
	t.Run("governance mode: an ordinary delete is refused but a privileged one is not", func(t *testing.T) {
		bucket := freshBucket(t, c, true)
		w := newTestWORM(t, c, bucket, RetentionGovernance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{RequiredMode: RetentionGovernance})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		t.Logf("canary report:\n%s", report)

		// The mode check is satisfied — the canary was asked for governance —
		// so the only thing that can fail here is the bypass, which isolates it.
		mustPass(t, report, CheckRetentionMode)
		mustPass(t, report, CheckVersionDeleteRefused)
		mustFail(t, report, CheckBypassDeleteRefused)
		if report.OK() {
			t.Fatalf("the canary passed a bucket whose retention a privileged caller can bypass:\n%s", report)
		}
	})
}

// The canary must refuse to certify a store it could not exercise. An error
// reaching the object store is not a refusal to delete.
func TestSEG005CanaryFailsWhenItCannotReachTheStore(t *testing.T) {
	c := requireMinIO(t)
	bucket := freshBucket(t, c, true)
	w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

	// Point the store at a bucket that does not exist, after construction, so
	// every request fails at the server rather than in the client.
	w.bucket = bucket + "-absent"

	report, err := RunCanary(context.Background(), w, CanaryOptions{})
	if err == nil && report.OK() {
		t.Fatalf("the canary passed against an unreachable bucket:\n%s", report)
	}
}

// The WORM writer is the Store the sealer writes through, and the two
// properties seal.go depends on are asserted here against the real server:
// a second write of identical bytes is a no-op, and a second write of
// different bytes under the same name is refused.
func TestWORMStoreIsWriteOnceAndRoundTrips(t *testing.T) {
	c := requireMinIO(t)
	bucket := freshBucket(t, c, true)
	w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

	records := seededRecords(1, 5)
	sealer := &Sealer{Store: w}

	sealed, err := sealer.Seal(Request{Records: records})
	if err != nil {
		t.Fatalf("Seal into a WORM bucket: %v", err)
	}

	got, err := w.Get(sealed.SegmentID)
	if err != nil {
		t.Fatalf("Get(%s): %v", sealed.SegmentID, err)
	}
	if !bytes.Equal(got, sealed.Object) {
		t.Fatalf("the stored bytes are not the sealed object")
	}

	// Re-sealing is how a crashed sealer resumes (SEG-002): identical bytes,
	// identical address, adopted rather than rewritten.
	again, err := sealer.Seal(Request{Records: records})
	if err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if !again.Resumed {
		t.Errorf("re-seal did not resume onto the stored object")
	}
	if again.SegmentID != sealed.SegmentID {
		t.Errorf("re-seal produced %s, want %s", again.SegmentID, sealed.SegmentID)
	}

	// A different object under an existing name is a lie about a content
	// address, and the writer refuses it without asking the server to.
	if err := w.Put(sealed.SegmentID, []byte(`{"not":"the object"}`)); err == nil {
		t.Errorf("Put overwrote an existing name with different bytes")
	}

	if _, err := w.Get(digestOf([]byte("nothing is stored under this"))); err == nil {
		t.Errorf("Get of an absent name returned no error")
	} else if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("Get of an absent name = %v, want ErrObjectNotFound", err)
	}
}

// Doc 05 §2 requires "a retention window >= the organization's audit horizon".
// The horizon is a number this project does not get to invent, so the check is
// opt-in — and an opt-in check that never fires is decoration, so this asserts
// it fires.
func TestCanaryChecksTheBucketRetentionWindowWhenAskedTo(t *testing.T) {
	c := requireMinIO(t)
	ctx := context.Background()

	t.Run("a default rule shorter than required fails", func(t *testing.T) {
		bucket := freshBucket(t, c, true)
		setBucketRetention(t, c, bucket, RetentionCompliance, 7)
		w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{MinBucketRetention: 365 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		t.Logf("canary report:\n%s", report)

		mustFail(t, report, CheckBucketObjectLock)
		// Everything the lock itself does still holds; only the window is short.
		mustPass(t, report, CheckVersionDeleteRefused)
		if report.OK() {
			t.Errorf("the canary passed a bucket whose retention expires long before the audit horizon")
		}
		if got := report.BucketLock.Duration(); got != 7*24*time.Hour {
			t.Errorf("bucket retention read back as %s, want %s", got, 7*24*time.Hour)
		}
	})

	t.Run("a default rule at least as long as required passes", func(t *testing.T) {
		bucket := freshBucket(t, c, true)
		setBucketRetention(t, c, bucket, RetentionCompliance, 400)
		w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{MinBucketRetention: 365 * 24 * time.Hour})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		t.Logf("canary report:\n%s", report)

		if !report.OK() {
			t.Fatalf("the canary failed a correctly configured bucket:\n%s", report)
		}
	})

	// A bucket with object lock on but no default rule is the case an operator
	// is most likely to mistake for protection: it protects only what the
	// writer itself retains, and says nothing about anything written by any
	// other path.
	t.Run("object lock with no default rule fails when a window is required", func(t *testing.T) {
		bucket := freshBucket(t, c, true)
		w := newTestWORM(t, c, bucket, RetentionCompliance, probeRetention)

		report, err := RunCanary(ctx, w, CanaryOptions{MinBucketRetention: 24 * time.Hour})
		if err != nil {
			t.Fatalf("RunCanary: %v", err)
		}
		mustFail(t, report, CheckBucketObjectLock)
		if !strings.Contains(strings.ToLower(checkResult(t, report, CheckBucketObjectLock).Detail), "no default retention rule") {
			t.Errorf("the failure does not say the bucket has no default rule: %s",
				checkResult(t, report, CheckBucketObjectLock).Detail)
		}
	})
}

// The fail-closed paths: everything that must refuse before a single request
// reaches an object store. None of these needs a container, and all of them are
// ways a misconfigured deployment could otherwise get a silent pass.
func TestWORMRefusesAnImpossibleConfiguration(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		cfg  WORMConfig
		want string
	}{
		{"no endpoint", WORMConfig{Bucket: "b"}, "no endpoint"},
		{"no bucket", WORMConfig{Endpoint: "127.0.0.1:9000"}, "no bucket"},
		{
			"negative retention",
			WORMConfig{Endpoint: "127.0.0.1:9000", Bucket: "b", Retention: -time.Hour},
			"negative",
		},
		{
			"a retention mode that is neither",
			WORMConfig{Endpoint: "127.0.0.1:9000", Bucket: "b", Mode: "WORM_ISH"},
			"is not COMPLIANCE or GOVERNANCE",
		},
		{
			"an endpoint the client itself rejects",
			WORMConfig{Endpoint: "https://example.invalid/path", Bucket: "b"},
			"misconfigured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := NewWORM(ctx, tc.cfg)
			if err == nil {
				t.Fatalf("NewWORM accepted %#v and returned %v", tc.cfg, w)
			}
			if !errors.Is(err, ErrWORMConfig) {
				t.Errorf("NewWORM error = %v, want it to wrap ErrWORMConfig", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewWORM error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestRunCanaryRefusesToPretendItRan(t *testing.T) {
	ctx := context.Background()

	t.Run("no store", func(t *testing.T) {
		report, err := RunCanary(ctx, nil, CanaryOptions{})
		if err == nil {
			t.Fatalf("RunCanary with no store returned no error")
		}
		if !errors.Is(err, ErrCanary) {
			t.Errorf("error = %v, want it to wrap ErrCanary", err)
		}
		if report == nil || report.OK() {
			t.Errorf("a canary that never ran reported OK")
		}
	})

	t.Run("a required mode that is neither", func(t *testing.T) {
		report, err := RunCanary(ctx, &WORM{}, CanaryOptions{RequiredMode: "WORM_ISH"})
		if err == nil {
			t.Fatalf("RunCanary accepted a required mode that is neither")
		}
		if report == nil || report.OK() {
			t.Errorf("a canary that never ran reported OK")
		}
	})
}

// OK() is the whole gate, so the ways it can be wrong are worth pinning: a
// report missing a check is not a pass, and a report is not a pass because
// every check it happens to carry held.
func TestCanaryReportOKRequiresEveryCheck(t *testing.T) {
	full := &CanaryReport{}
	for _, name := range CanaryCheckNames() {
		full.Checks = append(full.Checks, CanaryCheck{Name: name, Passed: true, Detail: "held"})
	}
	if !full.OK() {
		t.Fatalf("a report with every check passing is not OK:\n%s", full)
	}

	short := &CanaryReport{Checks: full.Checks[:len(full.Checks)-1]}
	if short.OK() {
		t.Errorf("a report missing %q reported OK", CanaryCheckNames()[len(CanaryCheckNames())-1])
	}

	oneBad := &CanaryReport{Checks: append([]CanaryCheck(nil), full.Checks...)}
	oneBad.Checks[0].Passed = false
	if oneBad.OK() {
		t.Errorf("a report with a failed check reported OK")
	}
	if _, found := oneBad.Check("no_such_check"); found {
		t.Errorf("Check found a check that was never run")
	}
}
