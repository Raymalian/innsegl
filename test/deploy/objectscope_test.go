// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"innsegl.dev/innsegl/internal/segment"
)

// ---------------------------------------------------------------------------
// OPS-025 / OPS-026 / OPS-027 / OPS-028 (PROPOSED for doc 07's TC-OPS) —
// the running stack holds no credential that may weaken the bucket.
//
// AB-17. Every network control in the reference deployment assumes an attacker
// who is not on the host. The object store has no published port and sits on a
// network declared `internal:`; that control is real, it is correctly built,
// and a process on the host with a container runtime goes around it, because
// such a process is effectively root on that host and no arrangement of
// container networks changes that.
//
// What that reaches is what the running stack HOLDS. Before this issue,
// deploy/compose/innsegl.yml gave `innsegl-sealer` and `innsegl-canary` the
// same value it gave the server as MINIO_ROOT_USER, so the sealer ran as the
// store's root account and an identity read off a container could set the
// bucket's object-lock configuration — downgrading the default rule from
// COMPLIANCE to GOVERNANCE, after which everything written is deletable by a
// holder of a bypass-capable credential.
//
// SEALED HISTORY IS NOT WHAT IS AT RISK and saying so matters, because it is
// what decides how much narrowing is worth doing. Compliance retention refuses
// deletion by anyone, the account that wrote it included — measured, and
// OPS-027 below is that measurement. The exposure is FUTURE protection, and it
// closes by the store's own authorization rather than by a better fence.
//
// THE DISCIPLINE THESE FOUR CASES INHERIT is appendonlyrole_test.go's, which
// inherits it from internal/api/readonly.go: a refusal is evidence only when
// the same identity is shown doing the thing it is supposed to do, in the same
// bucket, in the same run. "It was refused" is also true of a wrong bucket
// name, an absent object, a dead credential and an unreachable server. So
// OPS-025 is the positive case and it comes first — a scope narrow enough to
// stop the sealer is worse than the exposure it closes — and OPS-026 and
// OPS-027 each carry their own control.
// ---------------------------------------------------------------------------

// sealerCredential is what deploy/compose/innsegl.yml would actually hand the
// sealer, resolved by compose rather than restated here.
//
// Restating it would make this test agree with the compose file by
// construction, and the compose file is half of what is under test: the
// credential the stack mounts has to be one the shipped init actually
// provisioned, or the sealer does not start.
type sealerCredential struct {
	access string
	secret string
	prefix string
	bucket string
}

func composeSealerCredential(ctx context.Context, t *testing.T, bucket string) sealerCredential {
	t.Helper()
	cfg := interpolateCompose(ctx, t, bucket, "deploy/compose/innsegl.yml")

	access, ok := cfg.env("innsegl-sealer", "INNSEGL_OBJECT_STORE_ACCESS_KEY")
	if !ok {
		t.Fatalf("deploy/compose/innsegl.yml gives innsegl-sealer no object-store access key")
	}
	secret, ok := cfg.env("innsegl-sealer", "INNSEGL_OBJECT_STORE_SECRET_KEY")
	if !ok {
		t.Fatalf("deploy/compose/innsegl.yml gives innsegl-sealer no object-store secret key")
	}
	prefix, _ := cfg.env("innsegl-sealer", "INNSEGL_OBJECT_STORE_PREFIX")
	return sealerCredential{access: access, secret: secret, prefix: prefix, bucket: bucket}
}

// ---------------------------------------------------------------------------
// OPS-025 — the scoped identity does the sealer's whole job.
//
// THE POSITIVE CASE IS FIRST ON PURPOSE. A credential narrow enough to stop
// the sealer writing is not a fix, it is an outage with a security rationale;
// and every refusal the two cases below measure is worthless if this one does
// not hold, because a credential that can do nothing is refused everything.
//
// It writes through internal/segment's own WORM store rather than through a
// client this file builds, so what is measured is the code path the sealer
// actually takes — BucketExists at open, the write-once read before the put,
// the put itself — and not a second arrangement of the same calls.
//
// NOTHING SCOPED IS CONFIGURED. requireObjectStore runs object-init.sh with a
// root credential and nothing else, which is the state an existing operator's
// deployment is in. If the scoped credential had to be set before the stack
// worked, this change would not be deployable.
// ---------------------------------------------------------------------------

func TestOPS025TheScopedStoreIdentityCanSealASegment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-025: %v", err)
	}
	store := requireObjectStore(ctx, t, "OPS-025", "innsegl-segments-ops025")
	cred := composeSealerCredential(ctx, t, store.bucket)

	if cred.access == storeRootUser && cred.secret == storeRootPassword {
		t.Errorf("deploy/compose/innsegl.yml hands innsegl-sealer the store's ROOT credential "+
			"(access key %q). That is RM-144's root cause: an identity read off the running "+
			"container may then set the bucket's object-lock configuration, and everything "+
			"written after a downgrade is deletable. The sealer writes objects and does "+
			"nothing else; bucket creation is a one-time setup step.", cred.access)
	}

	// ---- the sealer's own store, under the credential the stack mounts -----
	worm, err := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  store.endpoint,
		AccessKey: cred.access,
		SecretKey: cred.secret,
		UseTLS:    false,
		Bucket:    store.bucket,
		Prefix:    cred.prefix,
		Mode:      segment.RetentionCompliance,
		OpTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("the scoped credential could not open the segment bucket at all: %v\n\n"+
			"A scope this narrow is worse than the problem it closes: the sealer cannot "+
			"start, so nothing is sealed and nothing is anchored.", err)
	}

	const name = "sha256:0000000000000000000000000000000000000000000000000000000000000025"
	body := []byte(`{"ops":"025","segment":"a sealed segment, written by the scoped identity"}`)

	if putErr := worm.Put(name, body); putErr != nil {
		t.Fatalf("the scoped credential could not WRITE a segment: %v\n\n"+
			"doc 05 §1 runs the sealer on this credential. Withholding "+
			"s3:PutObject makes the deployment stop sealing.", putErr)
	}
	got, getErr := worm.Get(name)
	if getErr != nil {
		t.Fatalf("the scoped credential wrote a segment it cannot READ BACK: %v\n\n"+
			"seal.go reads before it writes (write-once under a content address), so a "+
			"credential without s3:GetObject re-uploads every segment on every pass.", getErr)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("the segment read back as %d bytes that are not what was written", len(got))
	}
	t.Logf("OPS-025 wrote and read back %d bytes as %q", len(got), cred.access)

	// ---- the version surface the canary needs -----------------------------
	cl, clErr := store.clientAs(cred.access, cred.secret)
	if clErr != nil {
		t.Fatalf("building a client for the scoped credential: %v", clErr)
	}
	key := cred.prefix + name

	versions := 0
	for object := range cl.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{
		Prefix: key, WithVersions: true, Recursive: true,
	}) {
		if object.Err != nil {
			t.Fatalf("the scoped credential could not LIST VERSIONS: %v\n\n"+
				"SEG-005's canary finds the delete marker it just wrote by listing "+
				"versions; without s3:ListBucketVersions the canary is inconclusive, "+
				"and an inconclusive canary fails.", object.Err)
		}
		versions++
	}
	if versions == 0 {
		t.Errorf("the scoped credential listed no versions of a key it had just written")
	}

	// A delete marker carries no retention, so deleting one is the one
	// destructive thing this credential is SUPPOSED to be able to do — and it
	// is the whole basis of the canary's anti-vacuity control.
	if rmErr := cl.RemoveObject(ctx, store.bucket, key, minio.RemoveObjectOptions{}); rmErr != nil {
		t.Fatalf("the scoped credential could not write a delete marker: %v", rmErr)
	}
	marker := ""
	for object := range cl.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{
		Prefix: key, WithVersions: true, Recursive: true,
	}) {
		if object.Err == nil && object.Key == key && object.IsDeleteMarker {
			marker = object.VersionID
			break
		}
	}
	if marker == "" {
		t.Fatalf("no delete marker was found on %s after one was written", key)
	}
	if rmErr := cl.RemoveObject(ctx, store.bucket, key,
		minio.RemoveObjectOptions{VersionID: marker}); rmErr != nil {
		t.Fatalf("the scoped credential could not permanently delete an UNRETAINED version "+
			"(%s): %v\n\nThis is the canary's anti-vacuity control. Without it, every "+
			"refusal OPS-027 measures could be a missing permission rather than object "+
			"lock, and SEG-005 would prove nothing.", marker, rmErr)
	}
	t.Logf("OPS-025 permanently deleted unretained version %s as %q", marker, cred.access)
}

// ---------------------------------------------------------------------------
// OPS-026 — the scoped identity cannot set the bucket's object-lock
// configuration, and the root identity can.
//
// THIS IS THE CASE THAT FAILS TODAY, and the second half is what makes the
// first half mean anything. A refusal to set a bucket configuration is also
// what an unreachable server, a misspelled bucket and a dead credential
// produce. So the same call is made twice against the same bucket on the same
// server, and the root identity — the one object-init.sh runs as, which has to
// keep the permission or no bucket could ever be created — must succeed.
//
// The value written is the configuration the bucket ALREADY HAS. A test that
// proved the permission by downgrading a real bucket to GOVERNANCE would be
// performing the attack in order to detect it; writing the same rule back
// leaves the bucket exactly as it was whether the call is permitted or not.
// ---------------------------------------------------------------------------

func TestOPS026TheScopedStoreIdentityCannotWeakenTheBucket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-026: %v", err)
	}
	store := requireObjectStore(ctx, t, "OPS-026", "innsegl-segments-ops026")
	cred := composeSealerCredential(ctx, t, store.bucket)

	scoped, err := store.clientAs(cred.access, cred.secret)
	if err != nil {
		t.Fatalf("building a client for the scoped credential: %v", err)
	}
	root, err := store.clientAs(storeRootUser, storeRootPassword)
	if err != nil {
		t.Fatalf("building a client for the root credential: %v", err)
	}

	// ---- control: the scoped identity reaches this bucket at all ----------
	enabled, mode, validity, unit, err := scoped.GetObjectLockConfig(ctx, store.bucket)
	if err != nil {
		t.Fatalf("the scoped credential could not even READ the bucket's object-lock "+
			"configuration: %v\n\nWithout this the refusal below would be indistinguishable "+
			"from an unreachable bucket, and SEG-005's canary — which reads exactly this — "+
			"could not run under the credential the stack mounts.", err)
	}
	t.Logf("OPS-026 the bucket reports object lock %q, default %v for %v %v",
		enabled, deref(mode), deref(validity), deref(unit))
	if mode == nil || validity == nil || unit == nil {
		t.Fatalf("the bucket object-init.sh created carries no default retention rule; " +
			"there is nothing for this case to attempt to weaken")
	}

	// ---- the measurement: writing the SAME rule back ----------------------
	same := *mode
	days := *validity
	sameUnit := *unit

	scopedErr := scoped.SetBucketObjectLockConfig(ctx, store.bucket, &same, &days, &sameUnit)
	if scopedErr == nil {
		t.Errorf("the scoped credential SET the bucket's object-lock configuration.\n\n"+
			"AB-17: an identity that may do this can downgrade the default rule from "+
			"COMPLIANCE to GOVERNANCE, after which every segment written is deletable by a "+
			"holder of a bypass-capable credential. Sealed history survives; future "+
			"protection does not. The running stack must hold no credential that may set "+
			"this — bucket creation is a one-time setup step (doc 05 §2).\n"+
			"  access key: %s", cred.access)
	} else {
		t.Logf("OPS-026 %-14s SetBucketObjectLockConfig refused: %s %s", cred.access,
			minio.ToErrorResponse(scopedErr).Code,
			firstLine(minio.ToErrorResponse(scopedErr).Message))
	}

	// ---- and the refusal is the scope, not the bucket ---------------------
	if rootErr := root.SetBucketObjectLockConfig(ctx, store.bucket, &same, &days, &sameUnit); rootErr != nil {
		t.Errorf("the ROOT credential could not set the bucket's object-lock configuration "+
			"either: %v\n\nThen the refusal above says nothing about the scope — it says "+
			"the bucket, the server or the request is wrong — and object-init.sh could "+
			"never have created this bucket in the first place.", rootErr)
	} else {
		t.Logf("OPS-026 %-14s SetBucketObjectLockConfig accepted, so the refusal above is the scope",
			storeRootUser)
	}
}

// ---------------------------------------------------------------------------
// OPS-027 — the scoped identity cannot destroy a retained version, with or
// without a governance bypass.
//
// Run as SEG-005's own canary under the credential the stack mounts, rather
// than as a second set of delete calls written here. Two reasons, and the
// second is the one that matters:
//
//  1. RunCanary already makes every distinction this case needs — the delete,
//     the same delete asking to bypass governance retention, the byte-for-byte
//     read-back afterwards, and the anti-vacuity control that permanently
//     deletes an unretained version with the same credential in the same
//     bucket.
//
//  2. doc 05 §2 requires the canary to run as a scheduled job in production.
//     It runs on the deployment's credential. If the scope stopped the canary,
//     the narrowing would have disabled the control that detects the very
//     weakening it exists to prevent — so "the canary passes under the scoped
//     identity" is not a convenience, it is a requirement of the change.
//
// SAID PLAINLY, BECAUSE THE TDD RECORD SHOULD NOT BE READ AS MORE THAN IT IS:
// this case PASSED before the scoped identity existed, and that is the measured
// finding rather than a gap in the discipline. Compliance retention refuses
// deletion by the root account too, so running as root never made a sealed
// segment destroyable. OPS-025, OPS-026 and OPS-028 are the three that were
// observed failing. What this case adds is the guarantee in the other
// direction: the narrowing must not have bought the refusal by taking away the
// permissions the canary needs to prove the refusal means anything.
// ---------------------------------------------------------------------------

func TestOPS027TheScopedStoreIdentityCannotDestroyARetainedSegment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-027: %v", err)
	}
	store := requireObjectStore(ctx, t, "OPS-027", "innsegl-segments-ops027")
	cred := composeSealerCredential(ctx, t, store.bucket)

	worm, err := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  store.endpoint,
		AccessKey: cred.access,
		SecretKey: cred.secret,
		UseTLS:    false,
		Bucket:    store.bucket,
		Mode:      segment.RetentionCompliance,
		OpTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("the scoped credential could not open the bucket: %v", err)
	}

	report, err := segment.RunCanary(ctx, worm, segment.CanaryOptions{
		RequiredMode: segment.RetentionCompliance,
	})
	if err != nil {
		t.Fatalf("SEG-005's canary could not run under the scoped credential: %v\n\n"+
			"doc 05 §2 runs it as a scheduled job on the deployment's own credential. A "+
			"scope that stops it disables the control that detects a downgraded bucket "+
			"rule, which is the thing this narrowing exists to keep detectable.", err)
	}
	t.Logf("--- innsegl canary, as %s ---\n%s", cred.access, report.String())

	for _, name := range segment.CanaryCheckNames() {
		check, ok := report.Check(name)
		switch {
		case !ok:
			t.Errorf("the canary reported no result for %q", name)
		case !check.Passed:
			t.Errorf("OPS-027 %s FAILED under the scoped credential: %s", name, check.Detail)
		default:
			t.Logf("OPS-027 %-32s %s", name, check.Detail)
		}
	}

	// The two refusals this case is named for, said plainly rather than left
	// inside a report a reader has to decode.
	for _, want := range []struct{ check, why string }{
		{segment.CheckVersionDeleteRefused,
			"I4: a sealed segment's bytes are never destroyed, by anyone"},
		{segment.CheckBypassDeleteRefused,
			"the same delete with a governance bypass; the scoped identity holds no " +
				"s3:BypassGovernanceRetention, so a rule that had been downgraded to " +
				"GOVERNANCE would still not let this credential delete"},
		{segment.CheckCredentialsCanDelete,
			"the control: the same credential permanently deleted an unretained version " +
				"in the same bucket, so the two refusals above are the lock and not a " +
				"missing permission"},
	} {
		if check, ok := report.Check(want.check); ok && !check.Passed {
			t.Errorf("OPS-027 %s: %s\n  %s", want.check, want.why, check.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// OPS-028 — nothing that stays up holds the store's root credential.
//
// The two cases above measure what one credential may do. This one measures
// which credential the deployment actually mounts, on every service and in
// every shipped arrangement of them — including the folded one, where the
// sealer is not a container at all and a change made only to `innsegl-sealer`
// would miss it entirely.
//
// It reads the compose files through `docker compose config` rather than as
// text. RM-144's defect was not a misspelling: `x-object-store-user` was an
// ANCHOR whose value was the same string the server got as MINIO_ROOT_USER, and
// a text match would have read the anchor's name and been satisfied.
// ---------------------------------------------------------------------------

// storeCredentialHolders is every shipped arrangement of the stack, by the
// services in it that talk to the object store.
var storeCredentialHolders = []struct {
	files    []string
	services []string
	why      string
}{
	{
		files:    []string{"deploy/compose/innsegl.yml"},
		services: []string{"innsegl-sealer", "innsegl-canary"},
		why:      "the reference stack: the sealer stays up, and the canary is doc 05 §2's scheduled job",
	},
	{
		files: []string{
			"deploy/compose/innsegl.yml",
			"deploy/compose/innsegl.oneprocess.yml",
		},
		services: []string{"innsegl-mcp"},
		why: "ONEPROCESS=1 folds the sealer into the MCP process, so the MCP is the " +
			"service holding the store credential there. A narrowing applied only to " +
			"innsegl-sealer would leave this arrangement running as root",
	},
}

func TestOPS028NothingLongRunningHoldsTheStoreRootCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-028: %v", err)
	}

	for _, arrangement := range storeCredentialHolders {
		cfg := interpolateCompose(ctx, t, "innsegl-segments", arrangement.files...)

		for _, service := range arrangement.services {
			access, ok := cfg.env(service, "INNSEGL_OBJECT_STORE_ACCESS_KEY")
			if !ok {
				t.Errorf("%v declares %s without an object-store access key; %s",
					arrangement.files, service, arrangement.why)
				continue
			}
			secret, _ := cfg.env(service, "INNSEGL_OBJECT_STORE_SECRET_KEY")

			switch {
			case access == storeRootUser && secret == storeRootPassword:
				t.Errorf("%v runs %s on the store's ROOT credential.\n\n"+
					"%s.\n\nAB-17: an agent on the host reads this off the running "+
					"container and may then set the bucket's object-lock configuration. "+
					"Bucket creation is a one-time setup step; this service writes "+
					"objects and does nothing else.", arrangement.files, service, arrangement.why)
			case secret == "":
				t.Errorf("%v gives %s an access key and no secret key", arrangement.files, service)
			default:
				t.Logf("OPS-028 %-16s %-14s not the root credential", service, access)
			}
		}

		// And the root credential still reaches the two that need it: the
		// server itself, and the one-time init that creates the locked bucket.
		// A stack where nothing holds it is a stack with no bucket.
		for _, service := range []string{"minio", "innsegl-object-init"} {
			if _, ok := cfg.env(service, "MINIO_ROOT_PASSWORD"); !ok {
				t.Errorf("%v gives %s no root credential. The bucket can only be created "+
					"with object lock at creation, and only the root account may set the "+
					"default rule — so this is not a tighter deployment, it is one with no "+
					"locked bucket.", arrangement.files, service)
			}
		}

		// Nothing else may carry it. This is the check that catches a third
		// service quietly acquiring MINIO_ROOT_* later.
		for name, service := range cfg.Services {
			if name == "minio" || name == "innsegl-object-init" {
				continue
			}
			if _, ok := service.Environment["MINIO_ROOT_PASSWORD"]; ok {
				t.Errorf("%v gives %s the store's root password. Only the server and the "+
					"one-time init may hold it.", arrangement.files, name)
			}
		}
	}
}

// deref renders a pointer field of an object-lock configuration for a log
// line. errcheck's check-blank makes a named helper the idiom here rather than
// an inline nil test repeated four times.
func deref[T any](p *T) any {
	if p == nil {
		return "<none>"
	}
	return *p
}
