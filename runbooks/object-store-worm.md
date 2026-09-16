# Runbook — what the WORM canary proves, and the door it cannot see

**Who this is for.** An operator choosing or configuring the object store that
holds sealed segments. ADR-0008 decides *how* refusal is established; this is
what the result means once you have it, and what it does not cover.

**The short version.** `innsegl canary` exercises the **S3 endpoint**. A pass
is evidence about that endpoint and nothing else. If the store offers a second
way to reach the same bytes, the canary never touched it, and on at least one
supported store that second way will delete what S3 refused to.

---

## 1. Run it

```sh
innsegl canary -endpoint <host:port> -bucket <name> \
  -access-key <id> -secret-key <secret>
```

Exit status is the verdict, and there is no warn mode:

| | |
|---|---|
| `0` | every check held |
| `2` | bad command line |
| `3` | a check failed — **fail the deploy** |
| `4` | the canary could not run, so nothing was proved |

Eight named checks must all report. `bucket_object_lock_enabled`,
`probe_written`, `probe_carries_retention`, `retention_mode`,
`version_delete_refused`, `privileged_bypass_delete_refused`,
`probe_bytes_intact`, `credentials_can_delete_versions`.

That last one is the anti-vacuity control and the reason a pass means anything:
before a refusal counts, the canary permanently deletes something it *is*
entitled to delete, with the same call, credential and bucket. A read-only key
produces `AccessDenied` on a delete too, and without this control the canary
would certify a bucket it never tested.

---

## 2. Measured against SeaweedFS, 2026-09-06 and again on 2026-09-16

MinIO's Community Edition was archived on 2026-04-24 (#165) and was later
delisted from the registry the reference stack pulled it from, so SeaweedFS was
measured as a replacement rather than read about. RM-143 (#227) made it the
store the reference deployment ships.

**Setup.** `chrislusf/seaweedfs:4.46`. Bucket created with
`--object-lock-enabled-for-bucket`, then `put-object-lock-configuration` with
`COMPLIANCE` for 1 day. The shipped `innsegl canary` binary, pointed at it with
`-endpoint`. Not a re-implementation.

**S3 layer: PASS, exit 0, all eight checks.** Both the ordinary delete and the
governance-bypass delete of a COMPLIANCE-locked version were refused with
`AccessDenied`, *and* — measured separately — so were shortening that object's
retention and downgrading its mode, for the store's own `Admin` identity. That
is the "not even root" semantics the threat model requires, since doc 04 AB-02
treats the deployment operator as a party the design constrains.

**The bucket default rule is inherited.** An object written with no retention of
its own comes back carrying `COMPLIANCE` until the rule's window, and its
versioned delete is refused. This is the model the reference deployment depends
on: the bucket rule is the single source of truth and the Go services set
nothing.

**Filer layer: the object is destroyed one HTTP call later.**

```
curl -X DELETE 'http://<filer>:8888/buckets/<bucket>/<key>.versions?recursive=true'
→ 204 No Content

aws s3api get-object --version-id <the version S3 had just refused to delete>
→ NoSuchKey
```

No credential. No signature. Re-measured at 4.46 and unchanged. The Filer is
unauthenticated by default and lock-unaware. It is not a misconfiguration of
object lock; it is a separate access path that object lock does not govern.

The `.versions` suffix is not incidental: a versioned object is a *directory* in
the Filer's namespace holding one entry per version, and the retention lives on
the entries. A `DELETE` of the plain key answers `204` and removes nothing,
which is an easy way to conclude the door is shut when it is not.

**The layer below has the same shape.** The master and volume servers accept
unauthenticated writes and deletes of raw needles over HTTP from anything that
can reach them — measured: `GET /dir/assign` from the master, then `PUT` and
`DELETE` of that needle on the volume server, no credential at any step.

**Therefore, if you deploy SeaweedFS: isolating everything below the S3 gateway
is a hard requirement, not a hardening suggestion.** The reference deployment
does three things, and OPS-029 measures all of them:

1. **The Filer and the S3 gateway are separate containers.** `weed server -s3`
   runs both in one process on one bind address, and there is then no
   arrangement of networks that admits the gateway and excludes the Filer.
2. **The Filer runs with `-disableHttp`.** The gateway talks to it over gRPC,
   which that flag leaves alone; the HTTP door is simply gone.
3. **The Filer and the master/volume server are on a network whose only other
   member is the gateway**, and the gateway is the only service on both that
   network and the one the sealer and the canary use.

An adopter who exposes the Filer has a WORM store that `curl` can empty, with a
green canary.

**The gateway's own extra listeners are turned off.** `weed s3` serves, by
default, an IAM API on the S3 port itself, an Iceberg REST catalog and a Lance
namespace server. None is part of storing a sealed segment and each is an
authenticated write surface on the service whose job is refusing writes:
`-iam=false -port.iceberg=0 -port.lance=0`.

**It ships no default credentials, and the failure reads like something else.**
Started without `-s3.config`, every signed request is refused with `Signed
request requires setting up SeaweedFS S3 authentication`, which arrives at the
caller as `AccessDenied` on a write. That is indistinguishable, from the
outside, from object lock working. A deployment can look like it is enforcing
SEG-005 while nothing has ever been written to it.

**The permission model is coarser than AWS IAM, and the fix is a key prefix.**
There is no separate action for `PutObjectLockConfiguration`: an identity
granted a bucket-wide `Write` may set the bucket's object-lock configuration,
and may therefore downgrade `COMPLIANCE` to `GOVERNANCE`. Measured. What does
work is a prefix-scoped grant — with `Read:<bucket>`, `List:<bucket>` and
`Write:<bucket>/<prefix>*`, one identity may write every object the sealer
writes and is refused, all with `AccessDenied`:

| attempt | result |
|---|---|
| `GetObjectLockConfiguration` | allowed — the canary reads it every run |
| `PutObject` under the prefix | allowed — the sealer's whole job |
| `PutObject` anywhere else | refused |
| `PutObjectLockConfiguration` | refused |
| `CreateBucket`, `DeleteBucket` | refused |
| `PutBucketVersioning` | refused |
| `PutBucketPolicy`, `PutBucketLifecycle` | refused |
| `PutObjectRetention` | refused |
| `DeleteObjectVersion` with bypass | refused |

and SEG-005's whole canary passes on it. That is the identity
`deploy/compose/innsegl/s3-identities.sh` writes, and
`deploy/compose/innsegl/verify-object-scope.sh` measures it against the running
server on every boot rather than trusting the file.

---

## 3. Read the canary's scope honestly

A pass says: *this endpoint, this bucket, this credential, this moment.*

It does not say anything about

- **another endpoint into the same bytes** — the finding above, and the reason
  this runbook exists
- **later reconfiguration** — which is why doc 05 §2 makes the canary a
  scheduled job in production, not a deploy-time ritual
- **a different credential**, or an object written by a path that sets no
  retention
- **durability** — object lock is an API-level control. It says nothing about
  wiping the volume, deleting the tenancy, or a provider acting on the account.

ADR-0008's "What object lock does not protect against" is the fuller list, and
it holds for every store. This runbook adds the one item that is store-specific
and was found by measurement rather than reading.

---

## 4. Corrections to this repository's own earlier record

Three earlier runs against this store reported failures that were harness
errors, not store behaviour. They are written down because each of them looks
exactly like the thing the canary exists to catch:

- **The canary defaulted to HTTPS against a plain-HTTP endpoint.** Set
  `INNSEGL_OBJECT_STORE_TLS=false` for an in-cluster gateway.
- **No S3 identity file, so every write was refused for want of auth.** See
  above: it reads as `AccessDenied`.
- **No retention on a bucket with no default rule**, so the probe was
  unretained and there was nothing to refuse. Set the bucket's default rule at
  creation; the probe inherits it.

An earlier note here said `mc retention set --default` fails against this store
with `not supported for filesystem`, and concluded that the bucket default could
not be relied on. That conclusion was wrong: the client was the one that shipped
with the store being replaced, and the call it makes is not the one the protocol
specifies. `aws s3api put-object-lock-configuration` is accepted, reads back,
and is inherited by an object written with no retention — measured at 4.46.

The rule to take from all four: **a control that is asserted rather than read
back off the server is a control nobody has checked.**
`deploy/compose/innsegl/object-init.sh` never treats a command's exit status as
evidence; it asks the server what the bucket is.
