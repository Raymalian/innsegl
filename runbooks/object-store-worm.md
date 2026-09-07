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

## 2. Measured against SeaweedFS on 2026-09-06

MinIO's Community Edition was archived on 2026-04-24 (#165), so SeaweedFS was
measured as a replacement rather than read about.

**Setup.** `chrislusf/seaweedfs:4.45`, single process (`weed server -s3`), one
IAM identity holding every action SeaweedFS has — `Admin,Read,Write,List,Tagging`.
Bucket created with `--object-lock-enabled-for-bucket`. The shipped
`innsegl canary` binary, pointed at it with `-endpoint`. Not a re-implementation.

**S3 layer: PASS, exit 0, twice.** At the most privileged identity obtainable,
both the ordinary delete and the governance-bypass delete of a COMPLIANCE-locked
version were refused with `AccessDenied` — the "not even root" semantics the
threat model requires, since doc 04 AB-02 treats the deployment operator as a
party the design constrains.

**Filer layer: the object was destroyed one HTTP call later.**

```
# the Filer's own JSON directory API gives the on-disk path
curl -X DELETE http://<filer>:8888/<path-to-the-locked-object>
→ 204 No Content

aws s3api get-object --version-id <the version S3 twice refused to delete>
→ NoSuchVersion
```

The Filer is unauthenticated by default and lock-unaware. It is not a
misconfiguration of object lock; it is a separate access path that object lock
does not govern.

**Therefore, if you deploy SeaweedFS: isolating the Filer is a hard
requirement, not a hardening suggestion.** Bind it to loopback or a private
network, put authentication on it, and never expose port 8888. An adopter who
exposes the Filer has a WORM store that `curl` can empty, with a green canary.

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

## 4. Known rough edge

`mc retention set --default` fails against SeaweedFS 4.45 with `not supported
for filesystem`. It does not matter for correctness: `segment.WORM` sets mode
and retain-until on every `PutObject` itself, and ADR-0008 step 1 deliberately
checks the bucket default without depending on it. Set retention on the object,
not on the bucket, and the canary passes.
