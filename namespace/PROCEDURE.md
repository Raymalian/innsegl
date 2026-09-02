# Namespace procedure — the human steps

Everything in this file needs an account, and no agent, script or CI job in this
repository can do any of it. That is the point: the parts of asset A6 that are
defensible in code are already gated by `verify-namespace.sh`, and what remains
is exactly the part a person has to do.

Work top to bottom. Sections 1 and 2 take about ten minutes and are the ones
that matter most; section 3 is optional and can wait.

> **Nothing in this repository has published anything.** The 0.0.2 artifacts are
> built locally and sit in `namespace/dist/`. They reach a registry only when a
> human runs the command in §3.

---

## 1. The domain — `innsegl.dev`

### Why this is a security control and not administration

`spiffe://innsegl.dev` is the trust domain. Every SPIFFE ID Innsegl issues
carries it, every Sigstore signature made under one of those identities carries
it, and every Rekor entry anchoring a ledger segment is **public and permanent**
— Rekor is an append-only transparency log, so those entries outlive the
project, the repository, and the registration.

That is the whole argument. A lapsed domain is normally an outage: the site goes
dark, somebody notices, it comes back. Here, whoever registers `innsegl.dev`
next inherits the ability to speak for a trust domain that is already named in
permanent public records — to stand up a verification page, serve `go-import`
metadata for the module path `innsegl.dev/innsegl`, publish a "trust bundle",
and be, to anyone reading those Rekor entries, the successor of the identity
that signed them. The old entries do not become invalid; they become
*ambiguous*, and ambiguity is precisely what a non-repudiation system exists to
remove. There is no revocation for this and no cleanup afterwards.

A renewal notice in a spam folder is therefore an incident with a one-year fuse.
Doc 08 §4 calls auto-renew a control for this reason.

### What the registration looks like today

Checked 2026-09-02 with `curl -sS https://rdap.org/domain/innsegl.dev`:

| Field | Value |
|---|---|
| Registrar | Cloudflare, Inc. |
| Registered | 2026-08-28 |
| **Expires** | **2027-08-28** |
| Status | `clientTransferProhibited` — transfer lock already on |
| DNSSEC | `delegationSigned: false` — **no DS record at the registry** |
| Apex A record | none yet |

### Steps

- [ ] **1.1 Two-factor authentication on the Cloudflare account.** Cloudflare is
      both the registrar and the DNS host, so this one login controls renewal
      *and* where `innsegl.dev` points. Someone into that account does not have
      to wait for expiry — they repoint the domain this afternoon. My Profile →
      Authentication → Two-Factor Authentication. Prefer a hardware key or a TOTP
      app over SMS.
      **Check:** the section reads *enabled*, and the recovery codes are saved
      somewhere that is not the same laptop.
- [ ] **1.2 Auto-renew on.** Domain Registration → Manage Domains → `innsegl.dev`
      → Configuration.
      **Check:** auto-renew reads *on*, and the payment card on file does not
      expire before **2027-08-28**. An expired card with auto-renew on fails the
      same way auto-renew off does, one year from now, quietly.
- [ ] **1.3 Confirm the transfer lock.** RDAP already shows
      `clientTransferProhibited`, so this is a confirmation, not a change.
      **Check:** re-run the RDAP command above after any registrar change and
      confirm the status is still there.
- [ ] **1.4 Enable DNSSEC.** The delegation is currently unsigned, which leaves
      resolution of the trust-domain name spoofable by an on-path or
      cache-poisoning attacker — including resolution of the `go-import` metadata
      that the module path `innsegl.dev/innsegl` will depend on. Cloudflare hosts
      the zone, so this is DNS → Settings → DNSSEC → Enable, and Cloudflare
      publishes the DS record to the `.dev` registry itself.
      **Check:** `curl -sS https://rdap.org/domain/innsegl.dev` reports
      `"delegationSigned": true`. Allow up to an hour for the registry to reflect
      it.
- [ ] **1.5 Calendar the expiry.** A reminder for **2027-07-28**, one month
      ahead, that says *check auto-renew and the card on file*, owned by a person
      and not only by an inbox.

---

## 2. The registry accounts

An attacker who can publish under the project's existing names does not need to
squat anything — they inherit the trust the names already carry. `npx innsegl`
executes code on a developer's machine, which makes npm the sharper of the two.

- [ ] **2.1 npm two-factor, set to *auth and writes*.** npmjs.com → Account →
      Two-Factor Authentication. The weaker *auth-only* setting leaves `npm
      publish` unprotected by a second factor, which is the setting that matters.
      **Check:** the account page reads *Two-factor authentication is enabled for
      authorization and writes*, and §3 below prompts for an OTP.
- [ ] **2.2 PyPI two-factor, with recovery codes stored.** pypi.org → Account
      settings → Two factor authentication. PyPI requires 2FA for maintainers of
      any project, so this is likely already on; confirm the recovery codes exist
      and are stored off the publishing machine.
- [ ] **2.3 Audit standing tokens on both.** Delete any classic/legacy npm token
      and any PyPI API token that is not needed. A long-lived publish token is a
      standing credential for the project's own name — the exact thing Innsegl's
      short-TTL SVIDs exist to avoid. §4 is the replacement.
- [ ] **2.4 Confirm the `@innsegl` org, and record what it means.** This is the
      one claim in `namespace/README.md` that could not be verified from outside:
      npm org membership is not publicly readable.
      **Check:** `npm org ls innsegl` lists the account as an owner. Owning the
      org means nobody outside it can publish `@innsegl/*` at all, so
      `@innsegl/mcp` and `@innsegl/cli` need no defensive placeholder packages
      and stay free for real releases. If this command fails, the scope is *not*
      held and creating the org is the most urgent item in this file.
- [ ] **2.5 Move the unscoped `innsegl` package under the org.** It currently
      lists `maintainers: kodymike` — a single personal account. `npm owner add`
      takes users only, so this is the package's Settings page on npmjs.com, or a
      support request. Cosmetic for squatting (the name cannot be taken now) and
      real for bus factor.

---

## 3. Publishing the 0.0.2 stubs

Optional and not urgent. The names are already held by 0.0.1 and 0.0.1 is
honest; 0.0.2 replaces it with a version whose source is in this repository,
which names the Go module path, and which ships the licence text.

**A publish is irreversible.** Neither registry allows a real unpublish, so the
tarball uploaded here is a permanent artifact bearing the project's name.
Everything below is designed so that the bytes are inspected before they leave
the machine.

### 3.1 Build and inspect

```
namespace/build.sh
```

It runs `verify-namespace.sh` first and refuses to build if the metadata and the
repository disagree. Expected digests, from npm 11.19.0 / node 26.8.1 / uv 0.11.26
on macOS 26.6.2, 2026-09-02 — both packages built reproducibly across consecutive
runs:

| Artifact | Digest |
|---|---|
| `innsegl-0.0.2.tgz` | SHA-1 `8d9541d67ddbd128ac17df2462c02a1fa38d0f1b` |
| `innsegl-0.0.2.tgz` | SHA-256 `fdfb6bcf2d10545abf89f07bacb32782f93753a9b749ae8e2c6a08ab428f936c` |
| `innsegl-0.0.2.tar.gz` | SHA-256 `50cbfeb03af1910b98e9a9daeb463e0f8d631ef7b84f0e8e0ad0ccd0370ce8ff` |
| `innsegl-0.0.2-py3-none-any.whl` | SHA-256 `8c168dd34e01f55e8ea1365fce4eaf186ca67efe8e32425390bec6deec248635` |

A different toolchain version may gzip differently. If a digest does not match,
diff the tarball contents (`tar -tzf`) before assuming anything is wrong — a
content match with a digest mismatch is a compressor difference, not tampering.

Then look at what is actually in them, and run them:

```
tar -tzf namespace/dist/innsegl-0.0.2.tgz
unzip -Z1 namespace/dist/innsegl-0.0.2-py3-none-any.whl
uvx twine check namespace/dist/innsegl-0.0.2.tar.gz namespace/dist/innsegl-0.0.2-py3-none-any.whl

npm install --no-save namespace/dist/innsegl-0.0.2.tgz && npx innsegl
uv run --no-project --with namespace/dist/innsegl-0.0.2-py3-none-any.whl innsegl
```

Expect five files in the npm tarball (`package.json`, `index.js`,
`bin/innsegl.js`, `README.md`, `LICENSE`), `twine check` PASSED twice, and both
runs printing the source URL, the home page, the module path
`innsegl.dev/innsegl`, the licence, and the report-a-fake line.

### 3.2 npm

```
npm whoami                    # expect the maintainer account
npm publish namespace/dist/innsegl-0.0.2.tgz --access public
```

Publish **the built tarball**, not the directory. `namespace/npm/` has no
`LICENSE` in it — `build.sh` stages that in from the repository root — so
`npm publish` run inside `namespace/npm/` would upload a different, worse
artifact. npm will prompt for the 2FA OTP; if it does not, §2.1 is not done.

Afterwards:

```
npm view innsegl version        # 0.0.2
npm view innsegl license        # Apache-2.0
npm view innsegl dist.shasum    # 8d9541d67ddbd128ac17df2462c02a1fa38d0f1b
npx -y innsegl@0.0.2
```

The `dist.shasum` line is the one that matters: it proves the registry is
serving the exact bytes built from this repository, and it is the check to
re-run any time the package is suspected of having been tampered with.

### 3.3 PyPI

```
uvx twine upload namespace/dist/innsegl-0.0.2.tar.gz namespace/dist/innsegl-0.0.2-py3-none-any.whl
```

Afterwards:

```
curl -sS https://pypi.org/pypi/innsegl/json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['info']['version'], d['info']['license_expression']); [print(f['filename'], f['digests']['sha256']) for f in d['releases'][d['info']['version']]]"
uv run --no-project --with innsegl==0.0.2 innsegl
```

Expect `0.0.2 Apache-2.0` and the two SHA-256 values from the table above.

### 3.4 Record it

Update the *State of the registrations* table in `namespace/README.md` with the
new version and the date, and comment the published digests on #67. The digests
are the evidence; a claim that a publish happened is not.

---

## 4. For real releases: trusted publishing, not tokens

When Innsegl publishes an actual implementation rather than a reservation, do it
without a standing credential. PyPI and npm both support OIDC trusted
publishing: the project is bound to `Raymalian/innsegl` and a named GitHub
Actions workflow, and the registry issues a short-lived credential to that
workflow at publish time. No long-lived token exists to leak, and a publish that
did not come from the named workflow cannot happen.

This is the same argument Innsegl makes about agents — a credential scoped to
one purpose, for the duration of one run, is not a secret anyone can steal
later. A project whose product is that claim should not be publishing itself
with a token that never expires. It fits with RM-056 (#64).

## 5. Watching for squatters

Nothing above prevents someone registering `innsegel` tomorrow; registries have
no such control to offer. Detection is the only available answer.

- [ ] Quarterly, run the sweep in `namespace/README.md` against near-miss
      spellings on both registries and confirm they are still unclaimed.
- [ ] If one appears: report it through the registry's abuse/support channel —
      check the registry's current dispute policy at the time rather than
      assuming one — open an issue here so the record is public, and name it in
      `SECURITY.md` if it is malicious rather than merely parked.

## What this procedure does not do

- It does not stop typosquat registration. AB-09's registration half is
  unclosable by anyone but the registries.
- It does not protect the domain against a compromise of the Cloudflare account
  itself — §1.1 reduces the odds; nothing here detects it. A repointed
  `innsegl.dev` would be visible in DNS and in `go-import` metadata, and is worth
  an uptime check once the site is live.
- It does not make the published stubs verifiable with Innsegl's own tooling.
  Both registries support signed provenance; adopting it belongs with §4 and the
  first real release.
