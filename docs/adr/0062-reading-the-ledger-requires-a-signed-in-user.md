# ADR-0062: Reading the ledger requires a signed-in user

- Status: proposed
- Date: 2026-09-28
- Deciders: the operator

## Context

IP §1 lists the dashboard as a read-only web UI over the ledger and Rekor:
a runs table, a run-detail timeline, the three-check verification per
commit, and a public paste-a-SHA verification page. Every one of those
routes has run, since ADR-0044, with no login at all — the only stated
control is "read-only" (no mutating route exists) and "loopback only" (the
socket is not published beyond the machine it runs on).

**Why loopback was ever enough, and why it stops being enough now.**
Loopback answers a network question: which machine may open the socket. It
has never answered a process question: which program on that machine may
open it. The flight-recorder threat model (`agent-flight-recorder-threat-model.md`,
reviewed per doc 04 §6 because the gateway it covers is a new trust
boundary) names the adversary classes that live on the *far* side of that
gap explicitly — **A2**, a compromised or prompt-injected agent running as
the operator's own user, and **A3**, any other software running as that
same user. Row **I4** states the dashboard's own exposure in exactly those
terms: "Dashboard on loopback only; bodies shown to the logged-in operator
only — **Avoided (when built)**." The parenthetical is the finding: the
mitigation that makes I4 avoided rather than residual does not exist yet.
Row **I3** makes the same point one layer down, about the stores the
dashboard would read from — "the service user owns the stores, mode 0600" —
a control that separates *another OS user* from the data, and says nothing
about a process sharing the operator's own account, which is precisely what
an agent's shell is. Row **S1** shows the same class of actor already
proven able to send the gateway a request under a forged identity header;
nothing about the dashboard's HTTP surface is harder to reach than the
gateway's. A login check enforced by the server is one fact to verify,
independent of how any particular caller is sandboxed; relying on every
caller's sandbox to be configured correctly is not — and
`admin-access-and-identity.md` already measured a sandbox gap of exactly
this shape on a different surface ("an agent's shell can run `docker`... and
mint an admin credential"). A boundary that has already been found
misconfigured once is not the boundary to lean on for a second surface.

**Why this is urgent now and was not urgent before.** Today's dashboard
shows metadata: run identifiers, timestamps, verification badges. The run
page this ADR's epic (#362, E19) is building changes that materially — per
the operator's own requirement (`agent-flight-recorder.md` §10.4), it shows
a file tree of every file an agent touched and, per file, a diff with
additions and removals, including changes later reverted or never
committed, plus every action's command and output. That is exactly the
"conversation content (code, commands, outputs, secrets in them)" the
threat model's own asset table names first. Shipping that content behind a
boundary that a same-user process already defeats is the specific gap
`agent-flight-recorder.md` §10.7 records as an operator decision: "The
dashboard and the read API move behind a passkey (WebAuthn) login before
the run page shows any content, which supersedes ADR-0044's no-login read
posture. Loopback does not keep out agents running as the same user." This
ADR is that decision, written out with its reasons and its alternatives.

**What this is not.** IP §3's **E1** is explicit: "This system answers 'who
did it,' not 'was it allowed.' No policy engine, no RBAC beyond protecting
the MCP admin surface itself." A login check that gates the read *surface*
sits inside that carve-out the same way `account-identity-complete-plan.md`
§3 already argued for the MCP admin listener's own bearer check: "the
bearer check *is* protecting the MCP admin surface... [not] the day A
refuses a signed action because B said the *agent* may not." This ADR
protects the dashboard and read API's own surface the identical way. It
decides nothing about *who may see which run* — every signed-in user sees
everything the read API already serves, exactly as today, because there is
exactly one user until #409 exists to add a second. Per-project or per-run
scope is a future link (see Decision 3) and an authorization policy the day
it is built, which is precisely why it is not decided here.

**Relationship to two other local plans, named so the boundary is not
confused with either.** `admin-access-and-identity.md` is about the
*write* side — resolve-alert, keygen, retire, restore — reached over a
human-presence-gated admin credential, and its own optional Phase 5 admin
web panel is a *different*, not-yet-built surface with its own future ADR.
This ADR is about the existing *read-only* dashboard and read API only; it
adds no mutating route and takes nothing away from doc 06 P6's "no
mutating action exists anywhere in the UI."
`docs/decisions/account-identity-complete-plan.md`'s Phase 1 (#264, done)
put a bearer check on the MCP's *admin listener* — the boundary a harness
or an agent crosses to register or retire a run, authenticated by a
machine-minted JWT with no human in the loop. This ADR's boundary is a
*human's browser* reading the dashboard, authenticated by a passkey with a
human very much in the loop. The two are orthogonal trust boundaries
guarding different callers with different credentials; #264 being done does
not touch this gap, and this ADR does not touch #264's.

## Decision

**Every dashboard page and every read API route — the proof backend
included — refuses to answer without a valid session for a signed-in user.
A route is admitted only by being added to an explicit, reviewed list; a
route nobody decided about is refused by default**, inverting today's
implicit "everything answers" default. This is #410's build, and this ADR
commits to the direction: deny-by-default over allow-by-default, so that a
route added later without a decision fails closed rather than quietly
inheriting yesterday's openness.

**The public paste-a-SHA verification page (IP §1) is the one exception,
and it stays narrow.** It answers with no session, and it is wired only to
the live three-check verification path — Fulcio chain, Rekor inclusion,
trailer-to-certificate match, using the commit the caller supplies plus
public trust material. It has no path to the body store, the run page's
diffs, or any other stored content, and this ADR treats that absence as an
architectural boundary to hold, not an oversight to eventually close. This
is the same "no oracle" discipline `account-identity-complete-plan.md`
decision 6 already applied to a public host's health body (the AB-27
enumeration leak, fixed by keeping posture flags off the surface the public
can reach) — applied here to content rather than to configuration.

**Passkey (WebAuthn) only, user verification required. No passwords, ever.**
A password is a shared secret that must live somewhere the operator's own
processes can read it back — a file, an environment variable, a form
autofill store — which is exactly the same-user-readable surface that made
loopback insufficient in the first place (I5 in the flight-recorder model:
"Tokens exist only inside the gateway... no token files remain," closing
"today's same-user gap" for run tokens the same way this ADR closes it for
the operator's own login).

**A user account is the unit of login: a stable user id, a display name,
and one or more passkeys.** This is the first step of the user-account
model, not a one-off "operator passkey" bolted onto ADR-0044 — per the
operator's own framing (`agent-flight-recorder.md` §10.7's later note):
"the login is the first step of the user-account model
(`docs/decisions/account-identity-complete-plan.md`); one user now, more
users and user→run/project/action links later, no redesign." Concretely:

- `user_id` is a stable, generated identifier, minted once at enrolment and
  never derived from the display name — so the display name can change
  without touching anything that references the user.
- **The first user is enrolled only in the owner's physical presence** (the
  owner is simply the first user this table ever holds — nothing in the
  model treats them as a distinct kind of row).
- **A later user is added by an existing signed-in user, with presence**: a
  live session plus a fresh WebAuthn ceremony (`userVerification: required`)
  performed at the moment of adding, not merely a valid cookie. The same
  presence requirement governs adding a *second* passkey to an existing
  user. Neither action is available to a request carrying only a session
  cookie and nothing more.
- **Only one user's worth is built now.** The data model is additive-only
  from here: `users`, `passkeys` and `sessions` gain rows, and later work
  adds *columns elsewhere* that reference `users.user_id` — it does not
  migrate what these tables already hold. Named, and explicitly **not**
  built by this ADR: a `resolved_by` link from `innsegl.alert_resolutions`
  (ADR-0044, free text today) to a user; a scope linking a user to the
  projects or repositories they may see, once more than one user exists and
  seeing "everything" per Decision above stops being adequate (that link,
  when it is built, is an authorization decision and needs its own ADR,
  per E1); a "who is viewing this run" presence marker on the run page.
  None of these has a row, a column, or a migration today.

### The enrolment crux

An agent running as the operator's own user can, in principle, drive a
software or virtual WebAuthn authenticator — a browser automation surface
that completes a registration ceremony end to end with no human touch,
setting the user-verification flag itself rather than obtaining it from
real hardware. `userVerification: required` alone does not stop this: it
is the *authenticator*, not the relying party, that reports whether
verification happened, and a software stand-in can report anything it
likes. Two mechanisms were evaluated against exactly this threat.

**(a) Attestation-required enrolment** — request `attestation: "direct"`
and accept only a statement that chains to a platform vendor's root or a
FIDO Metadata Service entry, rejecting `self` and `none`. This does close
the software-authenticator case: a virtual authenticator has no hardware
root to attest to, so a chain-verification refusal catches it directly.
**What it leaves open, and why it is not chosen alone:** the platforms this
project's own operator is most likely to use for a platform passkey
increasingly sync credentials across devices by design (iCloud Keychain,
a browser's own password manager), and a synced, multi-device credential
is not tied to one piece of hardware the way a device-bound credential is —
its issuer typically reports `none` for exactly that reason, not as an
evasion. Enforcing attestation would refuse the operator's own ordinary
passkey unless they specifically provision a device-bound one (a hardware
security key, most commonly), which is a real UX and hardware-acquisition
cost this ADR does not require. It also adds a standing dependency this
project does not otherwise carry: a maintained root or metadata-service
store, fetched and kept current, or the check silently stops meaning
anything the day a new authenticator model ships. And attestation says
nothing about *who* is present at the ceremony — a human at a genuine
platform sensor and an automated script driving that same genuine sensor
through the OS's own UI (if such automation exists) would both attest
identically; attestation constrains *what* registered, not *whether a
human touched it*.

**(b) An out-of-band one-time code, issued only through the operator's
existing human-presence admin path** — the Secure-Enclave or
hardware-backed admin credential already required for every other admin
action, which the operating system will not use without a live touch or
biometric check. Minting the code is the presence gate; the WebAuthn
ceremony itself accepts whatever authenticator the browser offers,
attestation format unexamined. **Chosen.** It targets the actual threat
named in scope — completing enrolment *unattended* — directly, rather than
by proxy through the resulting credential's cryptographic pedigree; it
imposes no hardware requirement or metadata-service dependency; and it
reuses a mechanism this project already built and already trusts for
exactly this property, matching the fewer-parts direction ADR-0056 and
ADR-0060 already committed to rather than adding a second, parallel
gate. The code is single-use and short-lived, and is delivered only through
a channel the operator's own coding-agent tool access does not reach — the
same principle `admin-access-and-identity.md` §4 already applies to the
admin SSH key itself.

**Attestation is not discarded, only not enforced.** The format an
authenticator reports at registration is recorded on the passkey's row,
unenforced, so that `self`/`none` at enrolment is a fact available to
review later rather than information thrown away — the same "record it
rather than assume it never comes up" instinct ADR-0042 applied to the
public-log question it could not fully close. Tightening it into an
enforced check, if the out-of-band path is ever found insufficient on its
own, is a future ADR's decision, not this one's.

**Recovery when the only passkey is lost is the same door, not a new
one.** There is no password to fall back to and no email address on file
to send a reset link to (this project holds no operator email anywhere —
`account-identity-complete-plan.md` §5's own rule for its accounts service,
"never email," applies here for the same reason). Recovery re-runs
first-user enrolment: a new one-time code, minted only through the
human-presence admin path. There is no self-service "I lost my passkey"
flow reachable from a session, a cookie, or anything else a script running
as the operator's user could trigger — that flow would be exactly the hole
this ADR closes, reopened under a different name.

### Session and recording

- The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, with a
  bounded lifetime and an explicit logout that removes the server-side
  session row (not merely instructs the browser to forget the cookie). The
  exact lifetime is a value #409 measures and tunes against real use, not a
  number this ADR fixes.
- **Every enrolment, sign-in and refusal is recorded.** The need is named
  here; the mechanism is not invented here. Following ADR-0044's own
  precedent for the shape a security-relevant record takes when it is not
  part of the agent-attribution chain — a plain, non-append-only table
  beside `innsegl.events`, not a new `event_type` — this ADR's default is a
  table of that shape (an "auth events" table, mirroring
  `account-identity-complete-plan.md`'s own `audit` table for its
  account service), which needs no doc 02 change because it adds no field,
  type or grammar to the protected schema. If a later need — tamper-evidence
  for the sign-in record itself, say — turns out to require binding it into
  the chain proper, that is a new `event_type` and goes through doc 02's
  protected-schema process on its own merits, the same way ADR-0057 left a
  new capture-event type undecided rather than inventing one to avoid the
  process.
- **The credential that answers a WebAuthn ceremony or issues a session
  must never be able to write `innsegl.events` or any table
  `internal/api/readonly.go`'s `AssertReadOnly` already protects.**
  ADR-0044 drew this line once, for the resolutions table, by extending the
  same schema-wide probe rather than opening a second store; this ADR draws
  it again, the same way, for whichever new, small, mutable schema holds
  users, passkeys, sessions and auth events. The dashboard's existing
  read-only ledger role gains no new grant to make session-checking work —
  it may be given `SELECT` on the new schema (a session lookup is a read),
  never `INSERT`, `UPDATE` or `DELETE` on it or on anything ADR-0044 already
  covers. Which process holds the write-capable half of that credential —
  a new companion in ADR-0060's `-also` family, or a second, narrower pool
  inside the existing dashboard process — is #409's engineering decision;
  this ADR commits only to the invariant both choices must satisfy, verified
  by a startup probe the same way `AssertReadOnly` already is.

### Open question for the operator: is a "user" here a future accounts-service "principal"?

`account-identity-complete-plan.md` §6 designs its own human sign-in for a
different, not-yet-built surface — B's `/v1` API, authenticated by class
**H**, "human OIDC session + CSRF," for a multi-tenant deployment where an
account owns repositories and a principal (an OIDC `iss`+`sub`) belongs to
an account. That plan's Phase 3 (B service, ADR-0053) has not been built.
This ADR introduces a *different* mechanism — passkey enrolment with no
external identity provider — for the read boundary that exists today,
independent of whether B is ever built at all. Both plans converge on the
word "user" doing similar work, and this ADR does **not** resolve whether
they are the same entity:

- If B is later built, is the `users` row this ADR creates the same row as
  a B `principal`, reconciled at that point (a principal *is* a user, with
  an OIDC identity added to a passkey one, or vice versa)? Or does this
  ADR's `users` table stay the self-hosted default's own mechanism,
  permanently separate from B, for deployments that never stand up an
  accounts service at all?
- B's own design deliberately keeps human sign-in dependent on an external
  OIDC issuer, matching a hosted, multi-tenant posture; this ADR
  deliberately keeps it dependent on nothing external, matching the
  self-hosted, single-machine default doc 05 describes. Whether the project
  wants exactly one human-login mechanism long-term, or two for two
  different deployment shapes, is not decided by this ADR and is named here
  rather than assumed either way.

This is flagged rather than settled because settling it would mean
designing B's Phase 3 by inference from a read-login ADR, which is the
exact move `.claude/CLAUDE.md` forbids: "Never edit a spec document to
match an inference. A conflict is a question for the human."

## Alternatives considered

- **Keep no login; sandbox-block the port instead.** Deny the dashboard's
  loopback port to the agent's own tool sandbox (managed settings network
  rules) and call the surface closed. Rejected: the threat model's adversary
  A3 — "other software running as the operator's user" — is not a sandboxed
  tool call at all, and no per-agent sandbox rule reaches a cron job, a
  second terminal, or any other ordinary program on the machine. Even for
  A2, the control would be enforced by the *harness's* sandbox
  configuration, which `admin-access-and-identity.md` already measured
  failing once on a comparable surface (an agent's shell running `docker`
  unsandboxed). A server-side session check is one fact to verify; N
  callers' sandbox configurations are not.
- **Passwords.** Excluded by scope, and for a concrete reason beyond that:
  a password is a shared secret that must be typed, stored or autofilled
  somewhere the operator's own user account can read — a file, an
  environment variable, a browser's own store — which collapses back to
  the same same-user exposure loopback already had. It buys nothing over
  the status quo it would replace.
- **A client TLS certificate presented by the browser.** Rejected on two
  concrete grounds: a certificate provisioned into the browser's store is
  either backed by the OS keychain (no stronger a guarantee than a
  passkey's own hardware backing, so nothing is gained) or sits in a file
  on disk, which is exactly the same-user-readable surface a password has.
  It is also not origin-bound the way a passkey is — a WebAuthn credential
  is scoped to the exact origin by the browser itself, which is
  phishing-resistant in a way a portable client certificate is not.
- **OS-user separation** (run the browser session as a different account
  than the one agents run under). Rejected: it does not change who the
  operator is when they open the dashboard from their own everyday session,
  and it answers a different question than I4 asks. I4's mitigation is
  "bodies shown to the logged-in operator only" — logged into *what* is the
  question a login check answers directly; a separate OS account answers
  only "which account rendered the page," which still says nothing about
  whether the request came from the operator's own hand or from a process
  running under that same separate account. It would also demand the
  operator maintain and switch into a second account for routine use, a
  real operational cost this ADR's mechanism does not impose.

## Consequences

**Easier.** Once E19 ships, an operator can open the run page's diffs,
commands and outputs without every other process on their machine being
able to read the same content over loopback. The two boundaries stop being
asked to do each other's job: loopback keeps doing what it has always done
(no LAN exposure), and the session check does what loopback never could
(no same-user exposure).

**Harder.** Every dashboard and read-API route now carries a positive
obligation to be listed, checked and tested — #410's deny-by-default table
test is what makes forgetting a build failure rather than a silent gap, but
it is still a discipline every future route pays for. A fresh deployment
now needs one deliberate, in-person step — the first user's out-of-band
enrolment — before the dashboard shows anything at all, a small cost
against the alternative this ADR closes.

**Now settled, not yet built.** This ADR fixes the *why* — loopback and
read-only-database-role are not sufficient once same-user adversaries and
run-page content are both in scope — and the *what*: passkey-only,
deny-by-default routes, a public verification page that never touches
stored content, a presence-gated enrolment and recovery path, and a
`users`/`passkeys`/`sessions` shape built to be added to, not migrated. It
does not build the WebAuthn ceremony, the session middleware, the
deny-by-default route table, the auth-events table, or the write-path
credential split — those are #409 and #410, with test IDs assigned by the
supervisor per this epic's convention.

**Exit cost if reversed: low on the mechanism, real on the record.**
Removing the session check is mechanically small — the middleware comes
out and ADR-0044's original posture returns, with no ledger content
touched, because nothing here writes to `innsegl.events`. It is not free on
the trust story: every read served with a session between this ADR's
acceptance and any reversal is a period the record cannot show was read by
the operator alone, and any user or passkey data collected in that window
needs its own erasure decision — following
`account-identity-complete-plan.md` §10's precedent for its own
account data — before the tables holding it are dropped.
