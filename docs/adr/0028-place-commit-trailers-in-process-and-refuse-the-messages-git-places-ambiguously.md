# ADR-0028: Place commit trailers in process, refuse the messages git places ambiguously, and read I6 as "never emit `Co-authored-by:` at all"

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike

## Context

IP §1, component 3, names the artefact this ADR is about:

> Structured trailers on every commit: `Agent-Identity:`, `Agent-Run:`,
> `Agent-Task:`. Trailer is the claim; signature is the proof; verification
> requires they match.

and I6 constrains who the commit is authored by:

> No GitHub contributor is ever added. Commit author is the human operator or a
> deliberately unlinked address; agent identity lives only in trailers +
> signature. Never emit `Co-authored-by:` with a resolvable account.

Three forces meet in RM-031, and each of them is a decision the issue does not
make for us.

**1. Git trailers are a placement problem, not a formatting problem.** A
trailer is not "a line at the end of the message". It is a line in the last
paragraph of the message, where whether that paragraph counts as a trailer
block is decided by a rule with several clauses. `git-interpret-trailers(1)`
states it:

> Existing trailers are extracted … by looking for a group of one or more lines
> that (i) is all trailers, or (ii) contains at least one Git-generated or
> user-configured trailer and consists of at least 25% trailers. The group must
> be preceded by one or more empty (or whitespace-only) lines. The group must
> either be at the end of the message or be the last non-whitespace lines
> before a line that starts with `---`.

Measured against git 2.50.1, that rule bites in ways that are not guessable.
A four-line final paragraph containing one `Signed-off-by:` is a trailer block;
the same paragraph with one more prose line is not. A final paragraph of
`Refs:` and `Bug:` and nothing else is a trailer block even though neither
token is git-generated. A one-line message `Fix: the thing` is *not* a trailer
block, because nothing precedes it. Trailing comment lines are skipped, and a
`---` line anywhere truncates the message for placement purposes — including a
markdown horizontal rule in the middle of a body.

Getting this wrong is not cosmetic. A trailer git's parser does not find is
invisible to `git log --format='%(trailers)'`, to `git interpret-trailers
--parse`, and to anything downstream built on either. **A claim nothing can
find is not a claim.**

**2. The trailer keys are a protected surface.** VERSIONING.md surface 2 and
doc 08 §3 make `Agent-Identity` / `Agent-Run` / `Agent-Task` character-exact,
changeable only in a major release with a migration attestation.

**3. I6's `Co-authored-by:` clause has a qualifier we cannot evaluate.** "Never
emit `Co-authored-by:` **with a resolvable account**" asks whether an address
resolves to a GitHub account — a fact about GitHub's user table at some future
moment, which no code in this repository can observe. Threat model §5.3 already
records that I6's guarantee is empirical and dated (GH-001).

Invariants in play: I6 throughout; I5 in decision 4 (a verifier must be able to
settle the claim against Fulcio and Rekor alone); I2 indirectly, because the
message this package renders is the preimage of the object gitsign signs.

## Decision

**1. Placement is implemented in this repository. `git interpret-trailers` is
not invoked at signing time.**

The decisive reason is that `git interpret-trailers` reads configuration that
can rewrite a protected string. `trailer.<token>.key` replaces the token,
`trailer.separators` replaces the `: `, and `trailer.where` / `ifExists` /
`ifMissing` move the result. A `~/.gitconfig` or a repository `.git/config`
containing `[trailer "agent-identity"] key = X-Agent-Identity` would produce a
signed commit whose protected trailer key is not the one VERSIONING.md
protects, and the signature would cover the rewritten form. Neutralising that
means enumerating every `trailer.*` knob of every git version, forever, and
being wrong about one of them is silent.

Two further reasons. The rendered message is the preimage of the commit object
and therefore of the signature, so it must be a pure function of (message,
claim); a subprocess reading ambient configuration is not. And the output has
to be re-checked against the three protected keys regardless, which means a
parser exists in this repository either way.

The cost is real and is stated plainly: this is a second implementation of a
rule git already ships, which is the shape of thing threat model §5.4 warns
about for canonicalization ("single blessed library per language … cross-
implementation fixture checks"). Decision 3 is the mitigation §5.4 itself
prescribes.

**2. Two placements are implemented; the ambiguous ones are refused.**

After normalisation — leading blank lines and trailing whitespace stripped,
exactly one terminating newline, the part of `git commit --cleanup` that
changes where a block lands — the last paragraph is classified:

- *No line is trailer-shaped*: the trailers open a new paragraph. Git agrees;
  it reads no trailer block there either.
- *Every line is trailer-shaped and the paragraph is not the whole message*:
  the trailers join it, with no blank line. Git agrees, by clause (i).
- *Every line is trailer-shaped and it IS the whole message*: new paragraph.
  Git agrees, because a trailer block must be preceded by a blank line.
- *Mixed*: **refused.** This is the only case where clause (ii)'s 25% heuristic
  and its "user-configured trailer" term decide the answer, and the second of
  those is exactly the configuration decision 1 refuses to read.

Four message shapes are refused outright, because for each one the trailers
would land where git's parser will not look for them: a `---` divider line
anywhere; a trailing `#` comment line; a carriage return or any other C0
control but tab and newline; and an empty message. None of these can reach
`sign_commit` legitimately — `---` plus a diffstat and trailing comment lines
are artefacts of `git format-patch` and of the `git commit` editor, not of a
message argument in IP §4.

The classifier used to decide "trailer-shaped" is deliberately **narrower**
than git's, and the asymmetry is chosen, not incidental. Calling a line prose
that git calls a trailer costs one blank line, after which our three trailers
are the final all-trailer paragraph and git still finds them. Calling a line a
trailer that git calls prose would merge the claim into a paragraph git reads
as prose — and the claim disappears. Every error is pushed onto the harmless
side.

**3. `git interpret-trailers` is the oracle, in the test suite, on every
accepted input.** SIG-006's differential half runs real git over each accepted
case and asserts two things: that git's own parser reports all three trailers,
in order, in our rendered message; and that our bytes equal git's bytes for the
same three trailers on the same normalised message. Git is run with
`GIT_CONFIG_NOSYSTEM`, a non-existent `GIT_CONFIG_GLOBAL`, a `HOME` and a
`GIT_CEILING_DIRECTORIES` inside the test's temporary directory, so the oracle
is git's behaviour and not the developer's configuration. This is §5.4's
cross-implementation check, applied to the one place a second implementation
was accepted.

**4. All three trailers are held to the SPIFFE ID in `Agent-Identity`.**
`Agent-Run` must equal that identity's `{run_id}` segment, and `Agent-Task`
must lowercase to its `{task_id}` segment — ADR-0018 §6's rule, that `task_ref`
is recorded verbatim and lowercased into the SPIFFE ID, read back out.

The three trailers are therefore redundant with one another by construction,
and that is the point. IP §1's check 3 compares the certificate's SPIFFE ID
against `Agent-Identity`; because the other two are derivable from it, one
comparison settles all three, for a verifier holding only the commit, the
certificate and the Rekor entry — no access to this system's database (I5).
Without this rule a caller could sign a commit whose `Agent-Identity` matches
its certificate perfectly while `Agent-Run` and `Agent-Task` say something
else, and check 3 would pass.

**5. `Co-authored-by:` is never emitted, and a message that already carries one
is refused.** I6's "with a resolvable account" qualifier is unevaluable here,
and I5's discipline — never assert what you cannot check — leaves exactly one
safe reading: emit none, ever. The refusal covers the caller's message as well
as our own lines, because the message we render is what gets signed, and a
co-authorship trailer in an operator-supplied body would ride into the commit
unchanged. Matching is on the token at the start of a line,
case-insensitively, with optional whitespace before the separator — every
spelling git or GitHub might read as the key. Prose that merely mentions the
words mid-line is not matched.

**6. "Unlinked" means a domain the DNS guarantees will never exist.**
`AuthorPolicy` is an allowlist with two rules and a zero value that admits
nothing:

- `Operators` — exact addresses, in whatever form the human operator uses.
  Which addresses belong to the operator is not a fact a pattern can derive;
  only the operator can state it.
- `AllowUnlinked` — an address whose domain is, or is under, one of the names
  RFC 2606 §2 and RFC 6761 reserve: the `.invalid`, `.example`, `.test` and
  `.localhost` top-level names and `example.com` / `.net` / `.org`. These are
  guaranteed never to be delegated in the public DNS, so no mailbox in them can
  receive a verification message, so no GitHub account can ever hold one as a
  verified email, so no commit authored by one can ever produce a contributor.
  The guarantee is a property of the naming system, not of GitHub's current
  behaviour — which matters, because threat model §5.3 says GitHub's behaviour
  is the thing that may change.

**A `@users.noreply.github.com` address is explicitly NOT admitted by the
unlinked rule.** It looks like the answer and is the opposite of it: that form
is precisely how GitHub attaches a commit to an account. `1234+alice@users.
noreply.github.com` makes alice a contributor. It is admissible only by being
listed as an operator — which is correct, because when it is the human
operator's address, the human operator is exactly who I6 says the author should
be.

The address grammar is narrower than RFC 5322 (unquoted dot-atom local part,
dotted host domain, RFC 5321's 254-byte cap). The author email is written into
a commit object as `Name <email>`; an address carrying an angle bracket, a
comma or a newline can forge a second identity in a field the signature then
covers.

**7. The guard blocks; it does not warn.** `CommitMessage` runs `CheckAuthor`
first and returns an empty string with every refusal, so a caller that ignores
the error still has nothing to hand to gitsign. The zero-value policy admitting
nothing is the same choice: I6 is the one invariant with no cryptographic
backstop — a contributor that should not exist is detected only by GH-001's
empirical test against a real repository, long after the push.

**8. This package defines no error class.** Every failure it can produce is a
refusal of a malformed or forbidden request, and `internal/mcp.Classify`'s
documented fallback for an error it cannot name is `INVARIANT_VIOLATION`, not
retryable — the class ADR-0018 chose for the same shape of failure. A
`signing.Class` would put the protected error vocabulary in a third package to
say what the fallback already says.

## Alternatives considered

- **Shell out to `git interpret-trailers` at signing time, neutering the
  configuration with `GIT_CONFIG_NOSYSTEM=1`, an empty `GIT_CONFIG_GLOBAL` and
  a cwd outside any repository.** The strongest competitor, and what the test
  suite does. Rejected for production because the neutering is a
  denylist against an open set: it holds only as long as those three variables
  remain the complete set of paths by which `trailer.*` configuration reaches
  the process, across every git version an adopter might have installed. A
  future knob, or a distribution patch, silently rewrites a protected string
  into a signed commit. The failure is undetectable at the moment it happens
  and permanent afterwards. Against that, the thing bought is placement logic
  that fits in forty lines and is pinned against the reference on every CI run.

- **Implement git's rule in full, including clause (ii)'s 25% heuristic, and
  accept the mixed paragraph.** Rejected on two grounds. The heuristic's second
  input is "Git-generated **or user-configured** trailer", and the
  user-configured half is the `trailer.<token>` configuration decision 1
  refuses to read — so the rule is not implementable without either reading
  that configuration or silently diverging from git exactly where an operator
  has customised it. And a final paragraph that is half prose and half trailers
  is ambiguous to a human reader too; refusing it costs a caller one blank line
  and buys a placement that is decidable.

- **Refuse any message containing a trailer block, and always append a fresh
  paragraph.** Simpler than decision 2 and rejected as hostile: a
  `Signed-off-by:` is a legitimate and common thing for a commit message to
  carry (DCO), and refusing it would make Innsegl unusable in the repositories
  most likely to want it.

- **Accept the mixed case by always inserting a blank line, silently.**
  Rejected because it is silent. Our three trailers would still be found, but
  the caller's `Signed-off-by:` would be pushed out of the last paragraph and
  out of `%(trailers)` — the caller's own trailer destroyed by a tool they
  asked to add three. A refusal tells them; a blank line does not.

- **Strip a `Co-authored-by:` from the caller's message instead of refusing
  it.** Rejected: it is a silent mutation of an operator's commit message, made
  by the component whose entire product is faithful attribution. Refusing puts
  the decision where it belongs.

- **Emit `Co-authored-by:` with an address chosen to be unresolvable (the
  reserved domains of decision 6), on the reading that I6 forbids only the
  resolvable case.** Genuinely arguable, and rejected because I6's other
  sentence settles it: "agent identity lives **only** in trailers + signature".
  A fourth trailer carrying agent identity is a fourth place it lives. It would
  also depend forever on GitHub continuing not to create contributors for
  addresses it cannot resolve — precisely the external behaviour §5.3 says is
  a dated snapshot. Emitting nothing depends on nothing.

- **Accept `@users.noreply.github.com` as the "unlinked" pattern**, which is
  the form I6's own phrasing most readily suggests. Rejected because it is
  backwards: GitHub's noreply address is the mechanism by which a commit is
  linked to an account without exposing a mailbox. Admitting the *form* would
  admit `agent-bot@users.noreply.github.com` for an agent-shaped account, which
  is the exact outcome I6 exists to prevent. It remains admissible as an
  operator address, where it means the human.

- **Configure the author gate with a regular expression, per IP §6.9's word
  "pattern".** Rejected: a regex in configuration is a place where one typo —
  an unescaped dot, a missing anchor — silently opens the gate, and this gate
  has no cryptographic backstop behind it. Two rules that cannot be
  mis-specified beat one that can.

- **Allow a domain wildcard for the human case (`*@acme.com`).** Rejected for
  the same reason at lower volume: it admits every future address in the
  domain, including the agent-shaped service accounts an organisation will
  eventually create. An organisation whose operators are enumerable can
  enumerate them.

- **Fold the local part of an address case-insensitively when matching
  `Operators`.** Rejected: RFC 5321 §2.3.11 leaves the local part to the
  receiving host, so two spellings are not known to be one mailbox, and
  admitting more than was listed is the wrong direction for an allowlist. The
  domain IS folded, because DNS labels are case-insensitive (RFC 1035 §2.3.3).
  A refusal here is loud and the operator's fix is to list the spelling they
  use.

- **Skip an unparseable entry in `Operators` and carry on.** Rejected: it turns
  a configuration typo into a silently narrower allowlist, discovered later as
  an unexplained refusal. An unreadable policy admits nothing and says which
  entry it could not read.

## Consequences

- **A second implementation of a git rule now exists in this repository, and
  its correctness is a CI property rather than a structural one.** If the
  differential test is ever skipped — `gitOrSkip` skips when no `git` is on
  PATH — placement is asserted only against this project's own expectations.
  The skip is loud and says so. A machine that can clone this repository has
  git, so the case is close to hypothetical, but it is the one way this
  decision degrades quietly.

- **`core.commentChar` is a residual.** The trailing-comment refusal hardcodes
  `#`, git's default. An operator who has set `core.commentChar` to something
  else has a character git's parser will skip and this package will not refuse.
  The consequence is bounded — trailers placed after such a line would be
  invisible to `%(trailers)`, not wrong — and closing it would mean reading git
  configuration, which decision 1 refuses. **Flagged, not resolved.**

- **doc 07 has no test ID for the placement differential.** SIG-006 covers
  "trailer writer output" and is where the differential lives, but the property
  that pins it — *our placement equals git's placement* — is unnumbered and
  would be the thing to notice if it were ever deleted. Proposed: **SIG-009**
  (U) trailer placement agrees with `git interpret-trailers` on every accepted
  message.

- **The author policy has no wiring yet.** `AuthorPolicy` is a value; nothing
  in this issue reads it from a configuration file or an environment, and
  RM-032/RM-033 will have to. Because the zero value admits nothing, a wiring
  that forgets it fails closed and loudly at the first `sign_commit` rather
  than signing with an unguarded author. That is the intended failure.

- **IP §6.9's repo-level CI gate is not built here.** `CheckAuthor` is exported
  so that gate asks this package's question rather than a second question
  shaped like it, but the gate itself — walking a repository's commit authors —
  belongs to RM-038 and to `.github/`, neither of which this issue owns.

- **RM-037 must not use this package to parse.** The classifier here is
  deliberately strict because it is a *writer's* classifier, and the safe
  direction for a writer is the unsafe direction for a verifier: a verifier
  that fails to recognise a trailer git recognises would report a signed,
  correctly-trailered commit as unverified. Verification parses with git's
  rules. That is why no parser is exported from this package.

- **Exit cost.** Low, and asymmetric in the useful direction. The rendered
  bytes are a pure function of (normalised message, claim), so switching to a
  subprocess later changes nothing already written as long as the subprocess
  produces the same bytes — which the differential test already asserts it
  does, today, for every accepted input. The refusals are the expensive half to
  reverse: a message shape refused before the first tag is a message shape
  callers never learned to send, whereas widening the accepted set afterwards
  is always safe and narrowing it never is. Decision 4 is the one that is
  permanent: `Agent-Run` and `Agent-Task` values consistent with the SPIFFE ID
  are in signed commits and in Rekor, and relaxing the rule later would mean
  verifiers can no longer assume across the cutover what they can assume
  before it.
