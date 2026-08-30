// SPDX-License-Identifier: Apache-2.0

// Package signing writes the commit trailers that carry an agent run's claim,
// and holds the I6 gate on who a signed commit may be authored by.
//
// # The trailer is the claim, not the proof
//
// IP §1, component 3, states the division this package sits on one side of:
//
//	Structured trailers on every commit: Agent-Identity:, Agent-Run:,
//	Agent-Task:. Trailer is the claim; signature is the proof; verification
//	requires they match.
//
// Nothing in this file verifies anything. It renders three lines of text that
// SAY which run produced a commit. A caller with a valid credential and a
// caller with a stolen one produce identical trailers; what separates them is
// the Fulcio certificate the commit is signed under, and the comparison of the
// certificate's SPIFFE ID against the Agent-Identity trailer — check 3 of
// IP §1's three checks, implemented by RM-037's verifier and by the dashboard,
// not here. Naming in this package is chosen to keep that straight: a Claim is
// claimed, a message is rendered, an author is admitted. Nothing is attested,
// proven or verified.
//
// The one thing that IS made stronger here is internal consistency. All three
// trailers are held to the SPIFFE ID in Agent-Identity: Agent-Run must be that
// identity's run segment, and Agent-Task must lowercase to its task segment
// (ADR-0018 §6). The trailers are therefore redundant with each other by
// construction, which is what lets check 3 — a comparison against the
// certificate alone, with no access to this system's database (I5) — settle
// all three at once instead of only the first.
//
// # Protected strings
//
// The three trailer keys are a PROTECTED SURFACE (VERSIONING.md surface 2,
// doc 08 §3). They are character-exact, they are pinned by
// scripts/protected-surfaces.sh and by
// TestSIG006TheProtectedTrailerKeysAreSpelledExactly, and they change only in
// a major release with a migration attestation.
//
// # Placement
//
// This package places trailers itself rather than shelling out to
// `git interpret-trailers`, and refuses the inputs where placement is
// ambiguous. ADR-0028 records why, and the differential half of SIG-006 pins
// the result against git on every accepted input.
package signing

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// The three trailer keys of IP §1. PROTECTED STRINGS: character-exact, changed
// only in a major release (VERSIONING.md, doc 08 §3). The Go identifiers are
// ours; the string literals are not.
const (
	TrailerAgentIdentity = "Agent-Identity"
	TrailerAgentRun      = "Agent-Run"
	TrailerAgentTask     = "Agent-Task"
)

// coAuthoredBy is the trailer key this package never emits and never carries
// through. It is not a protected surface — it is git's and GitHub's, named
// here so the refusal can be spelled once.
//
// I6 says "Never emit Co-authored-by: with a resolvable account". This package
// reads that as never emitting one at all, because whether an account is
// resolvable is a fact about GitHub's user table at some future moment, which
// nothing here can observe. ADR-0028 records the reasoning.
const coAuthoredBy = "Co-authored-by"

// protectedKeys is the set a caller's message may not already contain. A
// second Agent-Identity line would leave a verifier choosing which of two
// claims the certificate is supposed to match (IP §6.9, trailer spoofing).
var protectedKeys = [...]string{TrailerAgentIdentity, TrailerAgentRun, TrailerAgentTask}

// MaxAuthorEmailBytes is RFC 5321 §4.5.3.1.3's cap on a forward path.
const MaxAuthorEmailBytes = 254

// commentPrefix is git's default core.commentChar. A message whose last line
// starts with it is refused rather than placed around: git's trailer parser
// skips trailing comment lines, so trailers appended after one are trailers
// git will not find. See ADR-0028 for the residual when core.commentChar has
// been changed.
const commentPrefix = "#"

// Errors. Every one of them is a refusal of a malformed or forbidden request,
// so none carries an IP §4 error class: internal/mcp.Classify renders an error
// it cannot name as INVARIANT_VIOLATION, not retryable, which is exactly the
// class ADR-0018 chose for this shape of failure. A signing.Class would put
// the protected error vocabulary in a third package to say what the documented
// fallback already says.
var (
	// ErrAuthorNotAdmitted is the I6 author gate refusing. It blocks the
	// commit: CommitMessage returns no message at all alongside it.
	ErrAuthorNotAdmitted = errors.New("commit author is not admitted by the author policy (I6)")

	// ErrCoAuthorship is a co-authorship trailer found in a caller's message.
	ErrCoAuthorship = errors.New("the message carries a co-authorship trailer, which I6 admits from no source")

	// ErrClaim is a claim whose three trailers do not agree with each other.
	ErrClaim = errors.New("invalid claim")

	// ErrMessage is a commit message this package will not place trailers in.
	ErrMessage = errors.New("invalid commit message")

	// ErrTrailerAlreadyPresent is a caller's message that already spells one
	// of the three protected keys.
	ErrTrailerAlreadyPresent = errors.New("the message already carries a protected trailer key")
)

// Trailer is one rendered `Key: value` line.
type Trailer struct {
	Key   string
	Value string
}

// String renders the trailer as git writes it: key, colon, one space, value.
func (t Trailer) String() string { return t.Key + ": " + t.Value }

// Claim is what a commit's trailers assert about the run that produced it. It
// is asserted, never established; see the package comment.
type Claim struct {
	// Identity is the run's SPIFFE ID, doc 02 §5's grammar. It becomes the
	// Agent-Identity trailer and is the value check 3 compares against the
	// Fulcio certificate.
	Identity string
	// Run is the run id. It becomes the Agent-Run trailer and must be the run
	// segment of Identity.
	Run string
	// Task is the caller's task reference, verbatim, as `sign_commit` was
	// given it (IP §4). It becomes the Agent-Task trailer and must lowercase
	// to the task segment of Identity (ADR-0018 §6).
	Task string
}

// Trailers returns the three trailers of the claim, in the order IP §1 lists
// them, or refuses the claim. It renders; it does not check the claim against
// SPIRE, the ledger or a certificate, none of which it can see.
func (c Claim) Trailers() ([]Trailer, error) {
	if err := event.ValidateSPIFFEID(c.Identity); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrClaim, TrailerAgentIdentity, err)
	}
	taskID, runID := agentPathOf(c.Identity)
	if c.Run != runID {
		return nil, fmt.Errorf("%w: %s is %q but %s names the run %q",
			ErrClaim, TrailerAgentRun, c.Run, TrailerAgentIdentity, runID)
	}
	if strings.ToLower(c.Task) != taskID {
		return nil, fmt.Errorf("%w: %s is %q, which does not lowercase to the task %q in %s",
			ErrClaim, TrailerAgentTask, c.Task, taskID, TrailerAgentIdentity)
	}
	return []Trailer{
		{Key: TrailerAgentIdentity, Value: c.Identity},
		{Key: TrailerAgentRun, Value: c.Run},
		{Key: TrailerAgentTask, Value: c.Task},
	}, nil
}

// agentPathOf returns the task and run segments of a SPIFFE ID that has
// already passed event.ValidateSPIFFEID, which guarantees the five parts.
func agentPathOf(id string) (taskID, runID string) {
	parts := strings.Split(strings.TrimPrefix(id, "spiffe://"), "/")
	return parts[3], parts[4]
}

// Commit is the message-and-author pair a run is about to create a commit
// from, together with what its trailers will claim.
type Commit struct {
	// Message is the caller's commit message, `sign_commit`'s `message`
	// argument (IP §4), before trailers.
	Message string
	// AuthorEmail is the email the commit object will be authored with. It is
	// what I6 constrains and what AuthorPolicy gates.
	AuthorEmail string
	// Claim is what the trailers will say.
	Claim Claim
}

// AuthorPolicy is the I6 gate on the commit author:
//
//	Commit author is the human operator or a deliberately unlinked address;
//	agent identity lives only in trailers + signature.
//
// It is an allowlist, and its zero value admits nothing. A guard that has not
// been configured blocks every commit rather than waving every commit through:
// I6 is the one invariant with no cryptographic backstop — a contributor that
// should not exist is detected only by GH-001's empirical test against a real
// GitHub repository, long after the commit was pushed.
type AuthorPolicy struct {
	// Operators are the exact addresses this deployment attributes commits
	// to — the human operator's, in whatever form that operator uses,
	// including a GitHub `@users.noreply.github.com` address. Membership is
	// something only the operator can state, so it is enumerated rather than
	// matched by pattern.
	Operators []string

	// AllowUnlinked admits an address that CANNOT be attached to any GitHub
	// account, because its domain is one of the names RFC 2606 §2 and
	// RFC 6761 reserve and guarantee will never be delegated in the public
	// DNS: the .invalid, .example, .test and .localhost top-level names, and
	// the example.com / example.net / example.org second-level names. No
	// mailbox in them can receive a verification message, so no account can
	// ever hold one as a verified email, so no commit authored by one can
	// ever produce a contributor.
	//
	// This is why a `@users.noreply.github.com` address is NOT admitted here:
	// that form is precisely how GitHub attaches a commit to an account. It
	// is admissible as an operator, by being listed, never as "unlinked".
	AllowUnlinked bool
}

var (
	// localPattern is RFC 5322's dot-atom: the unquoted local part. Quoted
	// and comment forms are refused — they can contain the characters that
	// break a commit object's `Name <email>` author line.
	localPattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")

	// domainPattern is a dotted host name, at least two labels. A single
	// label has no registrable domain to reason about, so it cannot be shown
	// to be unlinked and cannot be told apart from a local alias.
	domainPattern = regexp.MustCompile(
		`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
)

// reservedTLDs are the top-level names RFC 2606 §2 / RFC 6761 reserve.
var reservedTLDs = [...]string{"invalid", "example", "test", "localhost"}

// reservedDomains are the second-level names the same RFCs reserve.
var reservedDomains = [...]string{"example.com", "example.net", "example.org"}

// CheckAuthor reports whether the policy admits email as a commit author, and
// refuses with ErrAuthorNotAdmitted if it does not. It is exported so the
// repo-level CI gate IP §6.9 requires can ask the same question this package
// asks at signing time, rather than a second question shaped like it.
func (p AuthorPolicy) CheckAuthor(email string) error {
	local, domain, err := splitAddress(email)
	if err != nil {
		return err
	}
	for _, op := range p.Operators {
		opLocal, opDomain, opErr := splitAddress(op)
		if opErr != nil {
			// A policy that cannot be read is a policy that admits nothing.
			// Skipping the entry would turn a configuration typo into a
			// silently narrower allowlist.
			return fmt.Errorf("%w: the policy lists %q, which is not an address: %w",
				ErrAuthorNotAdmitted, op, opErr)
		}
		if local == opLocal && strings.EqualFold(domain, opDomain) {
			return nil
		}
	}
	if p.AllowUnlinked && isReservedDomain(domain) {
		return nil
	}
	return fmt.Errorf("%w: %q is neither a listed operator nor an address in a reserved domain",
		ErrAuthorNotAdmitted, email)
}

// splitAddress parses an author email into its local and domain parts.
//
// The grammar is narrower than RFC 5322 on purpose. The address is written
// into a commit object's author line as `Name <email>`, so an address carrying
// an angle bracket, a comma or a newline can forge a second identity in a
// field the signature then covers. Refusing them is the fail-closed direction:
// a legitimate address that this refuses is a loud failure, an illegitimate
// one it admits is a permanent record.
func splitAddress(email string) (local, domain string, err error) {
	bad := func(why string) (string, string, error) {
		return "", "", fmt.Errorf("%w: %q %s", ErrAuthorNotAdmitted, email, why)
	}
	if email == "" {
		return bad("is empty")
	}
	if len(email) > MaxAuthorEmailBytes {
		return bad(fmt.Sprintf("is %d bytes, over the %d-byte cap of RFC 5321 §4.5.3.1.3",
			len(email), MaxAuthorEmailBytes))
	}
	at := strings.IndexByte(email, '@')
	if at < 0 {
		return bad("has no @")
	}
	local, domain = email[:at], email[at+1:]
	if strings.ContainsRune(domain, '@') {
		return bad("has more than one @")
	}
	if !localPattern.MatchString(local) {
		return bad("has a local part outside the unquoted dot-atom grammar")
	}
	if !domainPattern.MatchString(domain) {
		return bad("has a domain that is not a dotted host name")
	}
	return local, domain, nil
}

// isReservedDomain reports whether domain is one of the names RFC 2606 §2 and
// RFC 6761 reserve, or a subdomain of one. Comparison is case-folded: DNS
// labels are case-insensitive (RFC 1035 §2.3.3).
func isReservedDomain(domain string) bool {
	d := strings.ToLower(domain)
	// splitAddress has already required at least one dot, so the last label
	// exists. LastIndexByte returning -1 would still yield the whole string
	// rather than panic, so this is total either way.
	tld := d[strings.LastIndexByte(d, '.')+1:]
	for _, r := range reservedTLDs {
		if tld == r {
			return true
		}
	}
	for _, r := range reservedDomains {
		if d == r || strings.HasSuffix(d, "."+r) {
			return true
		}
	}
	return false
}

// CommitMessage returns the message a signed commit will carry: the caller's
// message with the claim's three trailers placed in its trailer block.
//
// The author gate runs first and blocks: an author I6 does not admit yields
// ErrAuthorNotAdmitted and an empty string, so a caller that ignores the error
// still has nothing to hand to gitsign. Every other refusal behaves the same
// way — this function never returns a message and an error together.
func CommitMessage(p AuthorPolicy, c Commit) (string, error) {
	if err := p.CheckAuthor(c.AuthorEmail); err != nil {
		return "", err
	}
	trailers, err := c.Claim.Trailers()
	if err != nil {
		return "", err
	}
	body, join, err := prepareMessage(c.Message)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(body)
	if !join {
		// The trailer block opens its own paragraph. Git only reads a group
		// of lines as trailers when a blank line precedes it.
		b.WriteString("\n")
	}
	for _, t := range trailers {
		b.WriteString(t.String())
		b.WriteString("\n")
	}
	return b.String(), nil
}

// normalizeMessage strips leading blank lines and trailing whitespace and
// terminates the message with exactly one newline — the part of
// `git commit --cleanup` that changes where a trailer block lands. An empty
// result means the message had no content.
//
// Rendering is a pure function of the NORMALIZED message. That is what makes
// the bytes that get signed independent of how many newlines a caller happened
// to send, and it is the message the SIG-006 differential compares git
// against.
func normalizeMessage(message string) string {
	m := strings.TrimLeft(strings.TrimRight(message, " \t\n"), "\n")
	if m == "" {
		return ""
	}
	return m + "\n"
}

// prepareMessage validates a caller's message and decides where the trailers
// go. It returns the normalized message, and whether the trailers join the
// message's existing last paragraph (join) or open a new one.
//
// Placement follows git's rule for the two cases it is unambiguous in, and
// refuses the rest. See ADR-0028.
func prepareMessage(message string) (body string, join bool, err error) {
	fail := func(base error, format string, args ...any) (string, bool, error) {
		return "", false, fmt.Errorf("%w: %s", base, fmt.Sprintf(format, args...))
	}
	if i := indexControlByte(message); i >= 0 {
		return fail(ErrMessage, "byte %d is the control character %q; a commit message is lines of text",
			i, message[i])
	}
	norm := normalizeMessage(message)
	if norm == "" {
		return fail(ErrMessage, "the message is empty")
	}

	lines := strings.Split(strings.TrimSuffix(norm, "\n"), "\n")
	for i, line := range lines {
		if isDivider(line) {
			return fail(ErrMessage, "line %d is a --- divider; git reads everything after "+
				"the first one as a patch, so trailers placed past it are trailers git will not find", i+1)
		}
		if hasTrailerToken(line, coAuthoredBy) {
			return fail(ErrCoAuthorship, "line %d is a %s trailer", i+1, coAuthoredBy)
		}
		for _, key := range protectedKeys {
			if hasTrailerToken(line, key) {
				return fail(ErrTrailerAlreadyPresent, "line %d already spells %s; "+
					"a second claim is what a verifier cannot resolve (IP §6.9)", i+1, key)
			}
		}
	}
	if strings.HasPrefix(lines[len(lines)-1], commentPrefix) {
		return fail(ErrMessage, "the message ends in a %s comment line; git's trailer parser "+
			"skips trailing comments, so trailers placed after one are trailers git will not find",
			commentPrefix)
	}

	// The last paragraph is everything after the last blank line. If there is
	// no blank line the whole message is one paragraph, and git never reads
	// that as a trailer block — a trailer block must be preceded by at least
	// one blank line.
	start := 0
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			start = i + 1
			break
		}
	}
	last := lines[start:]
	trailerLines := 0
	for _, line := range last {
		if isTrailerLine(line) {
			trailerLines++
		}
	}
	switch {
	case trailerLines == 0:
		// Pure prose. Git reads no trailer block here either, so it opens one.
		return norm, false, nil
	case trailerLines == len(last) && start > 0:
		// An existing trailer block. Git appends into it, and so do we; a
		// blank line here would push the caller's own trailers out of the
		// last paragraph and out of `git log --format=%(trailers)`.
		return norm, true, nil
	case trailerLines == len(last):
		// Trailer-shaped, but it is the whole message: the subject line is
		// never part of a trailer block.
		return norm, false, nil
	default:
		return fail(ErrMessage, "the last paragraph mixes %d trailer line(s) with %d other line(s); "+
			"which of them git reads as a trailer block depends on a 25%% heuristic and on "+
			"trailer.* configuration this package does not read (ADR-0028). Put the trailers in "+
			"their own paragraph", trailerLines, len(last)-trailerLines)
	}
}

// indexControlByte returns the index of the first byte a commit message may
// not contain, or -1. Tab and newline are text; every other C0 control and DEL
// is not. A carriage return in particular would land inside a trailer's value
// and change what a parser reads back.
func indexControlByte(s string) int {
	for i := range len(s) {
		if b := s[i]; (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
			return i
		}
	}
	return -1
}

// isDivider reports whether the line is git's patch divider: "---" alone, or
// "---" followed by a space.
func isDivider(line string) bool {
	return line == "---" || strings.HasPrefix(line, "--- ")
}

// isTrailerLine reports whether the line is one this package is willing to
// call a trailer: a token of ASCII alphanumerics and hyphens, then a colon,
// with no whitespace between them.
//
// This is deliberately NARROWER than git's parser, which also accepts
// whitespace before the separator. The asymmetry is the safe one. Calling a
// line prose that git calls a trailer costs at most a blank line, after which
// our three trailers are still the last paragraph and still all-trailers, so
// git still finds them. Calling a line a trailer that git calls prose would
// merge our claim into a paragraph git reads as prose, and a trailer git
// cannot find is a claim nothing can check.
func isTrailerLine(line string) bool {
	i := 0
	for i < len(line) && isTokenByte(line[i]) {
		i++
	}
	return i > 0 && i < len(line) && line[i] == ':'
}

func isTokenByte(b byte) bool {
	return b == '-' ||
		(b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

// hasTrailerToken reports whether the line begins with the given trailer key,
// compared the way git and GitHub compare one: case-insensitively, with
// optional whitespace before the separator.
//
// This match is deliberately WIDER than isTrailerLine, and for the opposite
// reason: it is used only to refuse. Every spelling that any parser might read
// as the key must be caught, so the refusal cannot be stepped around with a
// tab or a capital letter.
func hasTrailerToken(line, key string) bool {
	if len(line) < len(key) || !strings.EqualFold(line[:len(key)], key) {
		return false
	}
	return strings.HasPrefix(strings.TrimLeft(line[len(key):], " \t"), ":")
}
