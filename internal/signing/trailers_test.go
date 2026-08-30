// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Test catalog IDs driven from this file:
//
//	SIG-006 | U | Trailer writer output   | Agent-Identity, Agent-Run, Agent-Task
//	                                        exactly; no Co-authored-by ever emitted
//	SIG-007 | U | Author identity guard   | author email matches the configured
//	                                        human/unlinked pattern; violation
//	                                        blocks the commit
//
// The reference claim used throughout. It is golden fixture 01's identity
// (doc 02 §6): task_ref "JIRA-118" against
// spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42.
var refClaim = Claim{
	Identity: "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
	Run:      "run-42",
	Task:     "JIRA-118",
}

const operator = "operator@example.com"

// refPolicy admits exactly one address, the human operator's.
var refPolicy = AuthorPolicy{Operators: []string{operator}}

// ---------------------------------------------------------------------------
// SIG-006
// ---------------------------------------------------------------------------

func TestSIG006TrailerWriterEmitsTheThreeProtectedKeysAndNeverACoAuthoredBy(t *testing.T) {
	// A real commit message, and one that already ends in a trailer-shaped
	// line — the case where git appends into the existing block instead of
	// opening a new one.
	const plainBody = `fix(ledger): reject an event over the size cap

The 4 KB hard cap is measured against the canonical preimage, not the
stored record.`

	const endsInTrailer = `fix(ledger): reject an event over the size cap

The 4 KB hard cap is measured against the canonical preimage, not the
stored record.

Refs: RM-031
Signed-off-by: A U Thor <thor@example.com>`

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "message whose last paragraph is prose: the trailers open their own block",
			in:   plainBody,
			want: plainBody + "\n" + `
Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42
Agent-Run: run-42
Agent-Task: JIRA-118
`,
		},
		{
			name: "message that already ends in a trailer-shaped line: the trailers join that block",
			in:   endsInTrailer,
			want: endsInTrailer + "\n" + `Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42
Agent-Run: run-42
Agent-Task: JIRA-118
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CommitMessage(refPolicy, Commit{
				Message:     tc.in,
				AuthorEmail: operator,
				Claim:       refClaim,
			})
			if err != nil {
				t.Fatalf("CommitMessage: %v", err)
			}

			// 1. The three protected trailers are PRESENT and correct. This
			//    assertion comes first on purpose: the Co-authored-by check
			//    below passes trivially against an empty output, so the
			//    positive claim has to be established before the negative one
			//    means anything.
			if got != tc.want {
				t.Fatalf("CommitMessage output\n--- got ---\n%s\n--- want ---\n%s", got, tc.want)
			}
			for _, want := range []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			} {
				if !hasLine(got, want) {
					t.Errorf("rendered message has no line %q", want)
				}
			}

			// 2. Only now is the absence of Co-authored-by worth asserting.
			if line, ok := coAuthoredByLine(got); ok {
				t.Errorf("rendered message emitted a co-authorship trailer: %q", line)
			}
		})
	}
}

// TestSIG006TheCoAuthoredByScannerBites is the anti-vacuity control for the
// negative half of SIG-006. The assertion "no Co-authored-by was emitted"
// passes against any output at all — including an empty one — unless the
// scanner that makes it is known to fire when one IS present. This test is
// what makes the SIG-006 assertion evidence rather than decoration.
func TestSIG006TheCoAuthoredByScannerBites(t *testing.T) {
	planted := []string{
		"Co-authored-by: Someone <someone@example.com>",
		"co-authored-by: someone <someone@example.com>",
		"CO-AUTHORED-BY: SOMEONE <someone@example.com>",
		"Co-Authored-By: agent <agent@users.noreply.github.com>",
		"Co-authored-by:agent <agent@example.com>",
		"Co-authored-by \t: agent <agent@example.com>",
	}
	for _, p := range planted {
		msg := "subject\n\nbody\n\nRefs: RM-031\n" + p + "\n"
		line, ok := coAuthoredByLine(msg)
		if !ok {
			t.Errorf("the scanner did not fire on a planted %q — the SIG-006 negative assertion is vacuous", p)
			continue
		}
		if line != p {
			t.Errorf("scanner reported %q, want the planted line %q", line, p)
		}
	}
	// And it does not fire on prose that merely mentions the words.
	if line, ok := coAuthoredByLine("subject\n\nDo not use Co-authored-by: here, ever.\n"); ok {
		t.Errorf("the scanner fired on prose: %q", line)
	}
}

// TestSIG006ACoAuthorshipTrailerInTheCallerMessageIsRefused closes the other
// half of "no code path emits it": the writer's own lines are not the only way
// a co-authorship trailer could reach a signed commit. I6 admits none, from
// any source, so a message that carries one is refused rather than carried
// through or silently stripped.
func TestSIG006ACoAuthorshipTrailerInTheCallerMessageIsRefused(t *testing.T) {
	bodies := []string{
		"subject\n\nCo-authored-by: Someone <someone@example.com>\n",
		"subject\n\nbody\n\nCo-Authored-By: Someone <someone@example.com>\n",
		"subject\n\nco-authored-by: someone <someone@example.com>\n\nmore body\n",
		"Co-authored-by: Someone <someone@example.com>\n",
	}
	for _, body := range bodies {
		got, err := CommitMessage(refPolicy, Commit{
			Message:     body,
			AuthorEmail: operator,
			Claim:       refClaim,
		})
		if !errors.Is(err, ErrCoAuthorship) {
			t.Errorf("CommitMessage(%q) error = %v, want ErrCoAuthorship", body, err)
		}
		if got != "" {
			t.Errorf("CommitMessage(%q) returned a message %q alongside its refusal", body, got)
		}
	}
}

// TestSIG006GitParsesTheThreeTrailersOutOfTheRenderedMessage is the
// differential half of ADR-0028: this package places trailers itself rather
// than shelling out, so `git interpret-trailers` is the oracle the placement
// is pinned against, in CI, on every accepted input.
func TestSIG006GitParsesTheThreeTrailersOutOfTheRenderedMessage(t *testing.T) {
	git := gitOrSkip(t)

	cases := []struct {
		name string
		in   string
		// wantParsed is what `git interpret-trailers --parse --only-trailers`
		// must report for the rendered message, in order.
		wantParsed []string
	}{
		{
			name: "prose body",
			in:   "subject line\n\nbody paragraph.\n",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "subject only",
			in:   "subject line",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "already ends in a trailer block",
			in:   "subject line\n\nbody.\n\nRefs: RM-031\nSigned-off-by: A U Thor <thor@example.com>\n",
			wantParsed: []string{
				"Refs: RM-031",
				"Signed-off-by: A U Thor <thor@example.com>",
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "subject that is itself trailer-shaped is not a trailer block",
			in:   "Fix: the thing\n",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "last paragraph is all trailers, none of them git-generated",
			in:   "subject line\n\nbody.\n\nRefs: RM-031\nBug: 99\n",
			wantParsed: []string{
				"Refs: RM-031",
				"Bug: 99",
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "trailing blank lines are normalized away before the block opens",
			in:   "subject line\n\nbody.\n\n\n\n",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "the whole message is one trailer-shaped paragraph",
			in:   "Refs: RM-031\nBug: 99\n",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
		{
			name: "leading blank lines are normalized away",
			in:   "\n\nsubject line\n\nbody.\n",
			wantParsed: []string{
				"Agent-Identity: spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
				"Agent-Run: run-42",
				"Agent-Task: JIRA-118",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CommitMessage(refPolicy, Commit{
				Message:     tc.in,
				AuthorEmail: operator,
				Claim:       refClaim,
			})
			if err != nil {
				t.Fatalf("CommitMessage: %v", err)
			}

			// (a) git's own parser sees all three trailers, in order, in the
			//     rendered message. This is the property that matters: a
			//     trailer git cannot find is a claim nothing can check.
			parsed := gitParseTrailers(t, git, got)
			if len(parsed) != len(tc.wantParsed) {
				t.Fatalf("git parsed %d trailers %q, want %d %q",
					len(parsed), parsed, len(tc.wantParsed), tc.wantParsed)
			}
			for i := range parsed {
				if parsed[i] != tc.wantParsed[i] {
					t.Errorf("git trailer %d = %q, want %q", i, parsed[i], tc.wantParsed[i])
				}
			}

			// (b) byte equality with what git itself would have produced for
			//     the same three trailers on the normalized message.
			viaGit := gitInterpretTrailers(t, git, normalizeMessage(tc.in),
				"Agent-Identity: "+refClaim.Identity,
				"Agent-Run: "+refClaim.Run,
				"Agent-Task: "+refClaim.Task)
			if got != viaGit {
				t.Errorf("placement differs from git interpret-trailers\n--- ours ---\n%s\n--- git ---\n%s", got, viaGit)
			}
		})
	}
}

// TestSIG006NoAcceptedInputEverYieldsACoAuthorshipTrailer is the property form
// of SIG-006's negative half: over generated messages, every output this
// package accepts carries the three trailers and none carries a co-authorship
// trailer. A refusal is a pass; a silently mangled acceptance is not.
func TestSIG006NoAcceptedInputEverYieldsACoAuthorshipTrailer(t *testing.T) {
	fragments := []string{
		"subject", "body line", "", "Refs: RM-031", "Signed-off-by: A <a@example.com>",
		"Co-authored-by: X <x@example.com>", "co-authored-by:X <x@example.com>",
		"# heading", "---", "  continued", "Agent-Run: forged",
		"Agent-Identity: spiffe://evil/agent/a/b/c", "\ttabbed", "Fix: it", "trailing ",
	}
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(rt, "lines")
		lines := make([]string, n)
		for i := range lines {
			lines[i] = rapid.SampledFrom(fragments).Draw(rt, "line")
		}
		msg := strings.Join(lines, "\n")

		got, err := CommitMessage(refPolicy, Commit{
			Message:     msg,
			AuthorEmail: operator,
			Claim:       refClaim,
		})
		if err != nil {
			if got != "" {
				rt.Fatalf("refused %q but still returned a message %q", msg, got)
			}
			return
		}
		for _, want := range []string{
			"Agent-Identity: " + refClaim.Identity,
			"Agent-Run: " + refClaim.Run,
			"Agent-Task: " + refClaim.Task,
		} {
			if !hasLine(got, want) {
				rt.Fatalf("accepted %q but the output has no line %q:\n%s", msg, want, got)
			}
		}
		if line, ok := coAuthoredByLine(got); ok {
			rt.Fatalf("accepted %q and emitted a co-authorship trailer %q", msg, line)
		}
	})
}

// TestSIG006TheProtectedTrailerKeysAreSpelledExactly pins the three protected
// strings (VERSIONING.md surface 2, doc 08 §3) as literals, so a rename is a
// failing test here as well as a failing scripts/protected-surfaces.sh.
func TestSIG006TheProtectedTrailerKeysAreSpelledExactly(t *testing.T) {
	if TrailerAgentIdentity != "Agent-Identity" {
		t.Errorf("TrailerAgentIdentity = %q, want %q — PROTECTED STRING", TrailerAgentIdentity, "Agent-Identity")
	}
	if TrailerAgentRun != "Agent-Run" {
		t.Errorf("TrailerAgentRun = %q, want %q — PROTECTED STRING", TrailerAgentRun, "Agent-Run")
	}
	if TrailerAgentTask != "Agent-Task" {
		t.Errorf("TrailerAgentTask = %q, want %q — PROTECTED STRING", TrailerAgentTask, "Agent-Task")
	}
	got, err := refClaim.Trailers()
	if err != nil {
		t.Fatalf("Claim.Trailers: %v", err)
	}
	want := []Trailer{
		{Key: "Agent-Identity", Value: "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"},
		{Key: "Agent-Run", Value: "run-42"},
		{Key: "Agent-Task", Value: "JIRA-118"},
	}
	if len(got) != 3 {
		t.Fatalf("Claim.Trailers returned %d trailers %v, want exactly 3", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("trailer %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// SIG-007
// ---------------------------------------------------------------------------

func TestSIG007AuthorIdentityGuardBlocksACommitWhoseAuthorI6Forbids(t *testing.T) {
	humanOnly := AuthorPolicy{Operators: []string{"operator@example.com", "Mike@Corp.Example"}}
	unlinked := AuthorPolicy{AllowUnlinked: true}
	both := AuthorPolicy{Operators: []string{"operator@example.com"}, AllowUnlinked: true}

	cases := []struct {
		name   string
		policy AuthorPolicy
		email  string
		admit  bool
	}{
		// The zero value admits nothing. A guard that has not been configured
		// is a guard that blocks, not one that waves everything through.
		{"zero-value policy admits nothing", AuthorPolicy{}, "operator@example.com", false},
		{"zero-value policy admits no unlinked address either", AuthorPolicy{}, "agent@innsegl.invalid", false},

		// The human operator, listed exactly.
		{"the listed operator", humanOnly, "operator@example.com", true},
		{"an operator who is not listed", humanOnly, "someone-else@example.com", false},

		// Domains are compared case-folded (DNS is case-insensitive); local
		// parts are not (RFC 5321 §2.3.11 leaves them to the receiving host,
		// so two spellings are not known to be one mailbox).
		{"listed operator, domain in a different case", humanOnly, "Mike@corp.example", true},
		{"listed operator, local part in a different case", humanOnly, "mike@Corp.Example", false},

		// "Unlinked" means an address that can never be verified by any
		// mailbox, hence can never be attached to a GitHub account: the
		// reserved names of RFC 2606 §2 / RFC 6761 §6.
		{"reserved TLD .invalid, unlinked allowed", unlinked, "agent@innsegl.invalid", true},
		{"reserved TLD .example, unlinked allowed", unlinked, "agent@innsegl.example", true},
		{"reserved TLD .test, unlinked allowed", unlinked, "agent@innsegl.test", true},
		{"reserved TLD .localhost, unlinked allowed", unlinked, "agent@innsegl.localhost", true},
		{"reserved second level example.com", unlinked, "agent@example.com", true},
		{"reserved second level example.net", unlinked, "agent@example.net", true},
		{"reserved second level example.org", unlinked, "agent@sub.example.org", true},
		{"reserved TLD, uppercase", unlinked, "agent@INNSEGL.INVALID", true},
		{"a real domain is not unlinked", unlinked, "agent@innsegl.dev", false},
		{"example.com.evil.dev is not example.com", unlinked, "agent@example.com.evil.dev", false},
		{"invalidation.dev is not .invalid", unlinked, "agent@invalidation.dev", false},

		// The one form that looks unlinked and is not: GitHub's noreply
		// address is precisely how GitHub attaches a commit to an account.
		// It is admissible only as a listed operator, never by the unlinked
		// rule — which is I6's whole point.
		{"github noreply is not unlinked", unlinked, "1234+alice@users.noreply.github.com", false},
		{"github noreply, bare form, is not unlinked", unlinked, "alice@users.noreply.github.com", false},
		{"github noreply admitted when listed as the operator",
			AuthorPolicy{Operators: []string{"1234+alice@users.noreply.github.com"}},
			"1234+alice@users.noreply.github.com", true},

		// Both rules together, and neither rule admitting.
		{"both rules: operator", both, "operator@example.com", true},
		{"both rules: unlinked", both, "agent@innsegl.invalid", true},
		{"both rules: neither", both, "agent@innsegl.dev", false},

		// Shapes that are not an address at all. The author email lands
		// inside `Name <email>` in a commit object, so anything carrying an
		// angle bracket, a comma or a newline can forge a second identity.
		{"empty", both, "", false},
		{"no at sign", both, "operator", false},
		{"two at signs", both, "a@b@example.com", false},
		{"empty local part", both, "@example.com", false},
		{"empty domain", both, "operator@", false},
		{"leading space", both, " operator@example.com", false},
		{"trailing space", both, "operator@example.com ", false},
		{"embedded newline", both, "operator@example.com\nCo-authored-by: x <x@example.com>", false},
		{"angle bracket", both, "operator@example.com>", false},
		{"comma", both, "operator@example.com,agent@innsegl.invalid", false},
		{"NUL", both, "operator@example\x00.com", false},
		{"domain with no dot", both, "operator@localhost", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.CheckAuthor(tc.email)
			switch {
			case tc.admit && err != nil:
				t.Fatalf("CheckAuthor(%q) = %v, want admitted", tc.email, err)
			case !tc.admit && err == nil:
				t.Fatalf("CheckAuthor(%q) admitted an address I6 forbids", tc.email)
			}
			if !tc.admit && !errors.Is(err, ErrAuthorNotAdmitted) {
				t.Errorf("CheckAuthor(%q) error = %v, want ErrAuthorNotAdmitted", tc.email, err)
			}

			// The guard BLOCKS: a refused author yields no commit message at
			// all, so a caller that ignores the error still has nothing to
			// hand to gitsign.
			msg, mErr := CommitMessage(tc.policy, Commit{
				Message:     "subject\n\nbody.\n",
				AuthorEmail: tc.email,
				Claim:       refClaim,
			})
			if tc.admit {
				if mErr != nil {
					t.Fatalf("CommitMessage: %v", mErr)
				}
				if !hasLine(msg, "Agent-Identity: "+refClaim.Identity) {
					t.Errorf("admitted author produced no Agent-Identity trailer:\n%s", msg)
				}
				return
			}
			if mErr == nil {
				t.Fatalf("CommitMessage produced a message for a forbidden author %q:\n%s", tc.email, msg)
			}
			if msg != "" {
				t.Errorf("CommitMessage refused %q but still returned a message: %q", tc.email, msg)
			}
			if !errors.Is(mErr, ErrAuthorNotAdmitted) {
				t.Errorf("CommitMessage error = %v, want ErrAuthorNotAdmitted", mErr)
			}
		})
	}
}

// TestSIG007TheGuardRunsBeforeAnythingIsRendered pins the order: an author I6
// forbids is refused even when the rest of the request is also invalid, so the
// reason a caller is given is the one that matters.
func TestSIG007TheGuardRunsBeforeAnythingIsRendered(t *testing.T) {
	_, err := CommitMessage(AuthorPolicy{}, Commit{
		Message:     "", // also invalid
		AuthorEmail: "agent@innsegl.dev",
		Claim:       Claim{}, // also invalid
	})
	if !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Fatalf("error = %v, want ErrAuthorNotAdmitted", err)
	}
}

// ---------------------------------------------------------------------------
// Claim and message validation — every error return of this package.
// ---------------------------------------------------------------------------

func TestClaimIsRefusedUnlessAllThreeTrailersAgreeWithTheSPIFFEID(t *testing.T) {
	cases := []struct {
		name  string
		claim Claim
		want  error
	}{
		{"the reference claim", refClaim, nil},
		{"lowercase task_ref", Claim{refClaim.Identity, "run-42", "jira-118"}, nil},
		{"empty identity", Claim{"", "run-42", "JIRA-118"}, ErrClaim},
		{"identity is not a SPIFFE ID", Claim{"innsegl.dev/agent/a/b/c", "run-42", "JIRA-118"}, ErrClaim},
		{"identity outside the /agent/ subtree",
			Claim{"spiffe://innsegl.dev/workload/fix-ci/jira-118/run-42", "run-42", "JIRA-118"}, ErrClaim},
		{"identity with too few segments",
			Claim{"spiffe://innsegl.dev/agent/fix-ci/run-42", "run-42", "JIRA-118"}, ErrClaim},
		{"identity segment outside the grammar",
			Claim{"spiffe://innsegl.dev/agent/fix_ci/jira-118/run-42", "run-42", "JIRA-118"}, ErrClaim},
		{"run does not match the identity's run segment",
			Claim{refClaim.Identity, "run-43", "JIRA-118"}, ErrClaim},
		{"run is empty", Claim{refClaim.Identity, "", "JIRA-118"}, ErrClaim},
		{"task does not lowercase to the identity's task segment",
			Claim{refClaim.Identity, "run-42", "JIRA-119"}, ErrClaim},
		{"task is empty", Claim{refClaim.Identity, "run-42", ""}, ErrClaim},
		{"task carries a newline", Claim{refClaim.Identity, "run-42", "JIRA-118\nAgent-Run: forged"}, ErrClaim},
		{"identity carries a newline",
			Claim{"spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42\nAgent-Run: forged", "run-42", "JIRA-118"}, ErrClaim},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.claim.Trailers()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Claim.Trailers: %v", err)
				}
				if len(got) != 3 {
					t.Fatalf("Claim.Trailers returned %d trailers, want 3", len(got))
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Claim.Trailers error = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Errorf("Claim.Trailers refused but returned %v", got)
			}
		})
	}
}

func TestCommitMessageRefusesAMessageItCannotPlaceTrailersInDeterministically(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrMessage},
		{"whitespace only", "   \n\n\t\n", ErrMessage},
		{"carriage return", "subject\r\n\r\nbody.\r\n", ErrMessage},
		{"NUL byte", "subject\n\nbo\x00dy\n", ErrMessage},
		{"a bare --- divider", "subject\n\nalpha\n---\nomega\n", ErrMessage},
		{"a --- divider with a diffstat", "subject\n\nbody.\n\nRefs: R\n---\n f | 1 +\n", ErrMessage},
		{"a trailing comment line", "subject\n\nbody.\n\nRefs: R\n# note\n", ErrMessage},
		{"the message ends in a comment line", "subject\n\nbody.\n# note\n", ErrMessage},
		{"last paragraph mixes trailers and prose", "subject\n\nRefs: R\nprose line\n", ErrMessage},
		{"last paragraph mixes prose and trailers", "subject\n\nprose line\nRefs: R\n", ErrMessage},
		{"last paragraph has a folded continuation line", "subject\n\nbody.\n\nRefs: R\n  continued\n", ErrMessage},
		{"the message already claims Agent-Identity",
			"subject\n\nbody.\n\nAgent-Identity: spiffe://innsegl.dev/agent/a/b/c\n", ErrTrailerAlreadyPresent},
		{"the message already claims Agent-Run", "subject\n\nbody.\n\nAgent-Run: run-9\n", ErrTrailerAlreadyPresent},
		{"the message already claims Agent-Task", "subject\n\nbody.\n\nAgent-Task: T-9\n", ErrTrailerAlreadyPresent},
		{"the message claims one in a different case", "subject\n\nbody.\n\nagent-run: run-9\n", ErrTrailerAlreadyPresent},
		{"the message claims one in the body", "subject\n\nAgent-Run: run-9\n\nbody.\n", ErrTrailerAlreadyPresent},
		// A comment line that is not at the end is prose, exactly as git
		// treats it, and is accepted.
		{"a heading in the middle of a paragraph", "subject\n\n# heading\nprose\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CommitMessage(refPolicy, Commit{
				Message:     tc.in,
				AuthorEmail: operator,
				Claim:       refClaim,
			})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CommitMessage: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("CommitMessage(%q) error = %v, want %v", tc.in, err, tc.want)
			}
			if got != "" {
				t.Errorf("CommitMessage refused but returned %q", got)
			}
		})
	}
}

func TestCommitMessageIsIdempotentUnderNormalization(t *testing.T) {
	// Rendering is a pure function of the normalized message: trailing
	// whitespace and blank lines cannot change the bytes that get signed.
	base := "subject\n\nbody."
	variants := []string{base, base + "\n", base + "\n\n\n", base + "   \n\n", base + "\t\n",
		"\n" + base, "\n\n\n" + base + "\n\n"}
	var first string
	for i, v := range variants {
		got, err := CommitMessage(refPolicy, Commit{Message: v, AuthorEmail: operator, Claim: refClaim})
		if err != nil {
			t.Fatalf("CommitMessage(%q): %v", v, err)
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Errorf("CommitMessage(%q) =\n%s\nwant the same bytes as CommitMessage(%q) =\n%s", v, got, base, first)
		}
	}
	if !strings.HasSuffix(first, "Agent-Task: JIRA-118\n") {
		t.Errorf("rendered message does not end in the last trailer plus one newline:\n%q", first)
	}
}

func TestTrailerStringIsKeyColonSpaceValue(t *testing.T) {
	got := Trailer{Key: TrailerAgentRun, Value: "run-42"}.String()
	if got != "Agent-Run: run-42" {
		t.Errorf("Trailer.String() = %q, want %q", got, "Agent-Run: run-42")
	}
}

// TestCheckAuthorRefusesAPolicyItCannotRead pins the fail-closed reading of a
// misconfigured allowlist: an entry that is not an address is not skipped
// (which would silently narrow the allowlist and hide the typo), it refuses.
func TestCheckAuthorRefusesAPolicyItCannotRead(t *testing.T) {
	p := AuthorPolicy{Operators: []string{"not-an-address"}, AllowUnlinked: true}
	// Even an address the unlinked rule would have admitted is refused, because
	// the policy is unreadable before the question is reached.
	err := p.CheckAuthor("agent@innsegl.invalid")
	if !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Fatalf("CheckAuthor = %v, want ErrAuthorNotAdmitted", err)
	}
	if !strings.Contains(err.Error(), "not-an-address") {
		t.Errorf("the refusal does not name the unreadable entry: %v", err)
	}
}

func TestCheckAuthorRefusesAnAddressOverTheRFC5321Cap(t *testing.T) {
	long := strings.Repeat("a", MaxAuthorEmailBytes) + "@innsegl.invalid"
	err := AuthorPolicy{AllowUnlinked: true}.CheckAuthor(long)
	if !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Fatalf("CheckAuthor = %v, want ErrAuthorNotAdmitted", err)
	}
	// One byte under the cap, in a reserved domain, is admitted — so the cap
	// is what refused the address above, not the grammar.
	ok := strings.Repeat("a", MaxAuthorEmailBytes-len("@innsegl.invalid")) + "@innsegl.invalid"
	if len(ok) != MaxAuthorEmailBytes {
		t.Fatalf("test setup: control address is %d bytes, want %d", len(ok), MaxAuthorEmailBytes)
	}
	if err := (AuthorPolicy{AllowUnlinked: true}).CheckAuthor(ok); err != nil {
		t.Fatalf("CheckAuthor(%d-byte address) = %v, want admitted", len(ok), err)
	}
}

// TestCommitMessageRefusesABadClaimAfterAdmittingTheAuthor covers the second
// gate: an admitted author does not make an incoherent claim renderable.
func TestCommitMessageRefusesABadClaimAfterAdmittingTheAuthor(t *testing.T) {
	got, err := CommitMessage(refPolicy, Commit{
		Message:     "subject\n\nbody.\n",
		AuthorEmail: operator,
		Claim:       Claim{Identity: refClaim.Identity, Run: "run-43", Task: refClaim.Task},
	})
	if !errors.Is(err, ErrClaim) {
		t.Fatalf("CommitMessage error = %v, want ErrClaim", err)
	}
	if got != "" {
		t.Errorf("CommitMessage refused but returned %q", got)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// hasLine reports whether the message contains want as a whole line.
func hasLine(message, want string) bool {
	for _, line := range strings.Split(message, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

// coAuthoredByLine reports the first line of message that GitHub would read as
// a co-authorship trailer, and whether one was found. The match is on the
// token at the start of a line, case-insensitively, with optional whitespace
// before the separator — which is what git's trailer parser accepts and what
// GitHub's attribution reads.
//
// Its own sensitivity is under test: see
// TestSIG006TheCoAuthoredByScannerBites.
func coAuthoredByLine(message string) (string, bool) {
	for _, line := range strings.Split(message, "\n") {
		rest, ok := cutPrefixFold(line, "co-authored-by")
		if !ok {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(rest, " \t"), ":") {
			return line, true
		}
	}
	return "", false
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// gitOrSkip locates the reference implementation. `git interpret-trailers` is
// the oracle for placement (ADR-0028); without it the differential half of
// SIG-006 cannot run and says so rather than passing quietly.
func gitOrSkip(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("skipping: no git on PATH (%v). `git interpret-trailers` is the oracle this "+
			"package's trailer placement is pinned against (ADR-0028); without it the placement "+
			"is asserted only against this file's own expectations", err)
	}
	return git
}

// gitEnv runs git with no system, global or repository configuration in scope.
// The `trailer.*` configuration keys can rewrite a trailer token, its
// separator and its placement — so a git invocation that reads them is not a
// fixed oracle. Neutering them is what makes the comparison meaningful.
func gitEnv(t *testing.T, git string, stdin string, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	// A repository discovered above the temp directory would contribute its
	// own config; the ceiling stops the search.
	// G204 is not a concern: git comes from LookPath and every argument is a
	// literal in this file.
	cmd := exec.CommandContext(t.Context(), git, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(dir, "nonexistent-gitconfig"),
		"GIT_CEILING_DIRECTORIES=" + dir,
		"HOME=" + dir,
	}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v", git, strings.Join(args, " "), err)
	}
	return string(out)
}

func gitInterpretTrailers(t *testing.T, git, message string, trailers ...string) string {
	t.Helper()
	args := []string{"interpret-trailers"}
	for _, tr := range trailers {
		args = append(args, "--trailer", tr)
	}
	return gitEnv(t, git, message, args...)
}

func gitParseTrailers(t *testing.T, git, message string) []string {
	t.Helper()
	out := gitEnv(t, git, message, "interpret-trailers", "--parse", "--only-trailers")
	out = strings.TrimSuffix(out, "\n")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}
