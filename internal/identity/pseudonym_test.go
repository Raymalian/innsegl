// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// PRI-001 — the pseudonym is a pseudonym.
//
// Four properties, and each of them is load bearing for RM-079 (#116):
//
//  1. it satisfies doc 02 §5's identifier grammar, so nothing about the
//     PROTECTED SPIFFE ID grammar has to change to carry it;
//  2. the same input yields the same pseudonym, so a replayed register_agent
//     asks SPIRE for the identity that already exists;
//  3. a different deployment secret yields a different pseudonym, so two
//     deployments' public records cannot be joined on a task;
//  4. the fields are domain-separated, so an agent type and a task ref that
//     read the same do not collide into one pseudonym.
func TestPRI001ThePseudonymIsAPseudonym(t *testing.T) {
	const (
		secretA = "0123456789abcdef0123456789abcdef"
		secretB = "fedcba9876543210fedcba9876543210"
		value   = "jira-118"
	)

	a := newOrFatal(t, ModePseudonymous, secretA)
	b := newOrFatal(t, ModePseudonymous, secretB)

	task, err := a.TaskID(value)
	if err != nil {
		t.Fatalf("TaskID(%q): %v", value, err)
	}

	// (1) The grammar. This is what makes the change cheap: doc 02 §5 holds
	// the segment to [a-z0-9][a-z0-9-]{0,62} and a pseudonym satisfies it
	// exactly as well as a ticket number does.
	if verr := event.ValidateIdentifier(task); verr != nil {
		t.Errorf("the pseudonym %q is not a SPIFFE ID component: %v", task, verr)
	}
	if len(task) != PseudonymLen {
		t.Errorf("the pseudonym %q is %d characters, want %d", task, len(task), PseudonymLen)
	}
	// It must not simply be the value back again, or nothing has happened.
	if strings.Contains(task, value) {
		t.Errorf("the pseudonym %q still carries the task reference %q", task, value)
	}

	// (2) Determinism, within one deployment.
	again, err := a.TaskID(value)
	if err != nil {
		t.Fatalf("TaskID(%q) a second time: %v", value, err)
	}
	if again != task {
		t.Errorf("the same task pseudonymised to %q and then to %q; a replayed "+
			"register_agent would ask SPIRE for a second identity", task, again)
	}

	// (3) Different deployments, different pseudonyms.
	other, err := b.TaskID(value)
	if err != nil {
		t.Fatalf("TaskID(%q) under the second secret: %v", value, err)
	}
	if other == task {
		t.Errorf("two deployments pseudonymised %q to the same %q; their public "+
			"records can be joined on the task", value, task)
	}

	// (4) Domain separation between the two fields.
	asType, err := a.AgentType(value)
	if err != nil {
		t.Fatalf("AgentType(%q): %v", value, err)
	}
	if asType == task {
		t.Errorf("agent type %q and task ref %q both pseudonymised to %q; the "+
			"fields are not domain-separated", value, value, task)
	}
}

// PRI-002 — the modes, and what an absent secret does.
//
// `literal` must reproduce exactly what the system did before RM-079, because
// it is the escape hatch a deployment that wants the old behaviour takes, and
// an escape hatch that behaves differently is a second behaviour to test.
//
// `pseudonymous` with no secret REFUSES. Falling back to literal values would
// defeat the whole issue while looking like a considered default, which is a
// shape this project has been bitten by twice.
func TestPRI002ModesAndTheAbsentSecret(t *testing.T) {
	t.Run("literal is what the system did before", func(t *testing.T) {
		p := newOrFatal(t, ModeLiteral, "")
		if got, err := p.AgentType("fix-ci"); err != nil || got != "fix-ci" {
			t.Errorf("AgentType(%q) = %q, %v; literal mode passes the agent type through",
				"fix-ci", got, err)
		}
		// task_id is lowercased for the SPIFFE ID and kept verbatim for the
		// event — golden fixture 01's split.
		if got, err := p.TaskID("JIRA-118"); err != nil || got != "jira-118" {
			t.Errorf("TaskID(%q) = %q, %v; literal mode lowercases the task ref",
				"JIRA-118", got, err)
		}
	})

	t.Run("pseudonymous with no secret refuses", func(t *testing.T) {
		p, err := New(ModePseudonymous, "")
		if err == nil {
			t.Fatalf("New(%q, \"\") returned %+v and no error. An empty secret that "+
				"silently fell back to literal values would put the ticket reference "+
				"back in the certificate while the configuration said it was private.",
				ModePseudonymous, p)
		}
		if !strings.Contains(err.Error(), string(ModeLiteral)) {
			t.Errorf("the refusal does not name %q, so an operator is not told how to "+
				"ask for the old behaviour on purpose: %v", ModeLiteral, err)
		}
	})

	t.Run("pseudonymous with a short secret refuses", func(t *testing.T) {
		if _, err := New(ModePseudonymous, "hunter2"); err == nil {
			t.Errorf("New accepted a %d-byte secret. The pseudonym is 32 bits of a "+
				"keyed digest; against a guessable key an adversary holding one "+
				"(value, pseudonym) pair recovers the key offline and then every "+
				"other pseudonym.", len("hunter2"))
		}
	})

	t.Run("an unknown mode refuses", func(t *testing.T) {
		if _, err := New(Mode("anonymous"), "0123456789abcdef0123456789abcdef"); err == nil {
			t.Errorf("New accepted an unknown mode; a typo in the deployment's " +
				"configuration would be read as a mode this package does not implement")
		}
	})

	t.Run("literal with a secret refuses", func(t *testing.T) {
		if _, err := New(ModeLiteral, "0123456789abcdef0123456789abcdef"); err == nil {
			t.Errorf("New accepted a secret in literal mode. An operator who set a " +
				"secret asked for pseudonyms; silently ignoring it is the same " +
				"failure as silently ignoring its absence, in the other direction")
		}
	})
}

// PRI-002 — a value the SPIFFE ID grammar would not carry is refused rather
// than laundered.
//
// Pseudonymisation maps anything at all onto eight hex digits, so it WOULD
// carry a 4 KB task reference or one with a slash in it. It must not: the
// tool contract that MCP-001 pins refuses those inputs today, and a mode that
// quietly widened the contract would make `literal` and `pseudonymous` two
// different tools.
func TestPRI002TheGrammarIsCheckedBeforeItIsHidden(t *testing.T) {
	p := newOrFatal(t, ModePseudonymous, "0123456789abcdef0123456789abcdef")
	for _, bad := range []string{"", "../../etc", "JIRA/118", strings.Repeat("x", 64)} {
		if got, err := p.TaskID(bad); err == nil {
			t.Errorf("TaskID(%q) = %q with no error; pseudonymisation is not a way "+
				"to admit an input the tool contract refuses", bad, got)
		}
	}
	// The one exception is case: task_id is lowercased before it is checked,
	// exactly as register_agent lowercases it today.
	if _, err := p.TaskID("JIRA-118"); err != nil {
		t.Errorf("TaskID(%q): %v; the task ref is lowercased before it is checked", "JIRA-118", err)
	}
	// AgentType refuses the same shapes. It does NOT lowercase: doc 02 §5's
	// grammar has no upper case and register_agent held agent_type to it as
	// given before RM-079, so an upper-case agent type is a refusal in both
	// modes rather than a silently rewritten identity.
	for _, bad := range []string{"", "Fix-CI", "../../etc", strings.Repeat("x", 64)} {
		if got, err := p.AgentType(bad); err == nil {
			t.Errorf("AgentType(%q) = %q with no error; the grammar is checked before "+
				"the value is hidden", bad, got)
		}
	}

	// And the same reference in two casings is ONE task, not two identities.
	upper, err := p.TaskID("JIRA-118")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := p.TaskID("jira-118")
	if err != nil {
		t.Fatal(err)
	}
	if upper != lower {
		t.Errorf("%q pseudonymised to %q and %q to %q; one ticket has become two "+
			"identities", "JIRA-118", upper, "jira-118", lower)
	}
}

// PRI-002 — the mode is readable, so a wiring site can log which one is in
// force. A privacy control whose state nobody can see is one nobody can audit.
func TestPRI002TheModeIsReadable(t *testing.T) {
	for _, tc := range []struct {
		mode   Mode
		secret string
	}{
		{ModeLiteral, ""},
		{ModePseudonymous, "0123456789abcdef0123456789abcdef"},
	} {
		if got := newOrFatal(t, tc.mode, tc.secret).Mode(); got != tc.mode {
			t.Errorf("Mode() = %q, want %q", got, tc.mode)
		}
	}
}

func newOrFatal(t *testing.T, mode Mode, secret string) *Pseudonymiser {
	t.Helper()
	p, err := New(mode, secret)
	if err != nil {
		t.Fatalf("New(%q, %d-byte secret): %v", mode, len(secret), err)
	}
	return p
}

// PRI-001 — the trailer and the segment are the same value under
// `pseudonymous` and differ by CASE ONLY under `literal`.
//
// ADR-0018 §6 requires Agent-Task to lowercase to the identity's {task_id}.
// Both modes must satisfy that, or `signing.Claim.Trailers` refuses every
// claim and no commit can be signed at all.
func TestPRI001TheTrailerAlwaysLowercasesToTheSegment(t *testing.T) {
	for _, tc := range []struct {
		mode    Mode
		secret  string
		trailer string
	}{
		{ModeLiteral, "", "JIRA-118"},
		{ModePseudonymous, "0123456789abcdef0123456789abcdef", ""},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			p := newOrFatal(t, tc.mode, tc.secret)
			segment, err := p.TaskID("JIRA-118")
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := p.ClaimedTask("JIRA-118")
			if err != nil {
				t.Fatal(err)
			}
			if strings.ToLower(claimed) != segment {
				t.Errorf("Agent-Task would be %q and the identity's {task_id} is %q; "+
					"they must agree once lowercased (ADR-0018 §6) or check 3 has "+
					"nothing to settle", claimed, segment)
			}
			if tc.trailer != "" && claimed != tc.trailer {
				t.Errorf("Agent-Task = %q, want the caller's own %q: `literal` must "+
					"reproduce exactly what the trailer said before RM-079", claimed, tc.trailer)
			}
			if tc.mode == ModePseudonymous && claimed != segment {
				t.Errorf("Agent-Task = %q and {task_id} = %q; under %q they are one value, "+
					"and a trailer that still read JIRA-118 would put the ticket back in "+
					"every public repository", claimed, segment, tc.mode)
			}
		})
	}
	// And the refusal path: a value the grammar will not carry is refused by
	// ClaimedTask too, not only by TaskID.
	p := newOrFatal(t, ModeLiteral, "")
	if _, err := p.ClaimedTask("JIRA/118"); err == nil {
		t.Errorf("ClaimedTask admitted a task reference TaskID refuses")
	}
}
