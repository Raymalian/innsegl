// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
)

// INIT-004 (proposed, doc 07 layer U): the two questions, and the rule that
// makes question 2 conditional on question 1 (#117 "The prompt logic").

func TestINIT004TrustRootFromFlagNeedsNoPrompt(t *testing.T) {
	var stdin, stdout bytes.Buffer
	choice, err := resolveTrustRoot(trustRootPrompt{
		Flag:            "self-hosted",
		In:              &stdin,
		Out:             &stdout,
		NonInteractive:  false,
		TerminalPresent: true,
	})
	if err != nil {
		t.Fatalf("resolveTrustRoot: %v", err)
	}
	if choice != trustRootSelfHosted {
		t.Fatalf("choice = %v, want self-hosted", choice)
	}
	if stdout.Len() != 0 {
		t.Errorf("a flag-supplied answer must not prompt: wrote %q", stdout.String())
	}
}

func TestINIT004TrustRootRejectsAnUnknownFlagValue(t *testing.T) {
	_, err := resolveTrustRoot(trustRootPrompt{Flag: "sideways", NonInteractive: true})
	if err == nil {
		t.Fatal("resolveTrustRoot with an unknown -trust-root value: want an error, got nil")
	}
}

func TestINIT004TrustRootNonInteractiveWithNoFlagRefuses(t *testing.T) {
	// "Both questions must also be settable as flags for unattended use — the
	// command has to work in CI with no terminal." The other side of that
	// requirement is that CI must never be left waiting on a prompt that will
	// never be answered.
	_, err := resolveTrustRoot(trustRootPrompt{NonInteractive: true})
	if err == nil {
		t.Fatal("resolveTrustRoot with no flag and no terminal: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "-trust-root") {
		t.Errorf("error %q does not name the flag that would have avoided it", err)
	}
}

func TestINIT004HeadlessWithoutNonInteractiveFlagIsDetectedAndRefusesToHang(t *testing.T) {
	// "A headless machine needs OIDC device flow. Detect that rather than
	// hanging on a browser that will never open." TerminalPresent=false
	// stands in for "no controlling TTY" (the actual detection is
	// stdinIsTerminal, exercised by TestINIT004StdinIsTerminalDoesNotPanic).
	_, err := resolveTrustRoot(trustRootPrompt{TerminalPresent: false})
	if err == nil {
		t.Fatal("resolveTrustRoot with no terminal and no flag: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "terminal") && !strings.Contains(err.Error(), "headless") {
		t.Errorf("error %q does not explain that no terminal was found", err)
	}
}

func TestINIT004TrustRootPromptsInteractivelyAndParsesTheAnswer(t *testing.T) {
	stdin := strings.NewReader("anyone\n")
	var stdout bytes.Buffer
	choice, err := resolveTrustRoot(trustRootPrompt{
		In: stdin, Out: &stdout, TerminalPresent: true,
	})
	if err != nil {
		t.Fatalf("resolveTrustRoot: %v", err)
	}
	if choice != trustRootPublic {
		t.Fatalf("choice = %v, want public", choice)
	}
	prompted := stdout.String()
	if !strings.Contains(prompted, "only us") || !strings.Contains(prompted, "anyone") {
		t.Errorf("prompt %q does not state both options", prompted)
	}
	// #117: "A private repository is a legitimate reason to choose literal,
	// and the prompt should say that." That text belongs to question 2, but
	// question 1's own prompt must state ITS consequences too — "what leaves
	// the deployment" is the issue's own table header.
	if !strings.Contains(prompted, "leaves the deployment") {
		t.Errorf("prompt %q does not state the consequence of each answer", prompted)
	}
}

func TestINIT004TrustRootDefaultsToSelfHostedOnEmptyAnswer(t *testing.T) {
	stdin := strings.NewReader("\n")
	var stdout bytes.Buffer
	choice, err := resolveTrustRoot(trustRootPrompt{In: stdin, Out: &stdout, TerminalPresent: true})
	if err != nil {
		t.Fatalf("resolveTrustRoot: %v", err)
	}
	if choice != trustRootSelfHosted {
		t.Fatalf("choice on empty answer = %v, want the ADR-0010 default (self-hosted)", choice)
	}
}

// TestINIT004IdentityModeIsSkippedAndPseudonymousOnSelfHosted is the prompt
// logic's central rule: "Question 2 is only load-bearing when question 1
// answered 'anyone'... init should say so rather than presenting a choice
// that does not matter."
func TestINIT004IdentityModeIsSkippedAndPseudonymousOnSelfHosted(t *testing.T) {
	var stdin, stdout bytes.Buffer // no input available: a prompt here would hang forever
	mode, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: trustRootSelfHosted,
		In:        &stdin, Out: &stdout, TerminalPresent: true,
	})
	if err != nil {
		t.Fatalf("resolveIdentityMode: %v", err)
	}
	if mode != identity.ModePseudonymous {
		t.Fatalf("mode = %v, want the safe default (pseudonymous) with nothing asked", mode)
	}
	if stdout.Len() == 0 {
		t.Error("init must still SAY why nothing was asked, not silently skip it")
	}
	if !strings.Contains(stdout.String(), "nothing is published") &&
		!strings.Contains(stdout.String(), "not published") {
		t.Errorf("explanation %q does not state the reason (self-hosted publishes nothing)", stdout.String())
	}
}

func TestINIT004IdentityModePromptsOnlyWhenTrustRootIsPublic(t *testing.T) {
	stdin := strings.NewReader("literal\n")
	var stdout bytes.Buffer
	mode, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: trustRootPublic,
		In:        stdin, Out: &stdout, TerminalPresent: true,
	})
	if err != nil {
		t.Fatalf("resolveIdentityMode: %v", err)
	}
	if mode != identity.ModeLiteral {
		t.Fatalf("mode = %v, want literal", mode)
	}
	prompted := stdout.String()
	if !strings.Contains(prompted, "pseudonymous") || !strings.Contains(prompted, "literal") {
		t.Errorf("prompt %q does not state both options", prompted)
	}
	// #117: "A private repository is a legitimate reason to choose literal,
	// and the prompt should say that. The goal is an informed default, not a
	// lecture."
	if !strings.Contains(prompted, "private repositor") {
		t.Errorf("prompt %q does not name a private repository as a legitimate reason for literal", prompted)
	}
	if !strings.Contains(prompted, "permanent") {
		t.Errorf("prompt %q does not state the consequence (a permanent public record)", prompted)
	}
}

func TestINIT004IdentityModeFromFlagSkipsThePromptEvenUnderPublic(t *testing.T) {
	var stdin, stdout bytes.Buffer
	mode, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: trustRootPublic,
		Flag:      "literal",
		In:        &stdin, Out: &stdout,
	})
	if err != nil {
		t.Fatalf("resolveIdentityMode: %v", err)
	}
	if mode != identity.ModeLiteral {
		t.Fatalf("mode = %v, want literal", mode)
	}
	if stdout.Len() != 0 {
		t.Errorf("a flag-supplied answer must not prompt: wrote %q", stdout.String())
	}
}

func TestINIT004IdentityModeDefaultsToPseudonymousOnEmptyAnswer(t *testing.T) {
	stdin := strings.NewReader("\n")
	var stdout bytes.Buffer
	mode, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: trustRootPublic, In: stdin, Out: &stdout, TerminalPresent: true,
	})
	if err != nil {
		t.Fatalf("resolveIdentityMode: %v", err)
	}
	if mode != identity.ModePseudonymous {
		t.Fatalf("mode on empty answer = %v, want pseudonymous (the safe default)", mode)
	}
}

func TestINIT004IdentityModeRejectsAnUnknownAnswer(t *testing.T) {
	stdin := strings.NewReader("mystery\n")
	var stdout bytes.Buffer
	_, err := resolveIdentityMode(identityModePrompt{
		TrustRoot: trustRootPublic, In: stdin, Out: &stdout, TerminalPresent: true,
	})
	if err == nil {
		t.Fatal("resolveIdentityMode with an unrecognised answer: want an error, got nil")
	}
}

func TestINIT004IdentityModeNonInteractiveUnderPublicWithNoFlagRefuses(t *testing.T) {
	_, err := resolveIdentityMode(identityModePrompt{TrustRoot: trustRootPublic, NonInteractive: true})
	if err == nil {
		t.Fatal("resolveIdentityMode(public, non-interactive, no flag): want an error, got nil")
	}
	if !strings.Contains(err.Error(), "-identity-mode") {
		t.Errorf("error %q does not name the flag that would have avoided it", err)
	}
}

func TestINIT004StdinIsTerminalDoesNotPanic(t *testing.T) {
	// Only exercised for the "does not panic and returns a bool" contract;
	// its actual value depends on how the test binary itself was invoked and
	// is not asserted.
	_ = stdinIsTerminal()
}
