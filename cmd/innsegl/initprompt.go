// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"innsegl.dev/innsegl/internal/identity"
)

// The two questions (#117 "The two questions"), and the rule that makes the
// second conditional on the first.
//
// Both are answerable as a flag, for unattended use ("the command has to
// work in CI with no terminal"), and both refuse — rather than hang — when
// neither a flag nor a terminal is available. That refusal is what "detect
// [a headless machine] rather than hanging on a browser that will never
// open" means at the level this file owns: the PROMPT never blocks
// indefinitely. The OIDC device flow itself, for the machine that DOES have
// a flag answer but no browser, is a separate, later concern (initsign.go).

// Environment fallbacks for the two questions' flags, following every other
// subcommand's convention (envFulcioURL and friends in serve.go): a flag
// falls back to an environment variable so unattended use needs no shell
// wrapper. envIdentityMode, envIdentitySecret and envIdentitySecretFile are
// serve.go's own names, reused rather than respelled — question 2 configures
// the SAME deployment setting `innsegl serve` reads at start-up, and two
// spellings of it would be a deployment that can disagree with itself.
const (
	envInitTrustRoot      = "INNSEGL_INIT_TRUST_ROOT"
	envInitNonInteractive = "INNSEGL_INIT_NONINTERACTIVE"
)

// trustRoot is the answer to question 1.
type trustRoot string

const (
	// trustRootSelfHosted: "only us" — self-hosted Fulcio + Rekor, ADR-0010's
	// shipped default. Nothing leaves the deployment.
	trustRootSelfHosted trustRoot = "self-hosted"
	// trustRootPublic: "anyone" — public Sigstore. The certificate, its
	// timestamp and its log index become a permanent public record.
	trustRootPublic trustRoot = "public"
)

// trustRootPrompt is everything resolveTrustRoot needs. Flag pre-empts the
// terminal entirely, which is what makes the same code path serve an
// interactive laptop and an unattended CI job.
type trustRootPrompt struct {
	Flag string // "", "self-hosted" or "public"; also accepts the issue's own words "only us"/"anyone"

	In  io.Reader
	Out io.Writer

	NonInteractive  bool // -non-interactive, or $INNSEGL_INIT_NONINTERACTIVE: never prompt, ever
	TerminalPresent bool // whether In is an interactive terminal; false means "headless"
}

// parseTrustRoot accepts both the flag's canonical spellings and the
// question's own words, so `-trust-root anyone` and typing "anyone" at the
// prompt behave identically — one grammar, not two.
func parseTrustRoot(s string) (trustRoot, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(trustRootSelfHosted):
		return trustRootSelfHosted, true
	case "only-us", "only us", "onlyus", "us":
		return trustRootSelfHosted, true
	case string(trustRootPublic):
		return trustRootPublic, true
	case "anyone":
		return trustRootPublic, true
	default:
		return "", false
	}
}

// resolveTrustRoot answers question 1: who must be able to verify?
func resolveTrustRoot(p trustRootPrompt) (trustRoot, error) {
	if p.Flag != "" {
		root, ok := parseTrustRoot(p.Flag)
		if !ok {
			return "", fmt.Errorf("innsegl init: -trust-root %q is neither %q (only us) nor "+
				"%q (anyone)", p.Flag, trustRootSelfHosted, trustRootPublic)
		}
		return root, nil
	}
	if p.NonInteractive {
		return "", fmt.Errorf("innsegl init: -trust-root (or $%s) is required with "+
			"-non-interactive; there is no terminal to ask on", envInitNonInteractive)
	}
	if !p.TerminalPresent {
		return "", fmt.Errorf("innsegl init: no terminal is attached to ask question 1 on, and "+
			"-trust-root (or $%s) was not given. This looks like a headless machine — pass the "+
			"flag rather than leaving this to hang", envInitTrustRoot)
	}

	fmt.Fprint(p.Out, initQuestion1Text)
	answer, err := readAnswer(p.In)
	if err != nil {
		return "", fmt.Errorf("innsegl init: reading the answer to question 1: %w", err)
	}
	root, ok := parseTrustRoot(answer)
	if !ok {
		return "", fmt.Errorf("innsegl init: %q is neither %q (only us) nor %q (anyone)",
			answer, trustRootSelfHosted, trustRootPublic)
	}
	return root, nil
}

// initQuestion1Text is question 1, stated with its consequences — "the
// prompts state consequences, not just options" (#117 acceptance bullet
// five) — using the issue's own table.
const initQuestion1Text = `Who must be able to verify signed commits in this repository?

  only us   self-hosted Fulcio + Rekor (the shipped default, ADR-0010).
            Nothing leaves the deployment: no certificate, no timestamp,
            no log index is published anywhere a stranger can reach.

  anyone    public Sigstore. The certificate, its timestamp and its log
            index become a permanent public record, checkable by anyone
            with no access to this deployment at all.

Answer "only us" or "anyone" [only us]: `

// identityModePrompt is everything resolveIdentityMode needs.
type identityModePrompt struct {
	TrustRoot trustRoot
	Flag      string // "", "pseudonymous" or "literal"

	In  io.Reader
	Out io.Writer

	NonInteractive  bool
	TerminalPresent bool
}

func parseIdentityMode(s string) (identity.Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(identity.ModePseudonymous):
		return identity.ModePseudonymous, true
	case string(identity.ModeLiteral):
		return identity.ModeLiteral, true
	default:
		return "", false
	}
}

// resolveIdentityMode answers question 2 — but only really asks it when the
// answer can matter.
//
// "Question 2 is only load-bearing when question 1 answered 'anyone' ...
// init should say so rather than presenting a choice that does not matter —
// a prompt that implies a risk that is not present teaches people to ignore
// prompts." So under self-hosted this returns the safe default without
// blocking on a terminal that may not even be there, and prints WHY, because
// silently skipping a question is a different failure — the operator can no
// longer see that a choice existed at all.
func resolveIdentityMode(p identityModePrompt) (identity.Mode, error) {
	if p.TrustRoot != trustRootPublic {
		fmt.Fprint(p.Out, initQuestion2SkippedText)
		if p.Flag != "" {
			mode, ok := parseIdentityMode(p.Flag)
			if !ok {
				return "", fmt.Errorf("innsegl init: -identity-mode %q is neither %q nor %q",
					p.Flag, identity.ModePseudonymous, identity.ModeLiteral)
			}
			return mode, nil
		}
		return identity.ModePseudonymous, nil
	}

	if p.Flag != "" {
		mode, ok := parseIdentityMode(p.Flag)
		if !ok {
			return "", fmt.Errorf("innsegl init: -identity-mode %q is neither %q nor %q",
				p.Flag, identity.ModePseudonymous, identity.ModeLiteral)
		}
		return mode, nil
	}
	if p.NonInteractive {
		return "", fmt.Errorf("innsegl init: -identity-mode (or $%s) is required with "+
			"-non-interactive under a public trust root; there is no terminal to ask on", envIdentityMode)
	}
	if !p.TerminalPresent {
		return "", fmt.Errorf("innsegl init: no terminal is attached to ask question 2 on, and "+
			"-identity-mode (or $%s) was not given", envIdentityMode)
	}

	fmt.Fprint(p.Out, initQuestion2Text)
	answer, err := readAnswer(p.In)
	if err != nil {
		return "", fmt.Errorf("innsegl init: reading the answer to question 2: %w", err)
	}
	mode, ok := parseIdentityMode(answer)
	if !ok {
		return "", fmt.Errorf("innsegl init: %q is neither %q nor %q",
			answer, identity.ModePseudonymous, identity.ModeLiteral)
	}
	return mode, nil
}

// initQuestion2SkippedText is what prints instead of asking, under a
// self-hosted trust root.
const initQuestion2SkippedText = `Identity in the record: not asked.

  On a self-hosted trust root, nothing is published either way — the
  certificate and the transparency-log entry stay inside this deployment.
  A prompt implying a risk that is not present teaches people to ignore
  prompts, so this deployment uses pseudonymous identities (the safe
  default) without asking.

`

// initQuestion2Text is question 2, with the issue's own two rows and the two
// reasons it names for choosing literal deliberately: an operator who wants
// the ticket reference legible in `git log`, and a private repository, where
// nothing in the Agent-Identity trailer is exposed to a stranger either.
const initQuestion2Text = `What identity appears in the record?

  pseudonymous   spiffe://.../agent/a7f3c91b/e2d5f004/run-...
                 The attested tracker link is gone from git log; resolving
                 it needs the ledger.

  literal        spiffe://.../agent/fix-ci/jira-118/run-...
                 The ticket reference is in every commit, and under public
                 Sigstore it becomes part of a permanent public Rekor
                 record. A legitimate reason to choose this anyway: a
                 private repository, where the trailer is not exposed to a
                 stranger either, or wanting the ticket reference legible
                 in git log.

Answer "pseudonymous" or "literal" [pseudonymous]: `

// readAnswer reads one line and trims it. bufio.Reader rather than
// bufio.Scanner: a Scanner's default token size would refuse a very long
// paste before this function ever sees it, and refusing quietly is worse
// than reading a long, wrong answer and refusing it BY NAME above.
func readAnswer(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// stdinIsTerminal reports whether os.Stdin looks like an interactive
// terminal. It is the headless-detection the issue asks for: "A headless
// machine needs OIDC device flow. Detect that rather than hanging on a
// browser that will never open" — applied here to the PROMPT (the browser
// question is initsign.go's).
//
// os.ModeCharDevice is the standard, dependency-free way to ask this in Go:
// a pipe or a redirected file is not a character device, a TTY is. It is not
// perfect (a character device that is not a TTY would pass), but a false
// positive here only means init tries to prompt and gets an empty read,
// which readAnswer already turns into "" (the default answer) rather than a
// hang.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
