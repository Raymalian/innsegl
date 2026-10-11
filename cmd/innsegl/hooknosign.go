// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// An agent's commit is signed or not made (ADR-0059; signing is fail-closed).
// A refused signature has a cause -- a repository that is not linked yet, a
// core that cannot be reached, signing itself down -- and the way out is the
// cause, never a commit with signing turned off: that commit carries the
// agent's author and no attribution. So the PreToolUse hook refuses exactly
// the git commands that turn signing off, and says why. Every other command
// runs.
//
// It reads command text, so it cannot see inside a script file. The ref
// backstop (hookreftx.go) refuses what such a script makes (#584).

var (
	// quotedSpan is a single- or double-quoted span. One holding whitespace
	// is prose (a commit message) and is dropped before matching; one
	// without is a quoted argument and is unquoted.
	quotedSpan = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	// noGPGSign is --no-gpg-sign on any git subcommand: commit, rebase,
	// merge, cherry-pick, revert, pull, am (#584).
	noGPGSign = regexp.MustCompile(`(^|[\s;&|(])--no-gpg-sign($|[\s;&|)])`)
	// gpgsignOff is `-c commit.gpgsign=<off>` on any git invocation.
	gpgsignOff = regexp.MustCompile(`(?i)(^|[\s;&|(])-c\s*commit\.gpgsign=(false|0|no|off)($|[\s;&|)])`)
	// gpgOption is `-c gpg.<key>=…`: the agent choosing its own signing
	// format or program. The hook places the only ones an agent's commit
	// needs, after the command's own.
	gpgOption = regexp.MustCompile(`(?i)(^|[\s;&|(])-c\s*gpg\.\S*=`)
	// configEnvOption is `--config-env <key>=<variable>` for a signing key.
	configEnvOption = regexp.MustCompile(`(?i)(^|[\s;&|(])--config-env(=|\s+)(commit\.gpgsign|gpg\.\S+)=`)
	// gitConfigVariable assigns or exports GIT_CONFIG_COUNT or
	// GIT_CONFIG_PARAMETERS: configuration a command has no reason to
	// carry, and which the harness's isolation guard refuses anyway.
	gitConfigVariable = regexp.MustCompile(`(^|[\s;&|(])GIT_CONFIG_(COUNT|PARAMETERS)=|` +
		`(^|[\s;&|(])export\s+([^;&|\n]*\s)?GIT_CONFIG_(COUNT|PARAMETERS)($|[\s;&|)=])`)
	// commitTree is `git … commit-tree <rest>`: plumbing that never signs
	// unless told to with -S.
	commitTree = regexp.MustCompile(`(^|[\s;&|(])git(\s+-\S+(\s+\S+)?)*\s+commit-tree($|[\s;&|)])([^;&|\n)]*)`)
	signFlag   = regexp.MustCompile(`(^|\s)(-S\S*|--gpg-sign(=\S*)?)($|\s)`)
	// gitConfig is `git … config <rest>`.
	gitConfig = regexp.MustCompile(`(^|[\s;&|(])git(\s+-\S+(\s+\S+)?)*\s+config($|[\s;&|)])([^;&|\n)]*)`)
	// signingKey is a configuration key that decides whether, or how, git
	// signs a commit.
	signingKey = regexp.MustCompile(`(?i)^(commit\.gpgsign|gpg\..+)$`)
	offValue   = regexp.MustCompile(`(?i)^(false|0|no|off)$`)
)

// unquotedForMatch is command with prose removed and bare quoted arguments
// unquoted, so a flag inside a commit message is not read as a flag.
func unquotedForMatch(command string) string {
	return quotedSpan.ReplaceAllStringFunc(command, func(s string) string {
		inner := s[1 : len(s)-1]
		if strings.ContainsAny(inner, " \t\n") {
			return " "
		}
		return inner
	})
}

// turnsSigningOff reports whether command makes a commit with signing off,
// or changes signing for later commits (CMT-021): any --no-gpg-sign,
// `-c commit.gpgsign=false`, `-c gpg.*`, `--config-env` for a signing key,
// GIT_CONFIG_COUNT or GIT_CONFIG_PARAMETERS, `git commit-tree` without -S,
// and `git config` writing a signing key.
func turnsSigningOff(command string) bool {
	c := unquotedForMatch(command)
	if noGPGSign.MatchString(c) || gpgsignOff.MatchString(c) || gpgOption.MatchString(c) ||
		configEnvOption.MatchString(c) || gitConfigVariable.MatchString(c) {
		return true
	}
	for _, m := range commitTree.FindAllStringSubmatch(c, -1) {
		if !signFlag.MatchString(m[len(m)-1]) {
			return true
		}
	}
	for _, m := range gitConfig.FindAllStringSubmatch(c, -1) {
		if configWritesSigning(strings.Fields(m[len(m)-1])) {
			return true
		}
	}
	return false
}

// configWritesSigning reports whether `git config <args>` changes a signing
// key: any write of a gpg.* key, and commit.gpgsign set off or unset.
// Reading one (--get, --list, `get`, `list`) changes nothing.
func configWritesSigning(args []string) bool {
	unset := false
	for i, a := range args {
		switch a {
		case "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "get", "list":
			return false
		case "--unset", "--unset-all", "unset":
			unset = true
		}
		if !signingKey.MatchString(a) {
			continue
		}
		if unset || strings.HasPrefix(strings.ToLower(a), "gpg.") {
			return true
		}
		return i+1 < len(args) && offValue.MatchString(args[i+1])
	}
	return false
}

// signingOutage is a signing outage the core's signing probe reports: since
// when, and why.
type signingOutage struct {
	Since  time.Time
	Reason string
}

// signingOutageNow answers whether signing is down right now. A variable so
// a test can set the answer.
var signingOutageNow = signingOutageFromClient

// signingOutageFromClient asks this machine's client service, which reads
// the core's signing probe (#583) every minute, whether signing is down.
// It is asked only when a command is refused, and anything that keeps it
// from knowing is "not known to be down": the refusal then names no outage.
func signingOutageFromClient() (signingOutage, bool) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return signingOutage{}, false
	}
	since, reason, down := client.SigningOutage(context.Background(), client.ClientPaths(home))
	return signingOutage{Since: since, Reason: reason}, down
}

// outageText is the sentence a refusal carries while signing is down
// (JRN-011), or "" when no outage is known.
func outageText(o signingOutage, down bool) string {
	if !down {
		return ""
	}
	text := "Now: signing is down since " + o.Since.UTC().Format(time.RFC3339)
	if o.Reason != "" {
		text += " (" + o.Reason + ")"
	}
	return text + "; do not retry with signing off; keep working and commit after repair. "
}

// signingOffReason is what the agent reads when a command that turns
// signing off is refused.
func signingOffReason() string {
	o, down := signingOutageNow()
	return "innsegl: an agent's commits must be signed, so a command that turns signing off is refused " +
		"(--no-gpg-sign, commit.gpgsign=false, -c gpg.*, GIT_CONFIG_COUNT or GIT_CONFIG_PARAMETERS, " +
		"git commit-tree without -S, git config of a signing key). " + outageText(o, down) +
		"If signing itself failed, do not retry with signing off; fix its cause instead: " +
		"run `innsegl link <repository>` when the core says the message lacks the run's trailers, and check " +
		"`curl -s http://127.0.0.1:28195/_client/status` when the core cannot be reached. Then commit normally."
}

// writeDeny writes the harness's PreToolUse refusal for this one command.
func writeDeny(stdout io.Writer, reason string) {
	var out struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = reason
	// A write failure has nothing to fall back to; the command then runs.
	_ = json.NewEncoder(stdout).Encode(out) //nolint:errcheck // see above
}
