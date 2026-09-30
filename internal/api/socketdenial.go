// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
)

// ADR-0062, "Enrolment stays locked until the presence gate is actually
// load-bearing": minting the first enrolment code and minting an admin
// credential are the same presence-gated action, and that presence gate only
// means anything once an agent running as the operator's own user is denied
// the container runtime's socket. E18 (#389, #390) is what makes that denial
// real: `install.sh` writes a managed-settings.json the harness cannot be
// talked out of, with `sandbox.enabled: true`, `sandbox.allowUnsandboxedCommands:
// false`, and — load-bearing by ABSENCE — no `sandbox.network.allowUnixSockets`
// or `allowAllUnixSockets` entry at all, because either key existing at any
// value is install.sh's own signal that the one thing this contract exists to
// deny has been listed (see install.sh's `install_sandbox`).
//
// CheckSocketDenial is the fact the enrolment endpoint reads, every time it is
// asked to mint or accept a first-enrolment code — never once at start-up,
// never cached — per the ADR's own words: "the enrolment endpoint asks, every
// time, rather than trusting that a denial applied once is still applied now."
//
// It never returns a hard error for a file that is absent, unreadable, or not
// JSON: every one of those is exactly a state in which the socket cannot be
// shown denied, and CheckSocketDenial's job is to say so as a refusal reason,
// not to distinguish "no" from "cannot tell" — both refuse enrolment. A real
// Go error is reserved for something CheckSocketDenial itself cannot recover
// from, which in practice does not happen: there is nothing here but a read
// and a parse.

// EnvManagedSettingsFile is the environment variable naming the managed
// settings file CheckSocketDenial reads. Unset falls back to
// DefaultManagedSettingsPath(runtime.GOOS).
const EnvManagedSettingsFile = "INNSEGL_API_MANAGED_SETTINGS_FILE"

// DefaultManagedSettingsPath is where Claude Code's harness reads its managed
// settings from, per OS — the same two paths install.sh's own
// default_managed_settings_path chooses between.
func DefaultManagedSettingsPath(goos string) string {
	if goos == "darwin" {
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	}
	return "/etc/claude-code/managed-settings.json"
}

// ManagedSettingsPathFromEnv resolves the path CheckSocketDenial should read:
// $INNSEGL_API_MANAGED_SETTINGS_FILE if set, else the per-OS default for the
// running process.
func ManagedSettingsPathFromEnv() string {
	if v := os.Getenv(EnvManagedSettingsFile); v != "" {
		return v
	}
	return DefaultManagedSettingsPath(runtime.GOOS)
}

// SocketDenial is what CheckSocketDenial established, named so an enrolment
// refusal can say why rather than only that.
type SocketDenial struct {
	// Denied is true only when the file names sandbox.enabled true,
	// sandbox.allowUnsandboxedCommands false, and carries no
	// sandbox.network.allowUnixSockets or allowAllUnixSockets entry.
	Denied bool
	// Reason is a plain-text explanation, safe to return to an operator on
	// their own machine (never sent anywhere this deployment does not
	// control) — this is the same "say exactly what is wrong" posture
	// admincred.go's own `verify` takes, for the same reason: refusing
	// loudly on your own box costs nothing.
	Reason string
	// Path is the file CheckSocketDenial read, echoed back so a refusal
	// names the file an operator should look at.
	Path string
}

// managedSettingsSandbox is the slice of managed-settings.json this check
// reads. Everything else in the file — env, hooks, permissions — is beside
// this question and deliberately left unparsed.
type managedSettingsSandbox struct {
	Sandbox struct {
		Enabled                  *bool `json:"enabled"`
		AllowUnsandboxedCommands *bool `json:"allowUnsandboxedCommands"`
		Network                  struct {
			AllowUnixSockets    json.RawMessage `json:"allowUnixSockets"`
			AllowAllUnixSockets json.RawMessage `json:"allowAllUnixSockets"`
		} `json:"network"`
	} `json:"sandbox"`
}

// CheckSocketDenial reads path and reports whether it can be read, right now,
// as denying the container runtime's unix socket to a sandboxed shell.
func CheckSocketDenial(path string) (SocketDenial, error) {
	out := SocketDenial{Path: path}

	body, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		out.Reason = fmt.Sprintf("no managed settings file at %s; E18's socket denial "+
			"cannot be shown in effect, so the first enrolment (or its recovery) is refused", path)
		return out, nil
	default:
		// Deliberate: see this function's own package doc comment. Every
		// read/parse problem is a refusal reason, never a Go error — the
		// caller has exactly one thing to decide either way.
		out.Reason = fmt.Sprintf("%s could not be read: %v; the socket denial cannot be "+
			"shown in effect, so enrolment is refused", path, err)
		return out, nil
	}

	var settings managedSettingsSandbox
	if jerr := json.Unmarshal(body, &settings); jerr != nil {
		// Deliberate, same reason as the os.ReadFile default case above:
		// malformed JSON is a refusal reason, never a Go error.
		out.Reason = fmt.Sprintf("%s is not valid JSON; the harness would have discarded "+
			"this file rather than loaded it, so the socket denial cannot be shown in effect", path)
		return out, nil //nolint:nilerr // see the comment above
	}

	switch {
	case settings.Sandbox.Enabled == nil || !*settings.Sandbox.Enabled:
		out.Reason = "sandbox.enabled is not true in " + path
		return out, nil
	case settings.Sandbox.AllowUnsandboxedCommands == nil || *settings.Sandbox.AllowUnsandboxedCommands:
		out.Reason = "sandbox.allowUnsandboxedCommands is not explicitly false in " + path
		return out, nil
	case len(settings.Sandbox.Network.AllowUnixSockets) > 0:
		out.Reason = "sandbox.network.allowUnixSockets is present in " + path +
			"; install.sh deliberately never sets this key, so its presence at all means " +
			"the socket is not denied"
		return out, nil
	case len(settings.Sandbox.Network.AllowAllUnixSockets) > 0:
		out.Reason = "sandbox.network.allowAllUnixSockets is present in " + path +
			"; install.sh deliberately never sets this key, so its presence at all means " +
			"the socket is not denied"
		return out, nil
	}

	out.Denied = true
	out.Reason = "sandbox.enabled is true, allowUnsandboxedCommands is false, and no " +
		"unix-socket exception is configured in " + path
	return out, nil
}
