// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The deployment config `innsegl init` writes (#117 point 3, second half).
//
// This is deliberately the SAME environment `innsegl serve`, `seal`, `reap`
// and `reconcile` already read (envFulcioURL, envRekorURL, envOIDCIssuer in
// serve.go; envIdentityMode / envIdentitySecretFile likewise) — not a new
// vocabulary. A repository `init` has set up can run any of those commands
// by sourcing the one file this writes, and a deployment can never have two
// spellings of the same setting disagreeing with each other.
//
// The identity secret is the one value that never goes in that tracked
// file. It goes in its own file under .git/ — never committed, matching
// gitsignInstallDir's own reasoning — and the tracked file names it through
// $INNSEGL_IDENTITY_SECRET_FILE, exactly the indirection serve.go already
// supports for "compose can mount a volume but cannot read one into an
// environment variable" (RM-084, #124). A constant secret in a tracked file
// is the mistake #124 exists to describe; this file does not repeat it.

// deployConfigRelPath is where the tracked, non-secret deployment
// configuration lives, relative to the repository root. Committing it is
// the operator's choice — every value in it is already public in the sense
// that it configures WHICH Sigstore this deployment uses, not a credential.
const deployConfigRelPath = ".innsegl/deploy.env"

// identitySecretRelPath is where the generated or supplied identity secret
// lives: under .git/, which git itself never tracks, matching
// gitsignInstallDir's reasoning for the same directory.
//
//nolint:gosec // G101: this is a file PATH, not a credential value
const identitySecretRelPath = ".git/innsegl/identity-secret"

// deployConfigMarker opens the tracked file. Its presence is what lets
// writeDeployConfig tell "a file init wrote before" from "an unrelated file
// that happens to be at this path" apart, and what lets removeDeployConfig
// refuse to delete a file that lost it.
const deployConfigMarker = "# managed by `innsegl init` — do not edit by hand; see `innsegl init --undo`\n"

func deployConfigPath(repo string) string   { return filepath.Join(repo, deployConfigRelPath) }
func identitySecretPath(repo string) string { return filepath.Join(repo, identitySecretRelPath) }
func isManagedDeployFile(body []byte) bool {
	return strings.HasPrefix(string(body), deployConfigMarker)
}

// deployConfig is the non-secret half of what `init` writes.
type deployConfig struct {
	FulcioURL    string
	RekorURL     string
	OIDCIssuer   string
	IdentityMode string
}

// writeDeployConfig writes the tracked deploy.env and, when secret is
// non-empty, the untracked identity secret file. It returns every path it
// wrote (for the git-config bookkeeping in initgit.go's recordFiles), or
// refuses without writing anything if deploy.env already exists and was not
// written by a prior `init` run.
func writeDeployConfig(repo string, cfg deployConfig, secret string) ([]string, error) {
	target := deployConfigPath(repo)
	if existing, err := os.ReadFile(target); err == nil {
		if !isManagedDeployFile(existing) {
			return nil, fmt.Errorf("innsegl init: %s already exists and was not written by "+
				"`innsegl init` — refusing to overwrite a file it does not own", deployConfigRelPath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("innsegl init: reading %s: %w", deployConfigRelPath, err)
	}

	var b strings.Builder
	b.WriteString(deployConfigMarker)
	fmt.Fprintf(&b, "%s=%s\n", envFulcioURL, cfg.FulcioURL)
	fmt.Fprintf(&b, "%s=%s\n", envRekorURL, cfg.RekorURL)
	fmt.Fprintf(&b, "%s=%s\n", envOIDCIssuer, cfg.OIDCIssuer)
	fmt.Fprintf(&b, "%s=%s\n", envIdentityMode, cfg.IdentityMode)

	paths := []string{deployConfigRelPath}
	if secret != "" {
		secretAbs := identitySecretPath(repo)
		if err := os.MkdirAll(filepath.Dir(secretAbs), 0o700); err != nil {
			return nil, fmt.Errorf("innsegl init: preparing the identity secret directory: %w", err)
		}
		if err := os.WriteFile(secretAbs, []byte(secret+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("innsegl init: writing the identity secret: %w", err)
		}
		fmt.Fprintf(&b, "%s=%s\n", envIdentitySecretFile, identitySecretRelPath)
		paths = append(paths, identitySecretRelPath)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, fmt.Errorf("innsegl init: preparing %s: %w", filepath.Dir(deployConfigRelPath), err)
	}
	// 0600: this file names Fulcio/Rekor URLs and an identity MODE, not a
	// secret, but there is no reason to leave it group/world readable when
	// nothing needs it to be.
	if err := os.WriteFile(target, []byte(b.String()), 0o600); err != nil {
		return nil, fmt.Errorf("innsegl init: writing %s: %w", deployConfigRelPath, err)
	}
	return paths, nil
}

// removeDeployConfig reverses writeDeployConfig. paths are interpreted
// relative to repo (they are exactly what writeDeployConfig returned, and
// what initgit.go's bookkeeping stores). It deletes each one, EXCEPT the
// tracked deploy.env if that file no longer carries the marker — an operator
// who hand-edited it since has made it theirs, and --undo must not destroy
// an edit it cannot tell apart from its own output. The identity secret file
// is always removed unconditionally: nothing else is ever meant to write
// there.
func removeDeployConfig(repo string, paths []string) error {
	var errs []error
	for _, rel := range paths {
		p := rel
		if !filepath.IsAbs(p) {
			p = filepath.Join(repo, rel)
		}
		if strings.HasSuffix(rel, deployConfigRelPath) {
			body, err := os.ReadFile(p)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				errs = append(errs, err)
				continue
			}
			if !isManagedDeployFile(body) {
				continue // hand-edited since; leave it
			}
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
