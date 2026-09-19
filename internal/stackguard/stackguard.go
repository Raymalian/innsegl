// SPDX-License-Identifier: Apache-2.0

// Package stackguard lets a test package refuse to run itself against a live
// deployment — RM-170 (#275).
//
// # Why a package and not a wrapper
//
// Two packages in this repository destroy a running deployment. test/failure
// brings the shipped Sigstore stack up with the transparency log's tree id
// unset, which mints a new tree; measured once, a log of 74 entries became a
// log of 1. test/smoke earns OPS-004's clean slate with `docker compose down
// -v` on both shipped projects, which on a live host removes the ledger, the
// Fulcio CA key and the log itself.
//
// scripts/test-suite.sh keeps every wrapper away from them. It cannot keep a
// person away from them: `go test ./test/smoke` reaches the package with no
// wrapper in between, and that is the command somebody types when they are
// looking at a failure in it. This is what that command runs into.
//
// # One place decides, and it is not this file
//
// Nothing here knows what a deployment looks like. The question goes to
// scripts/test-suite.sh, which is the single definition — of what the suite is,
// of what is destructive, and of how a running deployment is recognised. Two
// places answering that would be the same defect in a new shape: five call
// sites each making the same judgement is how #275 happened.
//
// # What it refuses and what it does not
//
// It refuses only while there is something to destroy. On a runner, on a quiet
// laptop, on a host whose stack is stopped, Check returns no refusal and both
// packages run exactly as they always did — they are the only proof of two
// invariants and a permanent ban would cost more than the incident. A guard
// that cannot be found or cannot be run is reported as an error, never as a
// refusal: scripts/hooks/subagent-identity.sh carries this project's own words
// for it, that a gate which blocks and offers nothing strands the work.
package stackguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// guardScript is the single definition, relative to the repository root.
const guardScript = "scripts/test-suite.sh"

// exitRefused is scripts/test-suite.sh's REFUSED status. Anything else
// non-zero is the guard failing rather than the guard deciding, and the two
// must not be confused: one is a live deployment, the other is a bug.
const exitRefused = 9

// guardTimeout bounds the question. It is generous because the guard talks to
// docker, and short because every test binary in the suite waits behind it.
const guardTimeout = 60 * time.Second

// ErrNoGuard reports that the repository root, or the guard inside it, could
// not be found.
var ErrNoGuard = errors.New("stackguard: " + guardScript + " not found")

// Root walks up from the working directory to the repository that holds the
// guard.
//
// A test binary runs with its package directory as the working directory, so
// this is two or three levels of walking and no assumption about how deep the
// caller sits.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, guardScript)); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNoGuard
		}
		dir = parent
	}
}

// Check asks the guard in root whether pkgDir may run here.
//
// It returns the refusal the guard printed, or "" when the package may run. An
// error means the question could not be asked — a missing guard, or a guard
// that failed for a reason of its own — and is never by itself a reason to stop.
func Check(root, pkgDir string) (string, error) {
	script := filepath.Join(root, guardScript)
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoGuard, script)
	}

	// BOUNDED. The guard asks docker what is running, and an unresponsive
	// daemon is a thing that happens. A question that never returns would hang
	// every test binary in the suite behind it — a worse outcome than either
	// answer, and the kind of gate that gets switched off.
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()

	// `sh script` rather than executing it directly: a checkout that lost the
	// executable bit (a zip, a copy, a container mount) would otherwise turn
	// this into the error path on a host where the guard is fine.
	cmd := exec.CommandContext(ctx, "sh", script, "guard", pkgDir)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr

	err := cmd.Run()
	if err == nil {
		return "", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == exitRefused {
		return strings.TrimRight(stderr.String(), "\n"), nil
	}
	return "", fmt.Errorf("stackguard: %s guard %s: %w: %s",
		guardScript, pkgDir, err, strings.TrimSpace(stderr.String()))
}

// Refuse ends the process when running pkgDir here would destroy a deployment.
//
// Call it first thing in TestMain, before any harness has started a container.
// A refusal exits non-zero: a package that declined to run is not a package
// that passed, and a green exit here would be the false green this repository
// keeps finding.
func Refuse(pkgDir string) {
	root, err := Root()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v — running %s unguarded\n", err, pkgDir)
		return
	}
	refusal, err := Check(root, pkgDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v — running %s unguarded\n", err, pkgDir)
		return
	}
	if refusal == "" {
		return
	}
	fmt.Fprintln(os.Stderr, refusal)
	os.Exit(1)
}
