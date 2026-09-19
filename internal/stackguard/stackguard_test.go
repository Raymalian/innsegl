// SPDX-License-Identifier: Apache-2.0

package stackguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes a throwaway repository root whose scripts/test-suite.sh is the
// given shell body, and returns the root.
//
// The stub is how these cases reach the refusing branch without a deployment to
// refuse: the real script answers "nothing is running" on a CI runner, which is
// exactly the answer that proves nothing about the refusal.
func fixture(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "test-suite.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCheckPassesWhenTheGuardExitsZero(t *testing.T) {
	root := fixture(t, "exit 0\n")

	refusal, err := Check(root, "test/smoke")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if refusal != "" {
		t.Fatalf("a guard that exited 0 produced a refusal:\n%s", refusal)
	}
}

func TestCheckReturnsTheRefusalTheGuardPrinted(t *testing.T) {
	root := fixture(t, "echo 'REFUSED: it is up' >&2\nexit 9\n")

	refusal, err := Check(root, "test/smoke")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(refusal, "REFUSED: it is up") {
		t.Fatalf("the refusal did not carry what the guard said; got %q", refusal)
	}
}

func TestCheckPassesTheDirectoryToTheGuard(t *testing.T) {
	// If the package name never reached the script, a guard keyed on it would
	// refuse everything or nothing — and both read as working.
	root := fixture(t, `[ "$2" = "test/failure" ] || { echo "got $2" >&2; exit 9; }`+"\nexit 0\n")

	refusal, err := Check(root, "test/failure")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if refusal != "" {
		t.Fatalf("the guard did not see the package directory: %s", refusal)
	}
}

func TestCheckIsNotARefusalWhenTheGuardIsMissing(t *testing.T) {
	// A checkout with no script is a broken checkout, not a live deployment.
	// scripts/hooks/subagent-identity.sh carries the reason a gate must not
	// strand work it cannot judge; scripts/test-suite.sh's own `gate` is what
	// keeps the file present.
	root := t.TempDir()

	refusal, err := Check(root, "test/smoke")
	if err == nil {
		t.Fatal("a missing guard was reported as a clean pass; it must say so")
	}
	if refusal != "" {
		t.Fatalf("a missing guard produced a refusal: %s", refusal)
	}
}

func TestCheckReportsAGuardThatFailedForSomeOtherReason(t *testing.T) {
	// Exit 2 is the guard's own usage error. Reporting it as "safe" would be
	// the silent pass this package exists to remove; reporting it as a refusal
	// would block on a bug in the guard rather than on a live deployment.
	root := fixture(t, "echo 'bad command line' >&2\nexit 2\n")

	refusal, err := Check(root, "test/smoke")
	if err == nil {
		t.Fatal("a guard that failed with exit 2 was reported as a clean pass")
	}
	if refusal != "" {
		t.Fatalf("exit 2 was turned into a refusal: %s", refusal)
	}
}

func TestCheckAgainstThisRepositoryLetsAnOrdinaryPackageRun(t *testing.T) {
	// The control that keeps the rest honest: the real script, this real
	// repository, and a package that destroys nothing. It must pass whether or
	// not a deployment is running on the machine this test is on — otherwise
	// the guard is a ban on the suite rather than on two packages.
	root, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}

	refusal, err := Check(root, "internal/ledger")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if refusal != "" {
		t.Fatalf("an ordinary package was refused:\n%s", refusal)
	}
}

func TestRootFindsTheRepositoryFromAPackageDirectory(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "scripts", "test-suite.sh")); statErr != nil {
		t.Fatalf("Root returned %s, which holds no scripts/test-suite.sh: %v", root, statErr)
	}
}
