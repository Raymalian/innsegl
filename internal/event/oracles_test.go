// SPDX-License-Identifier: Apache-2.0

package event

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SER-040 (proposed for doc 07; doc 07 is not modified here) — RM-262, #413.
//
// Every released fixture set carries verify.py, an oracle that is not Go: it
// re-derives each vector's canonical bytes and hash with Python's json and
// hashlib. A fixture checked only by the code it came from proves only that
// the code agrees with itself, so the oracles are the independent half of
// SER-024. Nothing ran them. v3's was copied from v2's with its version
// constant left at "2", and reported 19 mismatches on its own fixtures for as
// long as it existed, unnoticed.
//
// Two checks, per released version:
//
//   - the oracle declares the schema version of the directory it sits in, so
//     a copied oracle cannot quietly check the previous version's claims;
//   - the oracle runs, from its own directory, and exits 0.

// oracleVersion is the SCHEMA_VERSION line every oracle declares.
var oracleVersion = regexp.MustCompile(`(?m)^SCHEMA_VERSION = "([0-9]+)"$`)

func TestSER040EveryFixtureOracleRunsAndReadsItsOwnVersion(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 is not on PATH: %v", err)
	}
	for _, version := range releasedSchemaVersions {
		t.Run("v"+version, func(t *testing.T) {
			dir := filepath.Join("testdata", "fixtures", "v"+version)
			src, err := os.ReadFile(filepath.Join(dir, "verify.py"))
			if err != nil {
				t.Fatalf("schema %s has no oracle: %v", version, err)
			}
			m := oracleVersion.FindSubmatch(src)
			if m == nil {
				t.Fatalf("%s/verify.py declares no SCHEMA_VERSION; an oracle that does not "+
					"say which version it reads cannot be held to its directory", dir)
			}
			if got := string(m[1]); got != version {
				t.Errorf("%s/verify.py declares SCHEMA_VERSION %q; its directory is schema %q",
					dir, got, version)
			}

			// -I: isolated, so nothing in the environment or the current
			// directory can stand in for the standard library it imports.
			cmd := exec.CommandContext(t.Context(), python, "-I", "verify.py")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s/verify.py failed: %v\n%s", dir, err, out)
			}
			if !strings.HasPrefix(string(out), "OK:") {
				t.Errorf("%s/verify.py exited 0 without its OK line:\n%s", dir, out)
			}
		})
	}
}
