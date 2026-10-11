// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// OPS-135 (PROPOSED for doc 07's TC-OPS) — `make update` sees a settings
// change, not only a code change (#533).
//
// MEASURED: turning the trust-key backup on is two lines in
// deploy/compose/.env and `make update`. The update recorded only the commit
// it deployed, found the checkout unchanged, printed "already up to date" and
// started nothing; the backup service never ran. What `make update` records
// must name the settings it deployed with as well.
// ---------------------------------------------------------------------------

func TestOPS135UpdateRecordsTheSettingsItDeployedWith(t *testing.T) {
	env := filepath.Join(t.TempDir(), ".env")
	write := func(s string) {
		if err := os.WriteFile(env, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("INNSEGL_TLS=1\n")
	before := deploytest.UpdateMarker(t, env)
	if again := deploytest.UpdateMarker(t, env); again != before {
		t.Fatalf("the same settings gave two markers: %q then %q", before, again)
	}

	write("INNSEGL_TLS=1\nCOMPOSE_PROFILES=trust-backup\n")
	if after := deploytest.UpdateMarker(t, env); after == before {
		t.Fatalf("a changed .env left the marker at %q, so make update would call it up to date", after)
	}

	if err := os.Remove(env); err != nil {
		t.Fatal(err)
	}
	if none := deploytest.UpdateMarker(t, env); none == before {
		t.Fatalf("no .env gave the same marker as one with settings: %q", none)
	}
}
