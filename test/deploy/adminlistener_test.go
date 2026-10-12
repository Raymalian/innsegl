// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"regexp"
	"testing"
	"time"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// OPS-215 (#604, ADR-0083) — the live and dev stacks run no admin listener.
//
// `make start`, `make update` and every other path that brings the core up
// used to set INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090, so the identity lifecycle
// was served on every deployment the Makefile made, and published on the host
// at 127.0.0.1:28090. Nothing shipped calls it: the gateway registers in
// process and `innsegl retire` runs on the core (ADR-0077). The listener is now
// opt-in. No make path turns it on, the compose file leaves it unset and
// publishes no host port for it, and the old single-listener behaviour stays
// off too.
func TestOPS215TheStacksRunNoAdminListener(t *testing.T) {
	setsListener := regexp.MustCompile(`INNSEGL_MCP_ADMIN_LISTEN=['"]?[^'"\s]`)
	for _, mode := range []string{"live", "dev"} {
		for _, target := range []string{"start", "update", "innsegl-up-here"} {
			out := deploytest.MakeDryRun(t, mode, target)
			if m := setsListener.FindString(out); m != "" {
				t.Errorf("make -n %s (%s) turns the admin listener on: %s", target, mode, m)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := deploytest.ComposeUsable(ctx); err != nil {
		t.Skipf("skipping the compose half of OPS-215: %v", err)
	}
	cfg := deploytest.InterpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	if v, _ := cfg.Env("innsegl-core", "INNSEGL_MCP_ADMIN_LISTEN"); v != "" {
		t.Errorf("innsegl-core has INNSEGL_MCP_ADMIN_LISTEN=%q by default, want it unset", v)
	}
	if v, _ := cfg.Env("innsegl-core", "INNSEGL_MCP_LIFECYCLE_ON_AGENT_LISTENER"); v != "" {
		t.Errorf("innsegl-core has INNSEGL_MCP_LIFECYCLE_ON_AGENT_LISTENER=%q by default, want it unset", v)
	}
	for _, p := range cfg.Services["innsegl-core"].Ports {
		if p.Target == 8090 {
			t.Errorf("innsegl-core publishes the admin listener's port 8090 on the host (%+v)", p)
		}
	}
}
