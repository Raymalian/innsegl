// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"testing"
	"time"
)

// A restart lets the gateway finish the model replies it is streaming. The
// gateway drains for INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT, and the runtime must
// wait at least that long before it kills the container; with the runtime's
// 10s default, a reply in flight was cut (measured 2026-10-03, "Connection
// lost mid-response"). New requests during the drain find the listener
// closed, and the client sends them to the provider and journals them.
func TestGatewayDrainFitsInsideTheStopGracePeriod(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	mcp := cfg.service(t, "innsegl-mcp")
	raw := mcp.Environment["INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT"]
	if raw == nil {
		t.Fatal("innsegl-mcp sets no INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT; the gateway drains for 15s")
	}
	drain, err := time.ParseDuration(*raw)
	if err != nil {
		t.Fatalf("INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT %q: %v", *raw, err)
	}
	if drain < 2*time.Minute {
		t.Errorf("the gateway drains for %s; a model reply streams for minutes", drain)
	}
	grace, err := time.ParseDuration(mcp.StopGracePeriod)
	if err != nil {
		t.Fatalf("innsegl-mcp stop_grace_period %q: %v (the runtime default is 10s)", mcp.StopGracePeriod, err)
	}
	// The drain is part of every update's restart: five minutes held each
	// `make update` that long (measured 2026-10-03: 292s). A model reply
	// rarely streams past two minutes, and what the drain does not wait for the
	// client sends on and journals.
	if drain > 2*time.Minute {
		t.Errorf("the gateway drain %s is longer than two minutes; every update waits that long", drain)
	}
	if grace <= drain {
		t.Errorf("stop_grace_period %s is not longer than the drain %s; the container is killed mid-drain", grace, drain)
	}
}
