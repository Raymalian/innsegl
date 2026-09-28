// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GW-005 — the gateway is reachable from the host on loopback only.
//
// ADR-0060 decision 1 folds the gateway into innsegl-mcp as a fifth
// companion, the same process `seal`, `reconcile` and `reap` already run
// inside. Decision 2 is the point of this case: inside the container the
// gateway listens the way the tool surface already does, so the only thing
// that makes it loopback-only AS EXPERIENCED FROM OUTSIDE THE CONTAINER is
// the compose publish line — "a host-reachability guarantee, not a
// same-container guarantee" — guarded by a compose-config test in the same
// family ADR-0056's own publish lines already run under, "so that line
// cannot drift to every interface, or lose its publish, unnoticed."
//
// This case never starts a container. It interpolates the shipped compose
// file the way the daemon would (docker compose config), the same static
// read oneprocess_test.go uses for INNSEGL_MCP_ALSO's settings, and reads
// back what a plain `docker compose up` — no profile — would actually
// publish for the gateway's container-side port.
// ---------------------------------------------------------------------------

// gatewayContainerPort is the gateway's default listen port inside the
// container (#369, RM-224). It is the container side of the mapping; the
// host side is INNSEGL_GATEWAY_PORT (default 28095) and is not asserted
// here — GW-005 is about reachability, not the mnemonic.
const gatewayContainerPort = 8095

func TestGW005TheGatewayIsPublishedOnLoopbackOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping GW-005: %v", err)
	}

	// No profile: what a plain `docker compose up` publishes, which is the
	// guarantee ADR-0060 decision 2 states — the same "plain up" reading
	// TestRM207OneProcessKeepsWhatTheFoldedServicesHad uses for the other
	// folded settings.
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")

	type publisher struct {
		service string
		port    composePort
	}
	var publishers []publisher
	for name, svc := range cfg.Services {
		for _, p := range svc.Ports {
			if p.Target == gatewayContainerPort {
				publishers = append(publishers, publisher{service: name, port: p})
			}
		}
	}

	switch len(publishers) {
	case 0:
		t.Fatalf("deploy/compose/innsegl.yml publishes no host port for the gateway's "+
			"container port %d. ADR-0060 decision 2: the host guarantee IS the compose "+
			"publish line — add \"127.0.0.1:${INNSEGL_GATEWAY_PORT:-28095}:%d\" to "+
			"innsegl-mcp's ports:, next to its %d and %d lines.",
			gatewayContainerPort, gatewayContainerPort, 8080, 8081)
		return
	case 1:
		// exactly one publisher — the shape ADR-0060 decision 2 requires.
	default:
		names := make([]string, 0, len(publishers))
		for _, p := range publishers {
			names = append(names, p.service)
		}
		t.Fatalf("the gateway's container port %d is published by more than one service: "+
			"%s. ADR-0060 decision 1 folds the gateway into innsegl-mcp alone; a second "+
			"publisher is a second, unaccounted door to the same traffic.",
			gatewayContainerPort, strings.Join(names, ", "))
		return
	}

	got := publishers[0]
	if got.service != "innsegl-mcp" {
		t.Errorf("the gateway's container port %d is published by %q, not innsegl-mcp. "+
			"ADR-0060 decision 1: the gateway is a fifth companion of the one innsegl "+
			"process, not a service of its own.", gatewayContainerPort, got.service)
	}
	if got.port.HostIP != "127.0.0.1" {
		t.Errorf("the gateway's container port %d is published on host_ip %q, not "+
			"127.0.0.1 (an empty host_ip, \"0.0.0.0\" and \"::\" all mean every "+
			"interface). ADR-0060 decision 2: the gateway sees a model provider's login "+
			"credential and the full content of every agent's conversation, in transit, "+
			"on every request — the loopback-only publish line is the entire guarantee, "+
			"the same reasoning ADR-0030 already gave for a lesser surface: \"a default "+
			"that published it on every interface would make an operator's omission the "+
			"exposure.\"", gatewayContainerPort, got.port.HostIP)
	}
}
