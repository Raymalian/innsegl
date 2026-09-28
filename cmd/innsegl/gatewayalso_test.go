// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

// reservePort binds an ephemeral loopback port and returns it still
// listening, for a test that needs to occupy an address rather than merely
// learn a free one.
func reservePort(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port to occupy: %v", err)
	}
	return ln
}

// GW-004: `serve -also gateway` runs the gateway in-process, and a gateway
// return stops the replica.
//
// alsoCommands is untouched by this test -- it is the real map serve.go
// ships, mapping "gateway" to the real gatewayCommand -- so a companion
// goroutine here is genuinely running cmd/innsegl's own gateway subcommand,
// not a stub standing in for it. What makes its failure observable without
// a live network dependency is forcing openGateway's own listen call to
// fail: a port this test already holds open, handed to the companion as
// its OWN configured listen address. The error text that failure produces
// names that exact address, which is the proof this ran for real rather
// than being faked out from underneath.
//
// The (faked) MCP server this case is paired with blocks on its own context
// until it is cancelled and never returns on its own (fakeServer.Serve), so
// the only way runServeCommand can return here is the companion's failure
// stopping the whole replica -- ADR-0060 decision 1's "a gateway that has
// silently stopped forwarding traffic is exactly the failure mode the
// existing companions are already built to surface loudly rather than let
// happen quietly," and the mechanism -- "ANY RETURN IS A FAILURE" -- serve.go
// already built for `api`, `seal`, `reconcile` and `reap`.
func TestGW004ServeAlsoGatewayRunsInProcessAndAReturnStopsTheReplica(t *testing.T) {
	clearServeEnv(t)

	occupied := reservePort(t)
	defer func() { _ = occupied.Close() }()
	occupiedAddr := occupied.Addr().String()

	t.Setenv(envGatewayListen, occupiedAddr)
	t.Setenv(envGatewayUpstream, "https://api.anthropic.com")

	args := completeServeArgs("-also", "gateway")[1:]

	var stdout, stderr bytes.Buffer
	code := runServeCommand(args, &stdout, &stderr, fakeDeps(&fakeServer{addr: "127.0.0.1:1"}, nil))

	if code != exitServeFailed {
		t.Fatalf("serve -also gateway (listen address already in use) = %d, want %d "+
			"(exitServeFailed). stderr:\n%s", code, exitServeFailed, stderr.String())
	}
	if !strings.Contains(stderr.String(), "gateway") {
		t.Errorf("stderr does not name the gateway companion: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "a companion subcommand stopped") {
		t.Errorf("stderr does not report that the companion stopped: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), occupiedAddr) {
		t.Errorf("stderr does not name the listen address the REAL gatewayCommand tried to "+
			"bind (%s), which is what proves this ran for real: %q", occupiedAddr, stderr.String())
	}
}
