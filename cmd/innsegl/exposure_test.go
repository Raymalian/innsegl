// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"
)

// GW-015 — a gateway reachable beyond loopback without client authentication
// is refused.
func TestGW015CheckGatewayExposure(t *testing.T) {
	cases := []struct {
		name    string
		bind    string
		auth    string
		wantErr bool
	}{
		{"unset", "", "", false},
		{"ipv4 loopback", "127.0.0.1", "", false},
		{"ipv4 loopback block", "127.5.4.3", "", false},
		{"ipv6 loopback", "::1", "", false},
		{"ipv6 loopback bracketed", "[::1]", "", false},
		{"localhost", "localhost", "", false},
		{"all interfaces", "0.0.0.0", "", true},
		{"all interfaces v6", "::", "", true},
		{"lan address", "192.0.2.10", "", true},
		{"lan address wrong auth", "192.0.2.10", "none", true},
		{"all interfaces spiffe", "0.0.0.0", "spiffe", false},
		{"lan address spiffe", "192.0.2.10", "spiffe", false},
		{"unparseable bind", "not an address", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"INNSEGL_BIND": tc.bind, "INNSEGL_GATEWAY_CLIENT_AUTH": tc.auth}
			err := checkGatewayExposure(func(k string) string { return env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("bind=%q auth=%q: err = %v, wantErr %v", tc.bind, tc.auth, err, tc.wantErr)
			}
			if err != nil {
				for _, name := range []string{"INNSEGL_BIND", "INNSEGL_GATEWAY_CLIENT_AUTH"} {
					if !strings.Contains(err.Error(), name) {
						t.Errorf("error %q does not name %s", err, name)
					}
				}
			}
		})
	}
}

// The gateway refuses to start when the deployment publishes it beyond
// loopback and it does not authenticate its clients: the flag counts the
// same as the environment variable.
func TestGW015TheGatewayRefusesToStartExposedWithoutClientAuth(t *testing.T) {
	t.Setenv(envBind, "192.0.2.10")
	o := validGatewayOptionsForExposureTest(t)
	if msg := o.validate(); msg == "" || !strings.Contains(msg, envBind) {
		t.Fatalf("validate() = %q, want a refusal naming %s", msg, envBind)
	}
	t.Setenv(envBind, "127.0.0.1")
	if msg := o.validate(); msg != "" {
		t.Fatalf("validate() on loopback = %q, want none", msg)
	}
}

// validGatewayOptionsForExposureTest is a single-host option set validate()
// accepts, so the only refusal left is the one under test.
func validGatewayOptionsForExposureTest(t *testing.T) gatewayOptions {
	t.Helper()
	return gatewayOptions{
		listen: "127.0.0.1:0", upstream: "https://example.invalid", rateLimitRate: 1, rateLimitBurst: 1,
		backstopInterval: time.Minute, caKeyDir: t.TempDir(), caCertDir: t.TempDir(),
		agentMessageKeyID: defaultAgentMessageKeyID,
	}
}
