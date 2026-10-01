// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
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
