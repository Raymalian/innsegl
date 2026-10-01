// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"strings"
	"testing"
)

// The container's own route table, as captured from the running gateway on
// 2026-10-01: the default route's gateway (01001CAC, little-endian) is
// 172.28.0.1, the address a request published from the host arrives from.
const capturedRouteTable = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth3	00000000	01001CAC	0003	0	0	0	00000000	0	0	0
eth1	000014AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eth3	00001CAC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

func TestDefaultGatewayIsReadFromTheRouteTable(t *testing.T) {
	ip, err := defaultGatewayFromRouteTable(strings.NewReader(capturedRouteTable))
	if err != nil {
		t.Fatalf("defaultGatewayFromRouteTable: %v", err)
	}
	if !ip.Equal(net.ParseIP("172.28.0.1")) {
		t.Fatalf("gateway = %v, want 172.28.0.1", ip)
	}
}

func TestARouteTableWithNoDefaultRouteNamesNoGateway(t *testing.T) {
	table := "Iface\tDestination\tGateway\nEth1\t000014AC\t00000000\n"
	if _, err := defaultGatewayFromRouteTable(strings.NewReader(table)); err == nil {
		t.Fatal("want an error: there is no default route")
	}
}

// Loopback, and the host as the published port delivers it, are local. Any
// other address -- another container on the same network included -- is not.
func TestLocalCallersAdmitLoopbackAndTheHostOnly(t *testing.T) {
	local := localCallers{host: net.ParseIP("172.28.0.1")}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"[::1]:1234", true},
		{"172.28.0.1:1234", true},
		{"[::ffff:172.28.0.1]:1234", true},
		{"172.28.0.2:1234", false},
		{"203.0.113.7:1234", false},
		{"not-an-address", false},
		{"", false},
	} {
		if got := local.admits(tc.addr); got != tc.want {
			t.Errorf("admits(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestLocalCallersWithNoKnownHostAdmitOnlyLoopback(t *testing.T) {
	local := localCallers{}
	if !local.admits("127.0.0.1:1") || local.admits("172.28.0.1:1") {
		t.Fatal("with no host address, only loopback is local")
	}
}
