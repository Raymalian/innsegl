// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"strings"
	"testing"
)

func certEnv(v string) func(string) string {
	return func(k string) string {
		if k == gatewayCertNamesEnv {
			return v
		}
		return ""
	}
}

func TestGatewayCertNamesFromEnvValidList(t *testing.T) {
	dns, ips, err := gatewayCertNamesFromEnv(certEnv(" core.example.test , 192.0.2.10,fd00::1,Host-1 "))
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) != 2 || dns[0] != "core.example.test" || dns[1] != "Host-1" {
		t.Errorf("dns = %v", dns)
	}
	if len(ips) != 2 || ips[0].String() != "192.0.2.10" || ips[1].String() != "fd00::1" {
		t.Errorf("ips = %v", ips)
	}
}

func TestGatewayCertNamesFromEnvEmptyAndWhitespace(t *testing.T) {
	for _, v := range []string{"", "   ", " , ,"} {
		dns, ips, err := gatewayCertNamesFromEnv(certEnv(v))
		if err != nil || len(dns) != 0 || len(ips) != 0 {
			t.Errorf("%q: %v %v %v", v, dns, ips, err)
		}
	}
}

func TestGatewayCertNamesFromEnvRefusesInvalidEntries(t *testing.T) {
	for _, v := range []string{"bad name", "http://x.test", "a.test/b", "-a.test", "a..test", "1.2.3", "a.test:443", "*.test", "999.1.1.1"} {
		_, _, err := gatewayCertNamesFromEnv(certEnv(v))
		if err == nil || !strings.Contains(err.Error(), gatewayCertNamesEnv) {
			t.Errorf("%q: err = %v", v, err)
		}
	}
}

// The gateway's CA configuration carries the names from the environment, so
// a core reached by name or address presents a certificate that covers it.
func TestGatewayCAConfigCarriesTheConfiguredNames(t *testing.T) {
	getenv := func(k string) string {
		if k == gatewayCertNamesEnv {
			return "core.example.test, 192.0.2.10"
		}
		return ""
	}
	cfg, err := gatewayCAConfig("/keys", "/public", getenv)
	if err != nil {
		t.Fatalf("gatewayCAConfig: %v", err)
	}
	if cfg.KeyDir != "/keys" || cfg.PublicDir != "/public" {
		t.Errorf("dirs = %q, %q", cfg.KeyDir, cfg.PublicDir)
	}
	if len(cfg.DNSNames) != 1 || cfg.DNSNames[0] != "core.example.test" {
		t.Errorf("DNSNames = %v", cfg.DNSNames)
	}
	if len(cfg.IPs) != 1 || !cfg.IPs[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("IPs = %v", cfg.IPs)
	}
}

func TestGatewayCAConfigRefusesABadName(t *testing.T) {
	getenv := func(k string) string {
		if k == gatewayCertNamesEnv {
			return "http://nope"
		}
		return ""
	}
	if _, err := gatewayCAConfig("/k", "/p", getenv); err == nil {
		t.Fatal("want an error naming the bad entry")
	}
}
