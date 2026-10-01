// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"strings"

	"innsegl.dev/innsegl/internal/gateway"
)

// gatewayCertNamesEnv lists extra names the gateway's server certificate
// covers: comma-separated, each an IP address or a DNS name.
const gatewayCertNamesEnv = "INNSEGL_GATEWAY_CERT_NAMES"

// gatewayCertNamesFromEnv parses gatewayCertNamesEnv. Empty entries are
// skipped; any entry that is neither an IP nor a valid DNS name is an error.
func gatewayCertNamesFromEnv(getenv func(string) string) (dnsNames []string, ips []net.IP, err error) {
	for _, raw := range strings.Split(getenv(gatewayCertNamesEnv), ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !validDNSName(entry) {
			return nil, nil, fmt.Errorf("%s: %q is neither an IP address nor a DNS name", gatewayCertNamesEnv, entry)
		}
		dnsNames = append(dnsNames, entry)
	}
	return dnsNames, ips, nil
}

// validDNSName accepts dot-separated labels of letters, digits and hyphens,
// each 1-63 characters and not starting or ending with a hyphen, with a
// total length of at most 253. An all-numeric dotted string is rejected: it
// is a malformed IP, not a name.
func validDNSName(s string) bool {
	if len(s) > 253 {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= '0' && r <= '9':
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-':
				allNumeric = false
			default:
				return false
			}
		}
	}
	return !allNumeric
}

// gatewayCAConfig is the gateway's CA configuration: its key and public
// directories, and the names its server certificate must cover beyond
// loopback, from INNSEGL_GATEWAY_CERT_NAMES. A core reached by name or
// address (ADR-0066) sets that variable; a single-host install leaves it
// empty.
func gatewayCAConfig(keyDir, publicDir string, getenv func(string) string) (gateway.CAConfig, error) {
	dnsNames, ips, err := gatewayCertNamesFromEnv(getenv)
	if err != nil {
		return gateway.CAConfig{}, err
	}
	return gateway.CAConfig{KeyDir: keyDir, PublicDir: publicDir, DNSNames: dnsNames, IPs: ips}, nil
}
