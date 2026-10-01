// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

// localCallers decides whether a request to one of the gateway's local-only
// endpoints (/_gateway/session-end, /_gateway/session-workspace) came from
// this machine.
//
// # Why loopback alone is wrong in a container
//
// The gateway's port is published on the host's 127.0.0.1 only (ADR-0060
// decision 2), but a request published that way reaches the container from
// the host side of the container's network, not from loopback: measured
// 2026-10-01, a request from the host arrived as ::ffff:172.28.0.1, the
// default gateway of the network the port is published on. A loopback-only
// check refused every hook the host sent. Another container on that network
// arrives from its own address, so admitting exactly the default gateway
// keeps them out.
type localCallers struct {
	host net.IP // the default route's gateway; nil when unknown
}

// procRouteTable is where Linux states the routing table.
const procRouteTable = "/proc/net/route"

// localCallersFromHost reads the default gateway from the route table. When
// it cannot (not Linux, no default route), only loopback is local -- which
// is right outside a container.
func localCallersFromHost() localCallers {
	f, err := os.Open(procRouteTable)
	if err != nil {
		return localCallers{}
	}
	defer f.Close()
	ip, err := defaultGatewayFromRouteTable(f)
	if err != nil {
		return localCallers{}
	}
	return localCallers{host: ip}
}

// defaultGatewayFromRouteTable answers the gateway of the default route
// (destination 00000000) in /proc/net/route's format: hex, little-endian.
func defaultGatewayFromRouteTable(r io.Reader) (net.IP, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.LittleEndian.Uint32(b))
		if ip.IsUnspecified() {
			continue
		}
		return ip, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the route table has no default route")
}

// admits reports whether remoteAddr (an *http.Request's RemoteAddr) is
// loopback or the host. An address that cannot be parsed is never local.
func (l localCallers) admits(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || (l.host != nil && ip.Equal(l.host))
}
