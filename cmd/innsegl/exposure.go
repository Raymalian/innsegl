// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"strings"
)

const (
	envBind             = "INNSEGL_BIND"
	envGatewayClientAut = "INNSEGL_GATEWAY_CLIENT_AUTH"
	clientAuthSPIFFE    = "spiffe"
)

// checkGatewayExposure refuses a gateway that the deployment publishes beyond
// loopback while the gateway does not authenticate its clients. $INNSEGL_BIND
// unset or loopback is always fine; any other address needs
// $INNSEGL_GATEWAY_CLIENT_AUTH=spiffe.
func checkGatewayExposure(getenv func(string) string) error {
	bind := strings.TrimSpace(getenv(envBind))
	if bind == "" || bindIsLoopback(bind) {
		return nil
	}
	if strings.TrimSpace(getenv(envGatewayClientAut)) == clientAuthSPIFFE {
		return nil
	}
	return fmt.Errorf("the gateway would be reachable from the network without client authentication: "+
		"%s=%q is not a loopback address and %s is not %q; set %s=%s or unset %s",
		envBind, bind, envGatewayClientAut, clientAuthSPIFFE,
		envGatewayClientAut, clientAuthSPIFFE, envBind)
}

// bindIsLoopback reports whether a bind address is 127.0.0.0/8, ::1 or
// localhost. An address that does not parse is not loopback.
func bindIsLoopback(bind string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(bind, "["), "]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
