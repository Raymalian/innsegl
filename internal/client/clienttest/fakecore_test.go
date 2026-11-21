// SPDX-License-Identifier: Apache-2.0

package clienttest

import (
	"net"
	"testing"
)

func TestOutageKeepsCorePortReserved(t *testing.T) {
	core, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	core.Stop()

	var listen net.ListenConfig
	competing, err := listen.Listen(t.Context(), "tcp", core.HostPort())
	if err == nil {
		_ = competing.Close()
		t.Fatal("another listener claimed the core's address during the outage")
	}
}
