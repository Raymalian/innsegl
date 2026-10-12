// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package client

import (
	"errors"
	"net"
)

// peerUID cannot read a caller's user on this system, so the socket admits
// no one.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("reading a socket peer's user is supported on macOS and Linux only")
}
