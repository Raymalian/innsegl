// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID is the effective uid of the process at the other end of c, as
// the kernel recorded it when it connected (LOCAL_PEERCRED).
func peerUID(c net.Conn) (int, error) {
	raw, err := rawConn(c)
	if err != nil {
		return -1, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}
