// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func readProc(pid int) (procInfo, bool) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid {
		return procInfo{}, false
	}
	comm := k.Proc.P_comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	t := k.Proc.P_starttime
	return procInfo{ppid: int(k.Eproc.Ppid), comm: string(comm), start: t.Sec*1_000_000 + int64(t.Usec)}, true
}
