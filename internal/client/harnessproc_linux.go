// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"strconv"
	"strings"
)

// readProc reads /proc/<pid>/stat: the name between the parentheses, then
// the parent pid (field 4) and the start time in clock ticks (field 22).
func readProc(pid int) (procInfo, bool) {
	// #nosec G304 -- a path built from a pid.
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procInfo{}, false
	}
	s := string(b)
	open, closing := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closing < open {
		return procInfo{}, false
	}
	fields := strings.Fields(s[closing+1:])
	if len(fields) < 20 {
		return procInfo{}, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return procInfo{}, false
	}
	start, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return procInfo{}, false
	}
	return procInfo{ppid: ppid, comm: s[open+1 : closing], start: start}, true
}
