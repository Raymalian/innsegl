// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Process names one running process: its pid and its start time, so a pid
// the system reused for another program never reads as the same one.
type Process struct {
	PID   int   `json:"pid"`
	Start int64 `json:"start"`
}

// procInfo is what this package reads about a process (harnessproc_*.go).
type procInfo struct {
	ppid  int
	comm  string
	start int64
}

// ProcessOf reads the running process with this pid.
func ProcessOf(pid int) (Process, bool) {
	info, ok := readProc(pid)
	if !ok {
		return Process{}, false
	}
	return Process{PID: pid, Start: info.start}, true
}

// Alive reports whether p is still running: the same pid, started at the
// same time.
func (p Process) Alive() bool {
	now, ok := ProcessOf(p.PID)
	return ok && now.Start == p.Start
}

// shells run a hook command for the harness; the harness is the first
// ancestor that is not one.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true, "ksh": true}

// HarnessProcess is the process that ran this hook: Claude Code itself,
// found as the first ancestor that is not a shell.
func HarnessProcess() (Process, bool) {
	pid := os.Getppid()
	for range 16 {
		if pid <= 1 {
			return Process{}, false
		}
		info, ok := readProc(pid)
		if !ok {
			return Process{}, false
		}
		if !shells[strings.TrimPrefix(info.comm, "-")] {
			return Process{PID: pid, Start: info.start}, true
		}
		pid = info.ppid
	}
	return Process{}, false
}

// HarnessProcessQuery is how the session hook names its harness to the
// client, on the session statement's URL. The client keeps it and never
// forwards it.
func HarnessProcessQuery(p Process) string {
	return fmt.Sprintf("harness_pid=%d&harness_start=%d", p.PID, p.Start)
}

func harnessProcessFrom(q url.Values) (Process, bool) {
	pid, err := strconv.Atoi(q.Get("harness_pid"))
	if err != nil || pid <= 1 {
		return Process{}, false
	}
	start, err := strconv.ParseInt(q.Get("harness_start"), 10, 64)
	if err != nil || start <= 0 {
		return Process{}, false
	}
	return Process{PID: pid, Start: start}, true
}
