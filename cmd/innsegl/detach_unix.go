// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package main

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in a session of its own, so it outlives the hook that
// started it and is not stopped with the hook's process group.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
