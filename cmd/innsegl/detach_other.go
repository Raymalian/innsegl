// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package main

import "os/exec"

// detach does nothing here: the process is started and not waited for.
func detach(*exec.Cmd) {}
