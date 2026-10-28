//go:build !unix

// SPDX-License-Identifier: Apache-2.0

package main

import "os/exec"

// Managed Codex setup is currently supported on Unix. On other platforms
// CommandContext and the explicit pipe deadline still bound a direct probe.
func configureCodexProbe(_ *exec.Cmd) {}
