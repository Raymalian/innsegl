// SPDX-License-Identifier: Apache-2.0

// Command innsegl is the single binary for the innsegl backend: the MCP
// server, the reconciler, the segment sealer, the orphan-entry reaper and the
// standalone verification CLI, each selected by subcommand.
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
