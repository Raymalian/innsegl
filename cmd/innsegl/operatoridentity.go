// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// operatorIdentities loads the operator's age identity file for an
// interactive command. A plugin identity's own prompts ("touch your key")
// are written to w, the person's terminal (BAK-031, #592). A plugin runs
// only as `innsegl connect` pinned it in this user's client folder (#598).
func operatorIdentities(path string, w io.Writer) func() ([]age.Identity, error) {
	return func() ([]age.Identity, error) {
		pins := ""
		if home, err := os.UserHomeDir(); err == nil {
			pins = client.PluginPinsFile(client.ClientPaths(home))
		}
		return trustbackup.LoadIdentities(path, trustbackup.TerminalUI(w), pins)
	}
}
