// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// operatorIdentities loads the operator's age identity file for an
// interactive command. A plugin identity's own prompts ("touch your key")
// are written to w, the person's terminal (BAK-031, #592).
func operatorIdentities(path string, w io.Writer) func() ([]age.Identity, error) {
	return func() ([]age.Identity, error) {
		return trustbackup.LoadIdentities(path, trustbackup.TerminalUI(w))
	}
}
