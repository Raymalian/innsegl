// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// ParseIdentities reads an age identity file: one identity per line, blank
// lines and # comments ignored. An X25519 key opens a bundle in process; a
// plugin identity (AGE-PLUGIN-…) runs its plugin, which for a Secure Enclave
// key asks for Touch ID. ui is the plugin's prompt; nil is a terminal.
func ParseIdentities(r io.Reader, ui *plugin.ClientUI) ([]age.Identity, error) {
	if ui == nil {
		ui = plugin.NewTerminalUI(func(string, ...any) {}, func(string, ...any) {})
	}
	var out []age.Identity
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var id age.Identity
		var err error
		switch {
		case strings.HasPrefix(line, "AGE-PLUGIN-"):
			id, err = plugin.NewIdentity(line, ui)
		default:
			id, err = age.ParseX25519Identity(line)
		}
		if err != nil {
			return nil, fmt.Errorf("trust backup: identity line %d: %w", n, err)
		}
		out = append(out, id)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trust backup: identities: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("trust backup: the identity file holds no identity")
	}
	return out, nil
}

// LoadIdentities reads the identity file at path.
func LoadIdentities(path string, ui *plugin.ClientUI) ([]age.Identity, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the identity file
	if err != nil {
		return nil, fmt.Errorf("trust backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	return ParseIdentities(f, ui)
}
