// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// PluginNames are the plugins an identity file's plugin identities run, in
// order, each once: "se" for an AGE-PLUGIN-SE-1… line, run as age-plugin-se.
// Nothing is run to find them.
func PluginNames(r io.Reader) ([]string, error) {
	ids, err := ParseIdentities(r, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, id := range ids {
		if p, ok := id.(*plugin.Identity); ok && !slices.Contains(names, p.Name()) {
			names = append(names, p.Name())
		}
	}
	return names, nil
}

// TerminalUI is a plugin prompt for an interactive command: the plugin's
// messages ("touch your key") and warnings are written to w, one line each,
// and a value it asks for is read from the terminal.
func TerminalUI(w io.Writer) *plugin.ClientUI {
	line := func(format string, v ...any) { _, _ = fmt.Fprintf(w, "innsegl: "+format+"\n", v...) }
	return plugin.NewTerminalUI(line, line)
}

// PluginPin is one age plugin as `innsegl connect` resolved it (#598): the
// plugin's name ("se" for age-plugin-se), the absolute path of the file it
// runs, symlinks resolved, and that file's SHA-256. Every later use runs the
// plugin only while CheckPin still holds.
type PluginPin struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// pluginPins is the pin file's shape.
type pluginPins struct {
	Plugins []PluginPin `json:"plugins"`
}

// PinRepair is what every refusal tells the operator to do.
const PinRepair = "check that it is the plugin you installed, then run `innsegl connect --update` to pin it again"

// PinError is a plugin refused against its pin. Its message names the repair.
type PinError struct {
	Plugin string
	Reason string
}

func (e *PinError) Error() string {
	return fmt.Sprintf("age-plugin-%s refused: %s; %s", e.Plugin, e.Reason, PinRepair)
}

// PinPlugin resolves age-plugin-<name> once, as lookPath finds it (nil is
// this process's PATH), and records its file and hash. A plugin that anyone
// but its owner could replace, or that is owned by neither root nor this
// user, is not pinned.
func PinPlugin(name string, lookPath func(string) (string, error)) (PluginPin, error) {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	found, err := lookPath("age-plugin-" + name)
	if err != nil {
		return PluginPin{}, fmt.Errorf("age-plugin-%s: %w", name, err)
	}
	resolved, err := resolvePlugin(found)
	if err != nil {
		return PluginPin{}, fmt.Errorf("age-plugin-%s: %w", name, err)
	}
	if reason := unsafePlugin(resolved); reason != "" {
		return PluginPin{}, &PinError{Plugin: name, Reason: reason}
	}
	sum, err := fileSHA256(resolved)
	if err != nil {
		return PluginPin{}, fmt.Errorf("age-plugin-%s: %w", name, err)
	}
	return PluginPin{Name: name, Path: resolved, SHA256: sum}, nil
}

// CheckPin runs before the plugin starts, every time. The plugin this
// process's PATH finds (the one age runs) must still be the pinned file;
// the file and its directory must be writable only by their owner, who is
// root or this user; and its hash must be unchanged.
func CheckPin(p PluginPin) error {
	found, err := exec.LookPath("age-plugin-" + p.Name)
	if err != nil {
		return &PinError{Plugin: p.Name, Reason: fmt.Sprintf("it is not on PATH (pinned at %s)", p.Path)}
	}
	resolved, err := resolvePlugin(found)
	if err != nil || resolved != p.Path {
		return &PinError{Plugin: p.Name, Reason: fmt.Sprintf("PATH finds %s, not the pinned %s", found, p.Path)}
	}
	if reason := unsafePlugin(resolved); reason != "" {
		return &PinError{Plugin: p.Name, Reason: reason}
	}
	sum, err := fileSHA256(resolved)
	if err != nil {
		return &PinError{Plugin: p.Name, Reason: err.Error()}
	}
	if sum != p.SHA256 {
		return &PinError{Plugin: p.Name, Reason: fmt.Sprintf("%s has changed since it was pinned (sha256 %s, pinned %s)", resolved, sum, p.SHA256)}
	}
	return nil
}

func resolvePlugin(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// unsafePlugin says why the plugin file at resolved (no symlinks left) or its
// directory could be replaced by someone other than its owner, or is owned
// by neither root nor this user. Empty when neither holds.
func unsafePlugin(resolved string) string {
	for _, p := range []string{resolved, filepath.Dir(resolved)} {
		fi, err := os.Stat(p)
		if err != nil {
			return err.Error()
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Sprintf("%s is writable by group or others (mode %v)", p, fi.Mode().Perm())
		}
		if uid, ok := fileOwner(fi); ok && uid != 0 && uid != os.Getuid() {
			return fmt.Sprintf("%s is owned by uid %d, neither root nor this user", p, uid)
		}
	}
	return ""
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ReadPluginPins reads the pin file connect wrote. A file that does not
// exist pins nothing.
func ReadPluginPins(file string) ([]PluginPin, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust backup: plugin pins: %w", err)
	}
	var v pluginPins
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("trust backup: plugin pins %s: %w", file, err)
	}
	return v.Plugins, nil
}

// WritePluginPins replaces the pin file, 0600.
func WritePluginPins(file string, pins []PluginPin) error {
	raw, err := json.MarshalIndent(pluginPins{Plugins: pins}, "", "  ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// pinnedIdentity runs its plugin only while its pin holds.
type pinnedIdentity struct {
	id  *plugin.Identity
	pin PluginPin
}

func (p pinnedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if err := CheckPin(p.pin); err != nil {
		return nil, err
	}
	return p.id.Unwrap(stanzas)
}

// LoadIdentities reads the identity file at path. Each plugin identity in it
// runs its plugin only as pinned in pinFile (CLI-046, CLI-047, #598): one
// with no pin, or whose pin no longer holds, is refused here and again each
// time it is used. An X25519 key needs no pin.
func LoadIdentities(path string, ui *plugin.ClientUI, pinFile string) ([]age.Identity, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the identity file
	if err != nil {
		return nil, fmt.Errorf("trust backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	ids, err := ParseIdentities(f, ui)
	if err != nil {
		return nil, err
	}
	var pins []PluginPin
	if pinFile != "" {
		if pins, err = ReadPluginPins(pinFile); err != nil {
			return nil, err
		}
	}
	for i, id := range ids {
		p, ok := id.(*plugin.Identity)
		if !ok {
			continue
		}
		at := slices.IndexFunc(pins, func(q PluginPin) bool { return q.Name == p.Name() })
		if at < 0 {
			return nil, &PinError{Plugin: p.Name(), Reason: "it was never pinned"}
		}
		if err := CheckPin(pins[at]); err != nil {
			return nil, err
		}
		ids[i] = pinnedIdentity{id: p, pin: pins[at]}
	}
	return ids, nil
}
