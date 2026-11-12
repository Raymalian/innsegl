// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const codexManagedBegin = "# BEGIN INNSEGL CODEX\n"
const codexManagedEnd = "# END INNSEGL CODEX\n"

// CodexManagedPath is the system managed-defaults path on supported Unix hosts.
func CodexManagedPath(goos string) string {
	if goos == "darwin" || goos == "linux" {
		return "/etc/codex/managed_config.toml"
	}
	return ""
}

// CodexManagedActive distinguishes installed routing from an absent or paused
// block, so the optional launcher cannot inject duplicate managed hooks.
func CodexManagedActive(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	text, err := readCodexManaged(path)
	if err != nil {
		return false, err
	}
	_, block, err := splitCodexManaged(text)
	return len(block) > 0 && !bytes.HasPrefix(block, []byte("# paused: ")), err
}

// CodexManagedConfig configures ordinary Codex launches in the system
// managed layer. Authentication and personal configuration stay with Codex.
type CodexManagedConfig struct {
	LocalURL string
	HookBin  string
	API      bool
	Signing  bool
}

// CodexManagedTOML is the one settings contract used by installation and
// effective-configuration verification, derived from the existing launcher.
func CodexManagedTOML(cfg CodexManagedConfig) ([]byte, error) {
	args, err := CodexThreadLaunchArgs(cfg.LocalURL, cfg.HookBin, cfg.API, cfg.Signing)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			b.WriteString(args[i])
			b.WriteByte('\n')
		}
	}
	return []byte(b.String()), nil
}

// CodexManagedMode preserves explicit route and signing choices on update.
func CodexManagedMode(path string) (api, signing bool, err error) {
	text, err := readCodexManaged(path)
	if err != nil {
		return false, false, err
	}
	_, block, err := splitCodexManaged(text)
	if err != nil || len(block) == 0 {
		return false, false, err
	}
	block = unpauseCodexBlock(block)
	var cfg struct {
		Providers map[string]struct {
			BaseURL string `toml:"base_url"`
		} `toml:"model_providers"`
		Hooks map[string]any `toml:"hooks"`
	}
	if err := toml.Unmarshal(block, &cfg); err != nil {
		return false, false, fmt.Errorf("invalid Innsegl Codex settings")
	}
	_, signing = cfg.Hooks["PreToolUse"]
	return strings.HasSuffix(cfg.Providers["innsegl"].BaseURL, "/v1"), signing, nil
}

func readCodexManaged(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	text, err := os.ReadFile(path) // #nosec G304 -- the system configuration path selected by setup.
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if toml.Unmarshal(text, &cfg) != nil {
		return nil, fmt.Errorf("%s is not valid TOML; refusing to touch it", path)
	}
	return text, nil
}

func splitCodexManaged(text []byte) (rest, block []byte, err error) {
	begin, end := bytes.Count(text, bytes.TrimSpace([]byte(codexManagedBegin))), bytes.Count(text, bytes.TrimSpace([]byte(codexManagedEnd)))
	if begin == 0 && end == 0 {
		return text, nil, nil
	}
	if begin != 1 || end != 1 || !bytes.HasPrefix(text, []byte(codexManagedBegin)) || !bytes.Contains(text, []byte(codexManagedEnd)) {
		return nil, nil, fmt.Errorf("ambiguous Innsegl Codex settings markers; refusing to touch them")
	}
	i := bytes.Index(text, []byte(codexManagedEnd))
	if i < len(codexManagedBegin) {
		return nil, nil, fmt.Errorf("invalid Innsegl Codex settings markers")
	}
	return text[i+len(codexManagedEnd):], text[len(codexManagedBegin):i], nil
}

func planCodexSettings(path string, cfg CodexManagedConfig, install bool) ([]byte, bool, error) {
	old, err := readCodexManaged(path)
	if err != nil {
		return nil, false, err
	}
	rest, _, err := splitCodexManaged(old)
	if err != nil {
		return nil, false, err
	}
	next := rest
	if install {
		settings, err := CodexManagedTOML(cfg)
		if err != nil {
			return nil, false, err
		}
		var b strings.Builder
		b.WriteString(codexManagedBegin)
		b.Write(settings)
		b.WriteString(codexManagedEnd)
		next = append([]byte(b.String()), rest...)
		var parsed map[string]any
		if toml.Unmarshal(next, &parsed) != nil {
			return nil, false, fmt.Errorf("%s has administrator settings that overlap Codex setup; refusing to overwrite them", path)
		}
	}
	return next, !bytes.Equal(old, next), nil
}

// ValidateCodexSettings checks ownership, syntax and conflicts without staging
// active settings before the enrolled client has negotiated gateway support.
func ValidateCodexSettings(path string, cfg CodexManagedConfig) error {
	_, _, err := planCodexSettings(path, cfg, true)
	return err
}

// CheckCodexSettingsWritable stages a hash-checked administrator install
// before enrollment, without spending a token or changing the target file.
func CheckCodexSettingsWritable(path string, cfg CodexManagedConfig, install bool) error {
	next, changed, err := planCodexSettings(path, cfg, install)
	if err != nil || !changed || writable(path) {
		return err
	}
	return stageForAdmin(path, next)
}

func InstallCodexSettings(path string, cfg CodexManagedConfig, now func() time.Time, out io.Writer) error {
	return applyCodexSettings(path, cfg, true, now, out)
}

// UninstallCodexSettings removes only the owned block. The same operation
// pauses capture; Resume reinstalls it from the saved managed mode.
func UninstallCodexSettings(path string, now func() time.Time, out io.Writer) error {
	return applyCodexSettings(path, CodexManagedConfig{}, false, now, out)
}

func applyCodexSettings(path string, cfg CodexManagedConfig, install bool, now func() time.Time, out io.Writer) error {
	next, changed, err := planCodexSettings(path, cfg, install)
	if err != nil {
		return err
	}
	return writeCodexSettings(path, next, changed, now, out)
}

func planCodexPause(path string, paused bool) ([]byte, bool, error) {
	old, err := readCodexManaged(path)
	if err != nil {
		return nil, false, err
	}
	rest, block, err := splitCodexManaged(old)
	if err != nil || len(block) == 0 {
		return old, false, err
	}
	block = unpauseCodexBlock(block)
	if paused {
		block = []byte("# paused: " + strings.ReplaceAll(strings.TrimSuffix(string(block), "\n"), "\n", "\n# paused: ") + "\n")
	}
	next := append([]byte(codexManagedBegin), block...)
	next = append(next, []byte(codexManagedEnd)...)
	next = append(next, rest...)
	return next, !bytes.Equal(old, next), nil
}

func unpauseCodexBlock(block []byte) []byte {
	lines := bytes.Split(block, []byte("\n"))
	for i := range lines {
		lines[i] = bytes.TrimPrefix(lines[i], []byte("# paused: "))
	}
	return bytes.Join(lines, []byte("\n"))
}

// CheckCodexPauseWritable preflights both harnesses before either is paused.
func CheckCodexPauseWritable(path string, paused bool) error {
	next, changed, err := planCodexPause(path, paused)
	if err != nil || !changed || writable(path) {
		return err
	}
	return stageForAdmin(path, next)
}

// PauseCodexSettings comments only Innsegl's block. Administrator settings
// remain active, and resuming restores the exact previous mode.
func PauseCodexSettings(path string, paused bool, now func() time.Time, out io.Writer) error {
	next, changed, err := planCodexPause(path, paused)
	if err != nil {
		return err
	}
	return writeCodexSettings(path, next, changed, now, out)
}

func writeCodexSettings(path string, next []byte, changed bool, now func() time.Time, out io.Writer) error {
	if !changed {
		fmt.Fprintf(out, "innsegl: Codex managed settings %s already up to date\n", path)
		return nil
	}
	if !writable(path) {
		return stageForAdmin(path, next)
	}
	old, err := readCodexManaged(path)
	if err != nil {
		return err
	}
	if len(old) > 0 {
		backup, backupErr := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".bak."+now().UTC().Format("20060102T150405Z")+"-*")
		if backupErr != nil {
			return backupErr
		}
		_, writeErr := backup.Write(old)
		closeErr := backup.Close()
		if backupErr := errors.Join(writeErr, closeErr); backupErr != nil {
			return backupErr
		}
	}
	if err := writeFileAtomic(path, next, 0644); err != nil {
		return err
	}
	fmt.Fprintf(out, "innsegl: updated Codex managed settings %s\n", path)
	return nil
}
