// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// The rights innsegl holds on this machine (#596, privilege review D10, D11,
// D18): every path innsegl hands to something that runs unattended — the
// managed-settings hooks, the client service, the git hooks — must name this
// binary, and a file the user cannot change. doctor reports each one that
// does not with the command that repairs it, and never repairs it itself:
// the managed settings belong to an administrator (CLI-037). The one change
// it makes is tightening the modes of innsegl's own key files (CLI-039).

// agePluginProtocol is how the age library starts a plugin to open a file.
const agePluginProtocol = "--age-plugin=identity-v1"

// doctorAgePlugins are the plugins an identity may name for the CA unlock:
// the Secure Enclave and a YubiKey.
var doctorAgePlugins = []string{"se", "yubikey"}

// argSlot in an allow-list entry matches one non-empty argument: the
// repository given to `git -C`, which takes it as a directory whatever it
// says.
const argSlot = "\x00"

// doctorReadOnlyList is what doctor's checks run: git's version, the two
// rev-parse reads that find a repository's hooks, and an age plugin opening
// the CA's unlock material. None of them changes anything.
func doctorReadOnlyList() [][]string {
	l := [][]string{
		{"git", "--version"},
		{"git", "-C", argSlot, "rev-parse", "--path-format=absolute", "--git-common-dir"},
	}
	for _, h := range managedHooks {
		l = append(l, []string{"git", "-C", argSlot, "rev-parse", "--git-path", "hooks/" + h.name})
	}
	for _, p := range doctorAgePlugins {
		l = append(l, []string{"age-plugin-" + p, agePluginProtocol})
	}
	return l
}

func argvMatches(pattern, argv []string) bool {
	if len(pattern) != len(argv) {
		return false
	}
	for i, p := range pattern {
		if p == argSlot {
			if argv[i] == "" {
				return false
			}
			continue
		}
		if p != argv[i] {
			return false
		}
	}
	return true
}

// doctorReadOnly says argv is one of the checks' read-only commands.
func doctorReadOnly(argv []string) bool {
	return slices.ContainsFunc(doctorReadOnlyList(), func(p []string) bool { return argvMatches(p, argv) })
}

// doctorCommandAllowed is the allow-list (CLI-038): the client service
// restart for this user on this system, which is the one repair doctor
// runs, and the read-only commands its checks need. Nothing else.
func doctorCommandAllowed(goos string, uid int, argv []string) bool {
	return slices.Equal(argv, doctorRestartArgv(goos, uid)) || doctorReadOnly(argv)
}

// permitPlugins checks, before the unlock, that every plugin the identity
// file names is on the allow-list: the age library runs it, so the gate is
// here. An identity doctor cannot read is the unlock's to report.
func (d *doctor) permitPlugins() error {
	f, err := os.Open(d.identity)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	names, err := trustbackup.PluginNames(f)
	if err != nil {
		return nil
	}
	for _, n := range names {
		if err := d.permit([]string{"age-plugin-" + n, agePluginProtocol}); err != nil {
			return fmt.Errorf("the identity file %s names age-plugin-%s: %w", d.identity, n, err)
		}
	}
	return nil
}

// gitCommonDir answers whether repo is a git repository, through the
// allow-list.
func (d *doctor) gitCommonDir(ctx context.Context, repo string) error {
	ctx, cancel := context.WithTimeout(ctx, gitCommonDirTimeout)
	defer cancel()
	out, err := d.exec(ctx, []string{"git", "-C", repo, "rev-parse", "--path-format=absolute", "--git-common-dir"})
	if err != nil {
		return err
	}
	if p := strings.TrimSpace(string(out)); p == "" || !filepath.IsAbs(p) {
		return errors.New("git named no absolute common directory")
	}
	return nil
}

// hookScript is one of innsegl's git hooks in a repository, and the binary
// it runs.
type hookScript struct {
	name, path, bin string
}

// managedHook reads repo's hook h, located through the allow-list, and
// reports whether it is innsegl's.
func (d *doctor) managedHook(ctx context.Context, repo string, h managedHook) (hookScript, bool) {
	ctx, cancel := context.WithTimeout(ctx, gitCommonDirTimeout)
	defer cancel()
	out, err := d.exec(ctx, []string{"git", "-C", repo, "rev-parse", "--git-path", "hooks/" + h.name})
	if err != nil {
		return hookScript{}, false
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return hookScript{}, false
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(repo, p)
	}
	// #nosec G304 -- the hook path git itself resolved for this repository.
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), h.marker) {
		return hookScript{}, false
	}
	return hookScript{name: h.name, path: p, bin: hookScriptBin(string(b))}, true
}

// hookScriptBin is the binary an innsegl git hook runs: the single-quoted
// word right before " git-hook " (shellQuoteSingle, link.go).
func hookScriptBin(script string) string {
	for _, line := range strings.Split(script, "\n") {
		end := strings.Index(line, " git-hook ")
		if end < 0 {
			continue
		}
		for i := 0; i < end; i++ {
			if line[i] != '\'' {
				continue
			}
			if v, n, ok := parseSingleQuoted(line[i:]); ok && i+n == end {
				return v
			}
		}
	}
	return ""
}

// parseSingleQuoted reads one POSIX single-quoted word at the start of s,
// with the close-escape-reopen form for a quote inside it.
func parseSingleQuoted(s string) (val string, n int, ok bool) {
	if !strings.HasPrefix(s, "'") {
		return "", 0, false
	}
	var b strings.Builder
	i := 1
	for {
		j := strings.IndexByte(s[i:], '\'')
		if j < 0 {
			return "", 0, false
		}
		b.WriteString(s[i : i+j])
		i += j + 1
		if strings.HasPrefix(s[i:], `\''`) {
			b.WriteByte('\'')
			i += 3
			continue
		}
		return b.String(), i, true
	}
}

// hookBinaries reports the git hooks of repo that run another binary, or
// one the user can change; true when there is none.
func (d *doctor) hookBinaries(repo string, scripts []hookScript) bool {
	byBin := map[string][]string{}
	for _, s := range scripts {
		byBin[s.bin] = append(byBin[s.bin], s.name)
	}
	clean := true
	for _, bin := range sortedKeys(byBin) {
		names := strings.Join(byBin[bin], ", ")
		state, why := d.binary(bin)
		switch state {
		case "":
			continue
		case "WRITABLE":
			d.line("hooks", state, fmt.Sprintf("%s %s runs %s, which you can change: %s; %s",
				repo, names, bin, why, doctorInstallAdvice))
		default:
			d.line("hooks", state, fmt.Sprintf("%s %s runs %s: %s; run: innsegl link %s", repo, names, bin, why, repo))
		}
		clean = false
	}
	return clean
}

// doctorInstallAdvice is the repair for a binary the user can change.
const doctorInstallAdvice = "install this build as the root-owned copy the hooks and the service run (#599): " +
	"make install-release (in the innsegl checkout), then run: innsegl connect --update"

// self is this binary's resolved path.
func (d *doctor) self() string {
	if d.deps.self != "" {
		return d.deps.self
	}
	p, err := innseglBinaryPath()
	if err != nil {
		return ""
	}
	d.deps.self = p
	return p
}

// binary checks a path innsegl hands to something that runs it: it exists,
// it is this binary, and the user cannot change it. An empty state is ok.
func (d *doctor) binary(bin string) (state, why string) {
	if bin == "" {
		return "UNKNOWN", "no binary could be read from it"
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "MISSING", bin + " does not exist"
	}
	if self := d.self(); resolved != self && !sameContent(resolved, self) {
		return "FOREIGN", "not this binary (" + self + ")"
	}
	if why := userWritable(resolved, d.deps.uid); why != "" {
		return "WRITABLE", why
	}
	return "", ""
}

// sameContent says a and b hold the same bytes: a copy of this binary is
// this binary.
func sameContent(a, b string) bool {
	ha, okA := fileHash(a)
	hb, okB := fileHash(b)
	return okA && okB && ha == hb
}

func fileHash(p string) ([sha256.Size]byte, bool) {
	// #nosec G304 G703 -- a binary path innsegl wrote into a hook or service; only hashed.
	f, err := os.Open(p)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [sha256.Size]byte{}, false
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

// userWritable says why uid can replace the file at p (resolved), or ""
// when it cannot: it owns the file or a folder above it, or one of them is
// group- or world-writable. A sticky folder (/tmp) lets no one replace
// another's entry, so only its entries' owners count.
func userWritable(p string, uid int) string {
	for cur := p; ; cur = filepath.Dir(cur) {
		fi, err := os.Lstat(cur) // #nosec G703 -- only its owner and mode are read
		if err != nil {
			return "cannot read " + cur + ": " + err.Error()
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == uid {
			return fmt.Sprintf("you own %s (mode %04o)", cur, fi.Mode().Perm())
		}
		perm := fi.Mode().Perm()
		sticky := fi.IsDir() && fi.Mode()&os.ModeSticky != 0
		switch {
		case sticky:
		case perm&0o002 != 0:
			return fmt.Sprintf("%s is world-writable (mode %04o)", cur, perm)
		case perm&0o020 != 0:
			return fmt.Sprintf("%s is group-writable (mode %04o)", cur, perm)
		}
		if parent := filepath.Dir(cur); parent == cur {
			return ""
		}
	}
}

// rights runs the checks of what innsegl holds on this machine: the
// managed-settings hooks, the client service's binary, and the modes of
// innsegl's own files.
func (d *doctor) rights() {
	d.managedSettings()
	d.serviceBinary()
	d.tightenModes()
}

// doctorSessionEvents are the events connect installs `innsegl hook
// session` on (sessionHookEvents in internal/client/settings.go).
var doctorSessionEvents = []string{"SessionStart", "UserPromptSubmit", "SubagentStart", "CwdChanged",
	"SessionEnd", "SubagentStop"}

// doctorHookKinds is the innsegl hook each event must run once.
func doctorHookKinds() map[string]string {
	m := map[string]string{"PreToolUse": "pre-tool-use", "PostToolUse": "post-tool-use"}
	for _, ev := range doctorSessionEvents {
		m[ev] = "session"
	}
	return m
}

// innseglHookCommand reads a hook command as `<bin> hook <kind>`.
func innseglHookCommand(cmd string) (bin, kind string, ok bool) {
	f := strings.Fields(cmd)
	if len(f) != 3 || f[1] != "hook" {
		return "", "", false
	}
	switch f[2] {
	case "pre-tool-use", "post-tool-use", "session":
		return f[0], f[2], true
	}
	return "", "", false
}

// managedSettingsFile is the part of the managed settings doctor reads.
type managedSettingsFile struct {
	Hooks map[string][]struct {
		Hooks []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	} `json:"hooks"`
}

// managedSettings checks every innsegl hook in the managed settings (D10):
// each event has exactly one, and each names this binary at a path the
// user cannot change. It reads the file and changes nothing: the repair,
// `innsegl connect --update`, needs an administrator.
func (d *doctor) managedSettings() {
	const check = "managed settings"
	const repair = "run: innsegl connect --update"
	b, err := os.ReadFile(d.settings)
	if err != nil {
		d.line(check, "MISSING", fmt.Sprintf("%v; %s", err, repair))
		return
	}
	var ms managedSettingsFile
	if err := json.Unmarshal(b, &ms); err != nil {
		d.line(check, "UNREADABLE", fmt.Sprintf("%s: %v", d.settings, err))
		return
	}
	kinds := doctorHookKinds()
	bins := map[string][]string{}
	var missing []string
	clean := true
	for _, ev := range sortedKeys(kinds) {
		n := 0
		for _, g := range ms.Hooks[ev] {
			for _, h := range g.Hooks {
				bin, kind, ok := innseglHookCommand(h.Command)
				if !ok || h.Type != "command" {
					continue
				}
				if !slices.Contains(bins[bin], ev) {
					bins[bin] = append(bins[bin], ev)
				}
				if kind == kinds[ev] {
					n++
				}
			}
		}
		switch {
		case n == 0:
			missing = append(missing, ev)
		case n > 1:
			d.line(check, "DUPLICATE", fmt.Sprintf("%s runs innsegl's hook %d times; %s", ev, n, repair))
			clean = false
		}
	}
	if len(missing) > 0 {
		d.line(check, "MISSING", fmt.Sprintf("%s has no innsegl hook for %s; %s",
			d.settings, strings.Join(missing, ", "), repair))
		clean = false
	}
	for _, bin := range sortedKeys(bins) {
		state, why := d.binary(bin)
		switch state {
		case "":
			continue
		case "WRITABLE":
			d.line(check, state, fmt.Sprintf("hooks run %s, which you can change: %s; %s", bin, why, doctorInstallAdvice))
		default:
			d.line(check, state, fmt.Sprintf("%s runs %s: %s; %s from the binary the hooks should run",
				strings.Join(bins[bin], ", "), bin, why, repair))
		}
		clean = false
	}
	if clean {
		d.line(check, "ok", "every innsegl hook runs "+d.self())
	}
}

var plistProgram = regexp.MustCompile(`<key>ProgramArguments</key>\s*<array>\s*<string>([^<]*)</string>`)

// serviceProgram is the binary a client service definition starts.
func serviceProgram(goos string, def []byte) string {
	if goos == "darwin" {
		m := plistProgram.FindSubmatch(def)
		if m == nil {
			return ""
		}
		return html.UnescapeString(string(m[1]))
	}
	for _, line := range strings.Split(string(def), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		if !strings.HasPrefix(rest, `"`) {
			f := strings.Fields(rest)
			if len(f) == 0 {
				return ""
			}
			return f[0]
		}
		var b strings.Builder
		for i := 1; i < len(rest); i++ {
			c := rest[i]
			switch {
			case c == '"':
				return b.String()
			case c == '\\' && i+1 < len(rest):
				i++
				b.WriteByte(rest[i])
			case (c == '%' || c == '$') && i+1 < len(rest) && rest[i+1] == c:
				i++
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		}
		return ""
	}
	return ""
}

// serviceBinary checks the binary the client service starts (D11).
func (d *doctor) serviceBinary() {
	const check = "service binary"
	path := client.Service{GOOS: d.deps.goos, Home: d.deps.home}.Path()
	if path == "" {
		return
	}
	def, err := os.ReadFile(path) // #nosec G304 -- the service definition connect writes
	if err != nil {
		d.line(check, "not checked", "no client service definition at "+path)
		return
	}
	bin := serviceProgram(d.deps.goos, def)
	state, why := d.binary(bin)
	switch state {
	case "":
		d.line(check, "ok", bin)
	case "WRITABLE":
		d.line(check, state, fmt.Sprintf("%s starts %s, which you can change: %s; %s", path, bin, why,
			doctorInstallAdvice+" --service"))
	default:
		d.line(check, state, fmt.Sprintf("%s starts %s: %s; run: innsegl connect --update --service", path, bin, why))
	}
}

// tightenedMode is m less every group and other bit: never a bit added.
func tightenedMode(m os.FileMode) os.FileMode { return m.Perm() &^ 0o077 }

// innseglPrivatePaths are innsegl's own folders and files that hold keys
// and must be the user's alone (D18). Public certificates are not on it.
func (d *doctor) innseglPrivatePaths() []string {
	p := d.paths
	out := []string{p.Dir, p.Outbox, p.TrustBackups, filepath.Dir(p.TrustIdentity),
		p.Key, p.ProxyCAKey, p.TrustIdentity, p.Authors}
	if backups, err := filepath.Glob(filepath.Join(p.TrustBackups, "*.age")); err == nil {
		out = append(out, backups...)
	}
	return out
}

// tightenModes removes group and other access from innsegl's own private
// files (CLI-039): only those, only ones the user owns, never through a
// symlink, and never adding a bit.
func (d *doctor) tightenModes() {
	const check = "modes"
	changed := false
	for _, p := range d.innseglPrivatePaths() {
		from, to, err := tightenOne(p, d.deps.uid)
		switch {
		case err != nil:
			d.line(check, "NOT REPAIRED", fmt.Sprintf("%s: %v", p, err))
			changed = true
		case from != to:
			d.line(check, "tightened", fmt.Sprintf("%s %04o → %04o", p, from, to))
			changed = true
		}
	}
	if !changed {
		d.line(check, "ok", "innsegl's own key files are yours alone")
	}
}

// tightenOne tightens one path, opened without following a symlink, and
// returns its mode before and after. A path that is absent, a symlink, not
// the user's or unreadable is left as it is.
func tightenOne(p string, uid int) (from, to os.FileMode, err error) {
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || (!fi.Mode().IsRegular() && !fi.IsDir()) {
		return 0, 0, nil
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- innsegl's own file
	if err != nil {
		return 0, 0, nil
	}
	defer func() { _ = f.Close() }()
	fi, err = f.Stat()
	if err != nil {
		return 0, 0, nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		return 0, 0, nil
	}
	from = fi.Mode().Perm()
	to = tightenedMode(from)
	if to == from {
		return from, to, nil
	}
	if err := f.Chmod(to); err != nil {
		return from, from, err
	}
	return from, to, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
