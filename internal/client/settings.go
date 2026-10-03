// SPDX-License-Identifier: Apache-2.0

// Package client is the client half of the hosted core (ADR-0063): the
// files an enrolled machine holds, the Claude Code managed settings that
// point the harness at the local endpoint, the user-level service that runs
// that endpoint, and the endpoint itself — a reverse proxy to the core over
// the machine's client certificate, renewed at half-life.
package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// SettingsConfig is what the managed settings name.
type SettingsConfig struct {
	// HookBin is the absolute path of the innsegl binary the hooks run.
	HookBin string
	// LocalURL is the client service's loopback endpoint, http://<listen>.
	LocalURL string
	// ProxyCA is the client's proxy CA certificate (Paths.ProxyCA), which
	// NODE_EXTRA_CA_CERTS names (RM-329).
	ProxyCA string
	// LogDeny is the directory a sandboxed shell may not read (~/.innsegl).
	LogDeny string
	// CAAllow is the one directory under it the shell may read
	// (~/.innsegl/ca).
	CAAllow string
	// Hardened adds the machine lockdown on top of the route and the hooks
	// (RM-312): allowManagedHooksOnly, bypass mode disabled, and the
	// sandbox. Without it the client writes the route and its own hooks
	// only, and removes any lockdown keys an earlier version wrote.
	Hardened bool
	// StatusLine is the user's own statusLine from ~/.claude/settings.json
	// (nil when there is none). Under allowManagedHooksOnly the harness runs
	// no statusLine command but a managed one, so --hardened copies it into
	// the managed settings; otherwise a managed statusLine equal to it is
	// that copy, and is removed.
	StatusLine any
}

// ReadStatusLine returns the statusLine value in the user settings file at
// path, or nil when the file or the key is absent.
func ReadStatusLine(path string) (any, error) {
	// #nosec G304 -- path is the user's own Claude Code settings file.
	text, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if strings.TrimSpace(string(text)) == "" {
		return nil, nil
	}
	obj, err := parseObject(text)
	if err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", path, err)
	}
	line, _ := obj.get("statusLine")
	return line, nil
}

type envVar struct{ key, val string }

// noProxy keeps loopback off the proxy: the hooks, the commit path and the
// telemetry exporter talk to the client directly.
const noProxy = "127.0.0.1,localhost,::1"

// desiredEnv routes Claude Code's requests through the client as its HTTPS
// proxy (RM-329, #500). ANTHROPIC_BASE_URL is never set: Claude Code turns
// off the features it reserves for a direct connection (Remote Control,
// ultrareview) whenever it points anywhere but the provider. Both spellings
// of each proxy variable are set, since Claude Code reads the lowercase one
// first and a repository's settings could otherwise name another.
func (c SettingsConfig) desiredEnv() []envVar {
	return []envVar{
		{"INNSEGL_CORE_URL", c.LocalURL},
		{"HTTPS_PROXY", c.LocalURL},
		{"https_proxy", c.LocalURL},
		{"HTTP_PROXY", c.LocalURL},
		{"http_proxy", c.LocalURL},
		{"NO_PROXY", noProxy},
		{"no_proxy", noProxy},
		{"NODE_EXTRA_CA_CERTS", c.ProxyCA},
		{"CLAUDE_CODE_ENABLE_TELEMETRY", "1"},
		{"OTEL_LOGS_EXPORTER", "otlp"},
		{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/json"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT", c.LocalURL},
	}
}

// legacyEnv is what earlier versions wrote and this one removes: the base
// URL route, and the tool-search switch it needed.
func (c SettingsConfig) legacyEnv() []envVar {
	return []envVar{
		{"ANTHROPIC_BASE_URL", c.LocalURL},
		{"ENABLE_TOOL_SEARCH", "true"},
	}
}

func (c SettingsConfig) preToolUseCommand() string { return c.HookBin + " hook pre-tool-use" }
func (c SettingsConfig) sessionCommand() string    { return c.HookBin + " hook session" }

// sessionHookEvents are the four events `innsegl hook session` states the
// working directory on: a new or resumed session, every user turn, every
// subagent, every move.
var sessionHookEvents = []string{"SessionStart", "UserPromptSubmit", "SubagentStart", "CwdChanged"}

// NotWritableError is returned when the managed settings path cannot be
// written by this user. Nothing was changed; Staged holds the full new file
// and Command is the one line an administrator runs to install it.
type NotWritableError struct {
	Path    string
	Staged  string
	Command string
}

func (e *NotWritableError) Error() string {
	return fmt.Sprintf("%s is not writable; run this once, as an administrator:\n\n  %s\n", e.Path, e.Command)
}

// InstallSettings merges the client's keys into the managed settings at
// path. It is additive (the operator's own keys stay, in their order),
// idempotent (a second run compares parsed JSON and changes nothing), and
// backs the file up, timestamped, the moment before it first changes it.
func InstallSettings(path string, cfg SettingsConfig, now func() time.Time, out io.Writer) error {
	return applySettings(path, cfg, now, out, true)
}

// UninstallSettings removes exactly the keys InstallSettings writes, and
// only where they still hold what it wrote.
func UninstallSettings(path string, cfg SettingsConfig, now func() time.Time, out io.Writer) error {
	return applySettings(path, cfg, now, out, false)
}

// CheckSettingsWritable reports, before anything else happens, whether
// InstallSettings would need an administrator. It returns a
// *NotWritableError (with the file staged) when it would, and nil when the
// file is already up to date or can be written.
func CheckSettingsWritable(path string, cfg SettingsConfig) error {
	newText, changed, err := planSettings(path, cfg, io.Discard, true)
	if err != nil || !changed || writable(path) {
		return err
	}
	return stageForAdmin(path, newText)
}

func planSettings(path string, cfg SettingsConfig, out io.Writer, install bool) (newText []byte, changed bool, err error) {
	obj, oldText, err := loadSettings(path)
	if err != nil {
		return nil, false, err
	}
	before := marshal(obj)
	if install {
		err = installKeys(obj, cfg, path, out)
	} else {
		uninstallKeys(obj, cfg, path, out)
	}
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w; refusing to touch it", path, err)
	}
	after := marshal(obj)
	if bytes.Equal(before, after) {
		return nil, false, nil
	}
	if len(oldText) == 0 || bytes.HasSuffix(oldText, []byte("\n")) {
		after = append(after, '\n')
	}
	return after, true, nil
}

func applySettings(path string, cfg SettingsConfig, now func() time.Time, out io.Writer, install bool) error {
	newText, changed, err := planSettings(path, cfg, out, install)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintf(out, "innsegl: %s already up to date\n", path)
		return nil
	}
	if !writable(path) {
		return stageForAdmin(path, newText)
	}
	// #nosec G304 -- path is the managed settings path the operator named.
	if original, rerr := os.ReadFile(path); rerr == nil {
		backup := path + ".bak." + now().UTC().Format("20060102T150405Z")
		// #nosec G306 G703 -- a backup beside the managed settings path the
		// operator named, which every user's harness reads.
		if werr := os.WriteFile(backup, original, 0o644); werr != nil {
			return fmt.Errorf("backing up %s: %w", path, werr)
		}
		fmt.Fprintf(out, "innsegl: backed up %s -> %s\n", path, backup)
	} else if !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("reading %s: %w", path, rerr)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// #nosec G306 -- the harness, running as the user, must read it.
	if err := os.WriteFile(path, newText, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Fprintf(out, "innsegl: updated %s\n", path)
	return nil
}

func loadSettings(path string) (*object, []byte, error) {
	// #nosec G304 -- path is the managed settings path the operator named.
	text, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		// Absent, or under something that is not a directory: either way
		// there is no file yet, and writable() decides what happens next.
		return newObject(), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if strings.TrimSpace(string(text)) == "" {
		return newObject(), text, nil
	}
	obj, err := parseObject(text)
	if errors.Is(err, errNotObject) {
		return nil, nil, fmt.Errorf("%s does not hold a JSON object; refusing to touch it", path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not valid JSON (%w); refusing to touch it", path, err)
	}
	return obj, text, nil
}

func installKeys(obj *object, cfg SettingsConfig, path string, out io.Writer) error {
	env, err := obj.child("env")
	if err != nil {
		return err
	}
	for _, kv := range cfg.desiredEnv() {
		env.set(kv.key, kv.val)
	}
	removeLegacyEnv(env, cfg, path, out)

	hooks, err := obj.child("hooks")
	if err != nil {
		return err
	}
	if err = installHook(hooks, "PreToolUse", hookGroup("Bash", cfg.preToolUseCommand()), cfg); err != nil {
		return err
	}
	for _, event := range sessionHookEvents {
		if err = installHook(hooks, event, hookGroup("", cfg.sessionCommand()), cfg); err != nil {
			return err
		}
	}

	// The harness's own co-author trailer is an identity claim I6 admits
	// from no source. An empty string, never false: false makes Claude Code
	// discard the whole settings file, silently.
	attribution, err := obj.child("attribution")
	if err != nil {
		return err
	}
	attribution.set("commit", "")

	if !cfg.Hardened {
		// The route and the hooks only (RM-312). A file an earlier version
		// locked down is brought back to that, key by key, and only where a
		// key still holds what innsegl wrote.
		removeLockdown(obj, cfg)
		return nil
	}
	return installLockdown(obj, cfg, path, out)
}

// installLockdown writes the --hardened keys: the managed hooks only, bypass
// mode disabled, and a sandbox that denies the agent's shell ~/.innsegl.
func installLockdown(obj *object, cfg SettingsConfig, path string, out io.Writer) error {
	obj.set("allowManagedHooksOnly", true)
	perms, err := obj.child("permissions")
	if err != nil {
		return err
	}
	perms.set("disableBypassPermissionsMode", "disable")

	sandbox, err := obj.child("sandbox")
	if err != nil {
		return err
	}
	sandbox.set("enabled", true)
	sandbox.set("allowUnsandboxedCommands", false)
	sandbox.set("failIfUnavailable", true)
	// Go CLIs such as gh cannot verify TLS certificates under the macOS
	// sandbox; Claude Code's documented remedies are to run them outside it
	// and to allow the trust service.
	if err = appendUnique(sandbox, "excludedCommands", ghExcluded); err != nil {
		return err
	}
	sandbox.set("enableWeakerNetworkIsolation", true)
	fsys, err := sandbox.child("filesystem")
	if err != nil {
		return err
	}
	if err = appendUnique(fsys, "denyRead", cfg.LogDeny); err != nil {
		return err
	}
	if err = appendUnique(fsys, "allowRead", cfg.CAAllow); err != nil {
		return err
	}
	// Without allowLocalBinding the sandboxed shell cannot reach loopback,
	// and git runs the signing program inside that shell. The local endpoint
	// forwards with the machine's certificate; the core still authorises
	// each request. allowUnixSockets is never set: unset blocks the
	// container socket.
	net, err := sandbox.child("network")
	if err != nil {
		return err
	}
	net.set("allowLocalBinding", true)

	// allowManagedHooksOnly hides the user's own statusLine; a managed one
	// still runs, so the user's is copied here. A managed statusLine the
	// operator set is theirs and stays.
	if cfg.StatusLine != nil {
		if current, present := obj.get("statusLine"); !present {
			obj.set("statusLine", cfg.StatusLine)
		} else if !sameJSON(current, cfg.StatusLine) {
			fmt.Fprintf(out, "innsegl: statusLine in %s is not the user's own; leaving it alone\n", path)
		}
	}
	return nil
}

// ghExcluded is the sandbox.excludedCommands entry --hardened writes.
const ghExcluded = "gh *"

func sameJSON(a, b any) bool { return bytes.Equal(marshal(a), marshal(b)) }

// removeLockdown removes every --hardened key, and the lockdown earlier
// versions wrote by default, only where it still holds what innsegl wrote.
func removeLockdown(obj *object, cfg SettingsConfig) {
	if v, _ := obj.get("allowManagedHooksOnly"); v == true {
		obj.del("allowManagedHooksOnly")
	}
	if perms, ok := childIfObject(obj, "permissions"); ok {
		if v, _ := perms.get("disableBypassPermissionsMode"); v == "disable" {
			perms.del("disableBypassPermissionsMode")
		}
		dropIfEmpty(obj, "permissions", perms)
	}

	if sandbox, ok := childIfObject(obj, "sandbox"); ok {
		for _, kv := range []struct {
			key string
			val any
		}{{"enabled", true}, {"allowUnsandboxedCommands", false}, {"failIfUnavailable", true}, {"enableWeakerNetworkIsolation", true}} {
			if v, present := sandbox.get(kv.key); present && v == kv.val {
				sandbox.del(kv.key)
			}
		}
		removeFromList(sandbox, "excludedCommands", ghExcluded)
		if fsys, ok := childIfObject(sandbox, "filesystem"); ok {
			removeFromList(fsys, "denyRead", cfg.LogDeny)
			removeFromList(fsys, "allowRead", cfg.CAAllow)
			dropIfEmpty(sandbox, "filesystem", fsys)
		}
		if net, ok := childIfObject(sandbox, "network"); ok {
			if v, _ := net.get("allowLocalBinding"); v == true {
				net.del("allowLocalBinding")
			}
			dropIfEmpty(sandbox, "network", net)
		}
		dropIfEmpty(obj, "sandbox", sandbox)
	}

	if cfg.StatusLine != nil {
		if current, present := obj.get("statusLine"); present && sameJSON(current, cfg.StatusLine) {
			obj.del("statusLine")
		}
	}
}

func hookGroup(matcher, command string) *object {
	h := newObject()
	h.set("type", "command")
	h.set("command", command)
	g := newObject()
	if matcher != "" {
		g.set("matcher", matcher)
	}
	g.set("hooks", []any{h})
	return g
}

func isOurHook(v any, cfg SettingsConfig) bool {
	h, ok := v.(*object)
	if !ok {
		return false
	}
	typ, _ := h.get("type")
	cmd, _ := h.get("command")
	return typ == "command" && (cmd == cfg.preToolUseCommand() || cmd == cfg.sessionCommand())
}

func installHook(hooks *object, event string, group *object, cfg SettingsConfig) error {
	v, ok := hooks.get(event)
	if !ok {
		hooks.set(event, []any{group})
		return nil
	}
	groups, isList := v.([]any)
	if !isList {
		return fmt.Errorf("hooks.%s is not a list", event)
	}
	for _, g := range groups {
		if inner := groupHooks(g); inner != nil {
			for _, h := range inner {
				if isOurHook(h, cfg) {
					return nil
				}
			}
		}
	}
	hooks.set(event, append(groups, group))
	return nil
}

func groupHooks(g any) []any {
	o, ok := g.(*object)
	if !ok {
		return nil
	}
	list, ok := o.vals["hooks"].([]any)
	if !ok {
		return nil
	}
	return list
}

func appendUnique(o *object, key, val string) error {
	v, ok := o.get(key)
	if !ok {
		o.set(key, []any{val})
		return nil
	}
	list, isList := v.([]any)
	if !isList {
		return fmt.Errorf("%s is not a list", key)
	}
	for _, e := range list {
		if e == val {
			return nil
		}
	}
	o.set(key, append(list, val))
	return nil
}

// removeLegacyEnv takes out the base-URL route. A base URL connect did not
// write goes too, and is said: while it points anywhere but the provider,
// Claude Code sends its model requests there and not through the client, so
// nothing would be recorded. The backup keeps it.
func removeLegacyEnv(env *object, cfg SettingsConfig, path string, out io.Writer) {
	for _, kv := range cfg.legacyEnv() {
		v, present := env.get(kv.key)
		if !present {
			continue
		}
		if kv.key == "ANTHROPIC_BASE_URL" && v != kv.val {
			fmt.Fprintf(out, "innsegl: removed env.ANTHROPIC_BASE_URL (%v) from %s: model requests must reach "+
				"the provider through the client to be recorded; the backup keeps it\n", v, path)
			env.del(kv.key)
			continue
		}
		if v == kv.val {
			env.del(kv.key)
		}
	}
}

func uninstallKeys(obj *object, cfg SettingsConfig, path string, out io.Writer) {
	if env, ok := childIfObject(obj, "env"); ok {
		for _, kv := range cfg.legacyEnv() {
			if v, present := env.get(kv.key); present && v == kv.val {
				env.del(kv.key)
			}
		}
		for _, kv := range cfg.desiredEnv() {
			v, present := env.get(kv.key)
			if !present {
				continue
			}
			if v == kv.val {
				env.del(kv.key)
			} else {
				fmt.Fprintf(out, "innsegl: env.%s in %s does not match what connect writes; leaving it alone\n", kv.key, path)
			}
		}
		dropIfEmpty(obj, "env", env)
	}

	if hooks, ok := childIfObject(obj, "hooks"); ok {
		for _, event := range append([]string{"PreToolUse"}, sessionHookEvents...) {
			groups, isList := hooks.vals[event].([]any)
			if !isList {
				continue
			}
			kept := []any{}
			for _, g := range groups {
				inner := groupHooks(g)
				if inner == nil {
					kept = append(kept, g)
					continue
				}
				filtered := []any{}
				for _, h := range inner {
					if !isOurHook(h, cfg) {
						filtered = append(filtered, h)
					}
				}
				if len(filtered) > 0 {
					if o, isObj := g.(*object); isObj {
						o.set("hooks", filtered)
					}
					kept = append(kept, g)
				}
			}
			if len(kept) > 0 {
				hooks.set(event, kept)
			} else {
				hooks.del(event)
			}
		}
		dropIfEmpty(obj, "hooks", hooks)
	}

	if attribution, ok := childIfObject(obj, "attribution"); ok {
		if v, present := attribution.get("commit"); present && v == "" {
			attribution.del("commit")
		}
		dropIfEmpty(obj, "attribution", attribution)
	}
	removeLockdown(obj, cfg)
}

func childIfObject(o *object, key string) (*object, bool) {
	v, ok := o.get(key)
	if !ok {
		return nil, false
	}
	c, isObj := v.(*object)
	return c, isObj
}

func dropIfEmpty(parent *object, key string, child *object) {
	if child.empty() {
		parent.del(key)
	}
}

func removeFromList(o *object, key, val string) {
	list, ok := o.vals[key].([]any)
	if !ok {
		return
	}
	kept := []any{}
	for _, e := range list {
		if e != val {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(list) {
		return
	}
	if len(kept) == 0 {
		o.del(key)
		return
	}
	o.set(key, kept)
}

// writable reports whether this user can create or replace path, creating
// its directory when it can, as install.sh's own check does.
func writable(path string) bool {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	probe, err := os.CreateTemp(dir, ".innsegl-probe-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	if _, err := os.Stat(path); err == nil {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false
		}
		_ = f.Close()
	}
	return true
}

// stageForAdmin writes newText to a temporary file and returns the one
// command that installs it at path. install -m 0644, not cp: the temporary
// file is 0600, and cp would keep that, leaving settings the harness,
// running as the user, cannot read.
func stageForAdmin(path string, newText []byte) error {
	f, err := os.CreateTemp("", "innsegl-managed-settings.*.json")
	if err != nil {
		return fmt.Errorf("%s is not writable, and staging the new file failed: %w", path, err)
	}
	if _, err := f.Write(newText); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return &NotWritableError{
		Path:   path,
		Staged: f.Name(),
		Command: fmt.Sprintf("sudo mkdir -p %s && sudo install -m 0644 %s %s",
			shellQuote(filepath.Dir(path)), shellQuote(f.Name()), shellQuote(path)),
	}
}

// Pause moves the managed settings to <path>.paused, byte for byte, so the
// harness runs without the client endpoint until Resume puts them back.
func Pause(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s does not exist; there is nothing to pause", path)
	}
	return move(path, path+".paused")
}

// Resume puts paused managed settings back.
func Resume(path string) error {
	if _, err := os.Stat(path + ".paused"); err != nil {
		return fmt.Errorf("nothing is paused: %s.paused does not exist", path)
	}
	return move(path+".paused", path)
}

func move(from, to string) error {
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite it", to)
	}
	if err := os.Rename(from, to); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return &NotWritableError{Path: to, Command: "sudo mv " + shellQuote(from) + " " + shellQuote(to)}
		}
		return err
	}
	return nil
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellQuote quotes s for a POSIX shell the way Python's shlex.quote does:
// a plain word stays as it is.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
