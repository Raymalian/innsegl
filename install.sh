#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One command from a fresh clone to an enforced, signable checkout — RM-245
# (#390), epic #361 E18.
#
# WHY THIS EXISTS. Getting to a first signed commit used to mean knowing, in
# order, that you had to run `make start`, then `make innsegl-install-signer`,
# then hand-edit two Claude Code configuration files, then `make link
# DIR=...` — with no single place that said so, and nothing stopping an agent
# from editing those files right back. This is that sequence, once, aimed at
# the GATEWAY design instead: every request routes through the gateway, the
# harness's managed settings are the one file an agent cannot edit, and the
# sandbox denies the container socket and innsegl's own stores.
#
# WHAT IT DOES, IN ORDER
#   1. Checks the prerequisites — including that the innsegl binary this
#      checkout builds (`make build`) exists — and refuses before touching
#      anything if one is missing.
#   2. Brings the stack up (`make start`, or $INNSEGL_INSTALL_START_CMD).
#   3. Puts `innsegl-commit` on PATH (`make innsegl-install-signer`, or
#      $INNSEGL_INSTALL_SIGNER_CMD).
#   4. Writes the harness's MANAGED settings — a file users and agents cannot
#      override — to the system path (macOS
#      `/Library/Application Support/ClaudeCode/managed-settings.json`,
#      Linux `/etc/claude-code/managed-settings.json`), or wherever
#      --managed-settings / $INNSEGL_INSTALL_MANAGED_SETTINGS names. It
#      points ANTHROPIC_BASE_URL, INNSEGL_CORE_URL and telemetry at the
#      gateway, registers the one PreToolUse hook, requires the sandbox, and
#      denies a sandboxed shell innsegl's own stores. Idempotent, additive
#      (the operator's own keys survive), and every file is backed up,
#      timestamped, the moment before it is first changed. This installer
#      never sudos itself: when the target is not writable it prints the
#      one-line command an administrator runs, and changes nothing.
#   5. Links each DIR argument (`$INNSEGL_BIN_PATH link DIR`, or
#      $INNSEGL_INSTALL_LINK_CMD).
#   6. Prints the dashboard URL and the managed settings path.
#
# `--dry-run` runs step 1 (so a missing prerequisite is still caught) and then
# only computes and prints what steps 2-5 would do; nothing on disk changes.
#
# `--uninstall` removes exactly the keys THIS installer added to the managed
# settings — the env vars, the one hook entry, the permission and sandbox
# flags — and the signer symlink, and nothing the operator added themselves.
# It does not touch the running stack; it prints the command that does.
#
# `--uninstall-legacy` is separate and opt-in: it removes the OLD wiring an
# earlier version of this installer wrote directly into the harness's own
# $HOME/.claude/settings.json (six subagent-identity.sh hook entries) and
# $HOME/.claude.json (the `innsegl` MCP entry). It never runs as a side
# effect of a plain --uninstall, and it never installs that wiring — only
# removes it.
#
# USAGE
#   install.sh [--dry-run] [--uninstall] [--uninstall-legacy]
#              [--managed-settings <path>] [DIR...]
#
# Every DIR becomes signable, the same as `$INNSEGL_BIN_PATH link DIR` run by
# hand.
#
# See scripts/install-selftest.sh for what this is tested against, and
# deploy/compose/README.md for what the stack this brings up actually is.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd -P)"

# Overridable so the self-test can stub bring-up, the signer install and
# linking without touching Docker, a real PATH entry, or a real deployment.
START_CMD="${INNSEGL_INSTALL_START_CMD:-make start}"
SIGNER_CMD="${INNSEGL_INSTALL_SIGNER_CMD:-make innsegl-install-signer}"

# The compiled innsegl binary this checkout's `make build` produces. The
# PreToolUse hook command in managed settings names this path exactly — an
# absolute path, so the harness need not resolve it against any PATH.
INNSEGL_BIN_PATH="${INNSEGL_BIN_PATH:-$ROOT/innsegl}"
LINK_CMD="${INNSEGL_INSTALL_LINK_CMD:-$INNSEGL_BIN_PATH link}"

# The gateway every request routes through (ADR-0060): ANTHROPIC_BASE_URL,
# INNSEGL_CORE_URL and the telemetry endpoint all point here. Overridable for
# a deployment that moved it, or for a self-test / live check running against
# the plain-http gateway before its own TLS is wired up.
GATEWAY_URL="${INNSEGL_INSTALL_GATEWAY_URL:-https://127.0.0.1:28095}"

# innsegl's own CA, and the store the sandbox denies a shell read access to.
CA_PEM="${INNSEGL_INSTALL_CA_PEM:-$HOME/.innsegl/ca/gateway-ca.pem}"
LOG_DENY="${INNSEGL_INSTALL_LOG_DENY:-$HOME/.innsegl/log}"

# Matches `make innsegl-install-signer`'s own default, so uninstall looks for
# the symlink in the same place install put it.
BIN_DIR="${INNSEGL_BIN:-$HOME/.local/bin}"

default_managed_settings_path() {
  case "$(uname -s)" in
    Darwin) printf '%s' "/Library/Application Support/ClaudeCode/managed-settings.json" ;;
    *)      printf '%s' "/etc/claude-code/managed-settings.json" ;;
  esac
}
MANAGED_SETTINGS="${INNSEGL_INSTALL_MANAGED_SETTINGS:-$(default_managed_settings_path)}"

# scripts/hooks/subagent-identity.sh's own header names the six events it
# must be wired to — this is --uninstall-legacy's target, never installed by
# this script, only ever removed.
LEGACY_HOOK_SCRIPT="$ROOT/scripts/hooks/subagent-identity.sh"
LEGACY_MCP_URL="${INNSEGL_INSTALL_LEGACY_MCP_URL:-http://127.0.0.1:28080/}"

DRY_RUN=0
UNINSTALL=0
UNINSTALL_LEGACY=0
DIRS=()

usage() {
  cat <<'EOF'
usage: install.sh [--dry-run] [--uninstall] [--uninstall-legacy]
                   [--managed-settings <path>] [DIR...]

Brings the innsegl stack up, puts innsegl-commit on PATH, writes the
harness's managed settings (gateway env, the one PreToolUse hook, the
sandbox), and makes each DIR signable.

  --dry-run              print what would change; touch nothing
  --uninstall             remove exactly what this installer added
  --uninstall-legacy      also remove the OLD hook-and-MCP wiring (opt-in)
  --managed-settings <p>  write the managed settings to <p> instead of the
                          system path
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --uninstall-legacy) UNINSTALL_LEGACY=1; shift ;;
      --managed-settings)
        [ $# -ge 2 ] || { echo "install.sh: --managed-settings needs a path" >&2; exit 2; }
        MANAGED_SETTINGS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      -*)
        echo "install.sh: unrecognised option: $1" >&2
        usage >&2
        exit 2
        ;;
      *) DIRS+=("$1"); shift ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# 1. PREREQUISITES — checked before anything else runs, and nothing above
# this point has touched the filesystem.
# ---------------------------------------------------------------------------

hint_macos() {
  case "$1" in
    docker-daemon) echo "install and start Docker Desktop: https://www.docker.com/products/docker-desktop/" ;;
    compose)       echo "update Docker Desktop (it ships compose v2), or: brew install docker-compose" ;;
    git)           echo "brew install git" ;;
    make)          echo "xcode-select --install" ;;
    python3)       echo "brew install python3" ;;
    curl)          echo "brew install curl" ;;
    innsegl-bin)   echo "make build" ;;
  esac
}

hint_debian() {
  case "$1" in
    docker-daemon) echo "sudo apt-get install -y docker.io docker-compose-plugin && sudo systemctl enable --now docker" ;;
    compose)       echo "sudo apt-get install -y docker-compose-plugin" ;;
    git)           echo "sudo apt-get install -y git" ;;
    make)          echo "sudo apt-get install -y make" ;;
    python3)       echo "sudo apt-get install -y python3" ;;
    curl)          echo "sudo apt-get install -y curl" ;;
    innsegl-bin)   echo "make build" ;;
  esac
}

MISSING=0

check() {
  # check <key> <label> <test-command...>
  local key="$1" label="$2"
  shift 2
  if ! "$@" >/dev/null 2>&1; then
    printf 'install.sh: missing prerequisite: %s\n' "$label" >&2
    printf '  macOS:          %s\n' "$(hint_macos "$key")" >&2
    printf '  Debian/Ubuntu:  %s\n' "$(hint_debian "$key")" >&2
    MISSING=1
  fi
}

check_prereqs() {
  check docker-daemon "the Docker daemon (reachable)" docker info
  check compose       "docker compose v2"             docker compose version
  check git           "git"                            command -v git
  check make          "make"                           command -v make
  check python3       "python3"                        command -v python3
  check curl           "curl"                            command -v curl
  check innsegl-bin    "the innsegl binary ($INNSEGL_BIN_PATH)" test -x "$INNSEGL_BIN_PATH"

  if [ "$MISSING" -ne 0 ]; then
    echo >&2
    echo "install.sh: install what is missing above, then run this again. Nothing was changed." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# 2, 3, 5. STEPS WITH A REAL SIDE EFFECT — bring-up, the signer, and linking.
# Each runs from the repository root, exactly as typing the command by hand
# from here would. --dry-run prints the command instead of running it.
# ---------------------------------------------------------------------------

run_step() {
  local cmd="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'install.sh: (dry run) would run: %s\n' "$cmd"
    return 0
  fi
  ( cd "$ROOT" && eval "$cmd" )
}

# ---------------------------------------------------------------------------
# 4. THE MANAGED SETTINGS — the only step that edits a file, and the only one
# --dry-run can show a diff for rather than merely naming.
#
# Done in Python because `json` is the only thing here that can tell "no
# change" from "reformatted" — a sed edit cannot merge, and a naive rewrite
# cannot tell an idempotent second run from a real change, which is what
# would make it back up and rewrite a file it had already installed into.
# ---------------------------------------------------------------------------

connect_managed_settings() {
  local action="$1"
  INSTALL_FILE="$MANAGED_SETTINGS" \
  INSTALL_ACTION="$action" \
  INSTALL_DRY_RUN="$DRY_RUN" \
  INSTALL_HOOK_PATH="$INNSEGL_BIN_PATH" \
  INSTALL_GATEWAY_URL="$GATEWAY_URL" \
  INSTALL_CA_PEM="$CA_PEM" \
  INSTALL_LOG_DENY="$LOG_DENY" \
  python3 - <<'PYEOF'
import copy, datetime, difflib, json, os, shlex, sys, tempfile

path = os.environ["INSTALL_FILE"]
action = os.environ["INSTALL_ACTION"]
dry_run = os.environ.get("INSTALL_DRY_RUN") == "1"
hook_path = os.environ["INSTALL_HOOK_PATH"]
gateway_url = os.environ["INSTALL_GATEWAY_URL"]
ca_pem = os.environ["INSTALL_CA_PEM"]
log_deny = os.environ["INSTALL_LOG_DENY"]

# The four telemetry vars (Claude Code docs) plus the three that route this
# harness's own traffic through the gateway. Managed env wins over every
# other file and the shell (Claude Code docs), which is the whole point:
# nothing an agent can write overrides these.
DESIRED_ENV = {
    "ANTHROPIC_BASE_URL": gateway_url,
    "NODE_EXTRA_CA_CERTS": ca_pem,
    "INNSEGL_CORE_URL": gateway_url,
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": gateway_url,
}


def load(p):
    if not os.path.isfile(p):
        return {}, ""
    with open(p, "r", encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        return {}, text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        sys.stderr.write(
            "install.sh: %s is not valid JSON (%s); refusing to touch it\n" % (p, e)
        )
        sys.exit(1)
    if not isinstance(obj, dict):
        sys.stderr.write(
            "install.sh: %s does not hold a JSON object; refusing to touch it\n" % p
        )
        sys.exit(1)
    return obj, text


def is_ours_hook(h):
    return (
        isinstance(h, dict)
        and h.get("type") == "command"
        and h.get("command") == hook_path
    )


def install_env(obj):
    env = obj.setdefault("env", {})
    for k, v in DESIRED_ENV.items():
        env[k] = v


def uninstall_env(obj):
    env = obj.get("env")
    if not isinstance(env, dict):
        return
    for k, v in DESIRED_ENV.items():
        if k not in env:
            continue
        if env[k] == v:
            env.pop(k, None)
        else:
            sys.stderr.write(
                "install.sh: env.%s in %s does not match what this installer "
                "writes; leaving it alone\n" % (k, path)
            )
    if not env:
        obj.pop("env", None)


def install_hooks(obj):
    hooks = obj.setdefault("hooks", {})
    groups = hooks.setdefault("PreToolUse", [])
    if not isinstance(groups, list):
        sys.stderr.write(
            "install.sh: hooks.PreToolUse in %s is not a list; refusing to touch it\n"
            % path
        )
        sys.exit(1)
    already = any(
        is_ours_hook(h)
        for g in groups
        if isinstance(g, dict) and isinstance(g.get("hooks"), list)
        for h in g["hooks"]
    )
    if not already:
        groups.append({"matcher": "Bash", "hooks": [{"type": "command", "command": hook_path}]})
    if not hooks:
        obj.pop("hooks", None)


def uninstall_hooks(obj):
    hooks = obj.get("hooks")
    if not isinstance(hooks, dict):
        return
    groups = hooks.get("PreToolUse")
    if isinstance(groups, list):
        kept = []
        for g in groups:
            if not isinstance(g, dict) or not isinstance(g.get("hooks"), list):
                kept.append(g)
                continue
            filtered = [h for h in g["hooks"] if not is_ours_hook(h)]
            if filtered:
                g2 = dict(g)
                g2["hooks"] = filtered
                kept.append(g2)
            # else: this group held only our hook — drop the whole group.
        if kept:
            hooks["PreToolUse"] = kept
        else:
            hooks.pop("PreToolUse", None)
    if hooks:
        obj["hooks"] = hooks
    else:
        obj.pop("hooks", None)


def install_flags(obj):
    obj["allowManagedHooksOnly"] = True
    perms = obj.setdefault("permissions", {})
    perms["disableBypassPermissionsMode"] = "disable"


def uninstall_flags(obj):
    if obj.get("allowManagedHooksOnly") is True:
        obj.pop("allowManagedHooksOnly", None)
    perms = obj.get("permissions")
    if isinstance(perms, dict):
        if perms.get("disableBypassPermissionsMode") == "disable":
            perms.pop("disableBypassPermissionsMode", None)
        if perms:
            obj["permissions"] = perms
        else:
            obj.pop("permissions", None)


def install_sandbox(obj):
    sandbox = obj.setdefault("sandbox", {})
    sandbox["enabled"] = True
    sandbox["allowUnsandboxedCommands"] = False
    sandbox["failIfUnavailable"] = True
    fs = sandbox.setdefault("filesystem", {})
    deny = fs.setdefault("denyRead", [])
    if not isinstance(deny, list):
        sys.stderr.write(
            "install.sh: sandbox.filesystem.denyRead in %s is not a list; "
            "refusing to touch it\n" % path
        )
        sys.exit(1)
    if log_deny not in deny:
        deny.append(log_deny)
    # sandbox.network.allowUnixSockets is deliberately never set: unset blocks
    # every unix socket on macOS, including the container socket, and listing
    # it would be listing the one thing this contract exists to deny.


def uninstall_sandbox(obj):
    sandbox = obj.get("sandbox")
    if not isinstance(sandbox, dict):
        return
    if sandbox.get("enabled") is True:
        sandbox.pop("enabled", None)
    if sandbox.get("allowUnsandboxedCommands") is False:
        sandbox.pop("allowUnsandboxedCommands", None)
    if sandbox.get("failIfUnavailable") is True:
        sandbox.pop("failIfUnavailable", None)
    fs = sandbox.get("filesystem")
    if isinstance(fs, dict):
        deny = fs.get("denyRead")
        if isinstance(deny, list) and log_deny in deny:
            deny.remove(log_deny)
            if deny:
                fs["denyRead"] = deny
            else:
                fs.pop("denyRead", None)
        if fs:
            sandbox["filesystem"] = fs
        else:
            sandbox.pop("filesystem", None)
    net = sandbox.get("network")
    if isinstance(net, dict):
        if net.get("strictAllowlist") is True:
            net.pop("strictAllowlist", None)
        if net.get("allowManagedDomainsOnly") is True:
            net.pop("allowManagedDomainsOnly", None)
        net.pop("allowedDomains", None)
        if net:
            sandbox["network"] = net
        else:
            sandbox.pop("network", None)
    if sandbox:
        obj["sandbox"] = sandbox
    else:
        obj.pop("sandbox", None)


obj, old_text = load(path)
before = copy.deepcopy(obj)

if action == "install":
    install_env(obj)
    install_hooks(obj)
    install_flags(obj)
    install_sandbox(obj)
elif action == "uninstall":
    uninstall_env(obj)
    uninstall_hooks(obj)
    uninstall_flags(obj)
    uninstall_sandbox(obj)
else:
    sys.stderr.write("install.sh: internal error: unknown action %r\n" % action)
    sys.exit(1)

if obj == before:
    print("install.sh: %s already up to date" % path)
    sys.exit(0)

new_text = json.dumps(obj, indent=2) + "\n"
diff = list(
    difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=path,
        tofile=path,
    )
)
sys.stdout.writelines(diff)

if dry_run:
    print("install.sh: (dry run) would update %s" % path)
    sys.exit(0)


def writable(target):
    d = os.path.dirname(target) or "."
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return False
    try:
        fd, tmp = tempfile.mkstemp(dir=d)
        os.close(fd)
        os.unlink(tmp)
    except OSError:
        return False
    if os.path.isfile(target) and not os.access(target, os.W_OK):
        return False
    return True


if not writable(path):
    fd, tmp_path = tempfile.mkstemp(prefix="innsegl-managed-settings.", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new_text)
    sys.stderr.write("install.sh: %s is not writable.\n" % path)
    sys.stderr.write(
        "install.sh: run this once, as an administrator, then re-run install.sh:\n\n"
    )
    sys.stderr.write(
        "  sudo mkdir -p %s && sudo cp %s %s\n\n"
        % (
            shlex.quote(os.path.dirname(path)),
            shlex.quote(tmp_path),
            shlex.quote(path),
        )
    )
    sys.exit(1)

if os.path.isfile(path):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = "%s.bak.%s" % (path, ts)
    with open(path, "r", encoding="utf-8") as f:
        original = f.read()
    with open(backup, "w", encoding="utf-8") as f:
        f.write(original)
    print("install.sh: backed up %s -> %s" % (path, backup))

os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
print("install.sh: updated %s" % path)
PYEOF
}

# ---------------------------------------------------------------------------
# --uninstall-legacy — the OLD wiring, and ONLY this removes it. Never
# installed by this script; the six subagent-identity.sh hook entries and the
# `innsegl` MCP entry are what an earlier install.sh version wrote directly
# into the harness's own settings files.
# ---------------------------------------------------------------------------

legacy_uninstall_one() {
  # legacy_uninstall_one <file> <settings|mcp>
  INSTALL_FILE="$1" INSTALL_KIND="$2" \
  INSTALL_HOOK_PATH="$LEGACY_HOOK_SCRIPT" INSTALL_MCP_URL="$LEGACY_MCP_URL" \
  INSTALL_DRY_RUN="$DRY_RUN" \
  python3 - <<'PYEOF'
import datetime, difflib, json, os, sys

path = os.environ["INSTALL_FILE"]
kind = os.environ["INSTALL_KIND"]
hook_path = os.environ["INSTALL_HOOK_PATH"]
mcp_url = os.environ["INSTALL_MCP_URL"]
dry_run = os.environ.get("INSTALL_DRY_RUN") == "1"

EVENTS_NO_MATCHER = ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop"]
EVENTS_MATCHER = ["PreToolUse", "PostToolUse"]
ALL_EVENTS = EVENTS_NO_MATCHER + EVENTS_MATCHER


def load(p):
    if not os.path.isfile(p):
        return {}, ""
    with open(p, "r", encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        return {}, text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        sys.stderr.write(
            "install.sh: %s is not valid JSON (%s); refusing to touch it\n" % (p, e)
        )
        sys.exit(1)
    if not isinstance(obj, dict):
        sys.stderr.write(
            "install.sh: %s does not hold a JSON object; refusing to touch it\n" % p
        )
        sys.exit(1)
    return obj, text


def is_ours(hook):
    return (
        isinstance(hook, dict)
        and hook.get("type") == "command"
        and hook.get("command") == hook_path
    )


def uninstall_hooks(obj):
    hooks = obj.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event in ALL_EVENTS:
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        kept = []
        for g in groups:
            if not isinstance(g, dict) or not isinstance(g.get("hooks"), list):
                kept.append(g)
                continue
            filtered = [h for h in g["hooks"] if not is_ours(h)]
            if filtered:
                g2 = dict(g)
                g2["hooks"] = filtered
                kept.append(g2)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if hooks:
        obj["hooks"] = hooks
    else:
        obj.pop("hooks", None)


def uninstall_mcp(obj):
    servers = obj.get("mcpServers")
    if not isinstance(servers, dict):
        return
    desired = {"type": "http", "url": mcp_url}
    current = servers.get("innsegl")
    if current == desired:
        servers.pop("innsegl", None)
    elif current is not None:
        sys.stderr.write(
            "install.sh: mcpServers.innsegl in %s does not match what this "
            "installer writes; leaving it alone\n" % path
        )
    if servers:
        obj["mcpServers"] = servers
    else:
        obj.pop("mcpServers", None)


obj, old_text = load(path)
import copy
before = copy.deepcopy(obj)

if kind == "settings":
    uninstall_hooks(obj)
elif kind == "mcp":
    uninstall_mcp(obj)
else:
    sys.stderr.write("install.sh: internal error: unknown kind %r\n" % kind)
    sys.exit(1)

if obj == before:
    print("install.sh: %s already up to date" % path)
    sys.exit(0)

new_text = json.dumps(obj, indent=2) + "\n"
diff = list(
    difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=path,
        tofile=path,
    )
)
sys.stdout.writelines(diff)

if dry_run:
    print("install.sh: (dry run) would update %s" % path)
    sys.exit(0)

if os.path.isfile(path):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = "%s.bak.%s" % (path, ts)
    with open(path, "r", encoding="utf-8") as f:
        original = f.read()
    with open(backup, "w", encoding="utf-8") as f:
        f.write(original)
    print("install.sh: backed up %s -> %s" % (path, backup))

os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
print("install.sh: updated %s" % path)
PYEOF
}

do_uninstall_legacy() {
  echo "==> removing the old hook-and-MCP wiring (legacy)"
  legacy_uninstall_one "$HOME/.claude/settings.json" settings
  legacy_uninstall_one "$HOME/.claude.json" mcp
}

# ---------------------------------------------------------------------------
# --uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
  echo "==> removing the managed settings this installer added"
  connect_managed_settings uninstall

  local link="$BIN_DIR/innsegl-commit"
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -L "$link" ]; then
      printf 'install.sh: (dry run) would remove %s\n' "$link"
    else
      printf 'install.sh: %s is not present; nothing to remove\n' "$link"
    fi
  else
    echo "==> removing the signer symlink"
    if [ -L "$link" ]; then
      rm -f "$link"
      echo "install.sh: removed $link"
    else
      echo "install.sh: $link is not present; nothing to remove"
    fi
  fi

  cat <<'EOF'

This does not stop or delete the running stack. To do that:
  make innsegl-down                stop innsegl, keep the ledger and the signed history
  make innsegl-purge                stop innsegl AND delete its data volumes
  make spire-down sigstore-down     stop the two dependency stacks as well
EOF
}

# ---------------------------------------------------------------------------
# 6. FINISH
# ---------------------------------------------------------------------------

print_finish() {
  local dashboard="http://127.0.0.1:8082/"
  cat <<EOF

Ready. Managed settings:
  $MANAGED_SETTINGS
Dashboard:
  $dashboard

Every Bash tool call now runs through the gateway at $GATEWAY_URL, and a
git commit it makes is signed automatically — nothing further to run.
EOF
}

main() {
  parse_args "$@"

  if [ "$UNINSTALL_LEGACY" -eq 1 ]; then
    do_uninstall_legacy
  fi
  if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
  fi
  if [ "$UNINSTALL" -eq 1 ] || [ "$UNINSTALL_LEGACY" -eq 1 ]; then
    exit 0
  fi

  check_prereqs

  echo "==> bringing the stack up"
  run_step "$START_CMD"

  echo "==> putting innsegl-commit on PATH"
  run_step "$SIGNER_CMD"

  echo "==> writing the managed settings"
  connect_managed_settings install

  if [ "${#DIRS[@]}" -gt 0 ]; then
    echo "==> linking projects"
    for d in "${DIRS[@]}"; do
      run_step "$LINK_CMD $(printf '%q' "$d")"
    done
  fi

  print_finish
}

main "$@"
