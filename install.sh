#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One command from a fresh clone to a signable checkout — RM-214.
#
# WHY THIS EXISTS. Getting to a first signed commit used to mean knowing, in
# order, that you had to run `make start`, then `make innsegl-install-signer`,
# then `make link DIR=...`, and then hand-edit two Claude Code configuration
# files yourself — with no single place that said so. This is that sequence,
# once, plus the two file edits, and it changes nothing it did not add.
#
# WHAT IT DOES, IN ORDER
#   1. Checks the prerequisites and refuses before touching anything if one
#      is missing.
#   2. Brings the stack up (`make start`, or $INNSEGL_INSTALL_START_CMD).
#   3. Puts `innsegl-commit` on PATH (`make innsegl-install-signer`, or
#      $INNSEGL_INSTALL_SIGNER_CMD).
#   4. Connects this checkout to Claude Code: registers the harness hooks in
#      $HOME/.claude/settings.json and the `innsegl` MCP server in
#      $HOME/.claude.json. Idempotent, additive, and every file is backed up,
#      timestamped, the moment before it is first changed.
#   5. Links each DIR argument (`make link DIR=<dir>`, or
#      $INNSEGL_INSTALL_LINK_CMD).
#   6. Prints the dashboard URL and the next command to sign.
#
# `--dry-run` runs step 1 (so a missing prerequisite is still caught) and then
# only computes and prints what steps 2-5 would do; nothing on disk changes.
#
# `--uninstall` removes exactly what THIS script added — the six hook entries
# naming this checkout's hook script, the `innsegl` MCP entry, and the signer
# symlink — and nothing the user added themselves. It does not touch the
# running stack; it prints the command that does.
#
# USAGE
#   install.sh [--dry-run] [--uninstall] [DIR...]
#
# Every DIR becomes signable, the same as `make link DIR=<dir>` run by hand.
#
# See scripts/install-selftest.sh for what this is tested against, and
# deploy/compose/README.md for what the stack this brings up actually is.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd -P)"
HOOK_SCRIPT="$ROOT/scripts/hooks/subagent-identity.sh"

# Overridable so the self-test can stub bring-up, the signer install and
# linking without touching Docker, a real PATH entry, or a real deployment.
START_CMD="${INNSEGL_INSTALL_START_CMD:-make start}"
SIGNER_CMD="${INNSEGL_INSTALL_SIGNER_CMD:-make innsegl-install-signer}"
LINK_CMD="${INNSEGL_INSTALL_LINK_CMD:-make link}"

# The one URL the deployment publishes its MCP listener on
# (deploy/compose/innsegl.yml; overridable for a deployment that moved it).
MCP_URL="${INNSEGL_INSTALL_MCP_URL:-http://127.0.0.1:28080/}"

# Matches `make innsegl-install-signer`'s own default, so uninstall looks for
# the symlink in the same place install put it.
BIN_DIR="${INNSEGL_BIN:-$HOME/.local/bin}"

DRY_RUN=0
UNINSTALL=0
DIRS=()

usage() {
  cat <<'EOF'
usage: install.sh [--dry-run] [--uninstall] [DIR...]

Brings the innsegl stack up, puts innsegl-commit on PATH, connects this
checkout to Claude Code (hooks and MCP server), and makes each DIR signable.

  --dry-run    print what would change; touch nothing
  --uninstall  remove exactly what this installer added; the stack keeps running
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
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
  check curl          "curl"                            command -v curl

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
# 4. CONNECT CLAUDE CODE — the only step that edits a file, and the only one
# --dry-run can show a diff for rather than merely naming.
#
# Both files get the same treatment, done once in Python because `json` is
# the only thing here that can tell "no change" from "reformatted" — a sed
# edit cannot merge, and a naive rewrite cannot tell an idempotent second run
# from a real change, which is what would make it back up and rewrite a file
# it had already installed into.
# ---------------------------------------------------------------------------

connect_one() {
  # connect_one <file> <settings|mcp> <install|uninstall>
  INSTALL_FILE="$1" INSTALL_KIND="$2" INSTALL_ACTION="$3" \
  INSTALL_HOOK_PATH="$HOOK_SCRIPT" INSTALL_MCP_URL="$MCP_URL" \
  INSTALL_DRY_RUN="$DRY_RUN" \
  python3 - <<'PYEOF'
import copy, datetime, difflib, json, os, sys

path = os.environ["INSTALL_FILE"]
kind = os.environ["INSTALL_KIND"]
action = os.environ["INSTALL_ACTION"]
hook_path = os.environ["INSTALL_HOOK_PATH"]
mcp_url = os.environ["INSTALL_MCP_URL"]
dry_run = os.environ.get("INSTALL_DRY_RUN") == "1"

# The four events with no tool to match, and the two that fire per tool call.
# subagent-identity.sh's own header names all six as what it must be wired to.
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


def install_hooks(obj):
    hooks = obj.setdefault("hooks", {})
    for event in ALL_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            sys.stderr.write(
                "install.sh: hooks.%s in %s is not a list; refusing to touch it\n"
                % (event, path)
            )
            sys.exit(1)
        already = any(
            is_ours(h)
            for g in groups
            if isinstance(g, dict) and isinstance(g.get("hooks"), list)
            for h in g["hooks"]
        )
        if already:
            continue
        entry = {"hooks": [{"type": "command", "command": hook_path}]}
        if event in EVENTS_MATCHER:
            entry = {"matcher": "*", "hooks": [{"type": "command", "command": hook_path}]}
        groups.append(entry)
    if not hooks:
        obj.pop("hooks", None)


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
            # else: this group held only our hook — drop the whole group.
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if hooks:
        obj["hooks"] = hooks
    else:
        obj.pop("hooks", None)


def install_mcp(obj):
    servers = obj.setdefault("mcpServers", {})
    desired = {"type": "http", "url": mcp_url}
    if servers.get("innsegl") != desired:
        servers["innsegl"] = desired
    if not servers:
        obj.pop("mcpServers", None)


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
before = copy.deepcopy(obj)

if kind == "settings":
    (install_hooks if action == "install" else uninstall_hooks)(obj)
elif kind == "mcp":
    (install_mcp if action == "install" else uninstall_mcp)(obj)
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

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
print("install.sh: updated %s" % path)
PYEOF
}

connect_claude_code() {
  local action="$1"
  connect_one "$HOME/.claude/settings.json" settings "$action"
  connect_one "$HOME/.claude.json" mcp "$action"
}

# ---------------------------------------------------------------------------
# --uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
  echo "==> disconnecting Claude Code"
  connect_claude_code uninstall

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

Ready. Dashboard:
  $dashboard

Sign your next commit:
  make sign -- -m 'your message'
  innsegl-commit -m 'your message'      (from any linked project, once it is on PATH)
EOF
}

main() {
  parse_args "$@"

  if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
    exit 0
  fi

  if [ ! -f "$HOOK_SCRIPT" ]; then
    echo "install.sh: $HOOK_SCRIPT does not exist — is this a full checkout of innsegl?" >&2
    exit 1
  fi

  check_prereqs

  echo "==> bringing the stack up"
  run_step "$START_CMD"

  echo "==> putting innsegl-commit on PATH"
  run_step "$SIGNER_CMD"

  echo "==> connecting Claude Code"
  connect_claude_code install

  if [ "${#DIRS[@]}" -gt 0 ]; then
    echo "==> linking projects"
    for d in "${DIRS[@]}"; do
      run_step "$LINK_CMD DIR=$(printf '%q' "$d")"
    done
  fi

  print_finish
}

main "$@"
