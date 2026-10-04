#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The server installer: one command from a fresh clone to a running core —
# RM-245 (#390), RM-285 (#461), ADR-0063.
#
# WHAT IT DOES, IN ORDER
#   1. Checks the prerequisites — including that the innsegl binary this
#      checkout builds (`make build`) exists — and refuses before touching
#      anything if one is missing.
#   2. Brings the stack up (`make start`, or $INNSEGL_INSTALL_START_CMD).
#   3. Builds the innsegl binary.
#   4. Links each DIR argument (`$INNSEGL_BIN_PATH link DIR`, or
#      $INNSEGL_INSTALL_LINK_CMD).
#   5. Prints the dashboard URL, the one-time setup link while no account
#      exists, and how a machine connects.
#
# IT WRITES NO HARNESS SETTINGS. Every machine that runs agents, the core
# host included, connects with `innsegl connect`, which enrols it, runs its
# client service, and writes its managed settings (ADR-0063, ADR-0069). This
# script used to write them itself for the single-host shape (--local-client),
# pointing the harness straight at the gateway with a base URL ADR-0069 rules
# out; that, and --hardened, --egress-control, --pause and --resume, moved to
# `innsegl connect`, and naming one here says so.
#
# `--dry-run` runs step 1 (so a missing prerequisite is still caught) and then
# only prints what steps 2-4 would run; nothing on disk changes.
#
# Agents' commits are signed through the gateway (ADR-0059), and a human
# commits with plain git, so nothing is put on PATH.
#
# `--uninstall` removes the `innsegl-commit` symlink an older version of this
# installer put on PATH for the retired commit signer, if one is still there —
# cleanup of an old install, like --uninstall-legacy. A machine's managed settings are
# `innsegl connect --disconnect`'s to remove. It does not touch the running
# stack; it prints the command that does.
#
# `--uninstall-legacy` is separate and opt-in: it removes the OLD wiring an
# earlier version of this installer wrote directly into the harness's own
# $HOME/.claude/settings.json (six hook entries) and $HOME/.claude.json (the
# `innsegl` MCP entry). It never runs as a side effect of a plain
# --uninstall, and it never installs that wiring — only removes it.
#
# USAGE
#   install.sh [--local-client] [--dry-run] [--uninstall] [--uninstall-legacy] [DIR...]
#
# See scripts/install-selftest.sh for what this is tested against, and
# deploy/compose/README.md for what the stack this brings up actually is.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd -P)"

# Overridable so the self-test can stub bring-up and linking without touching
# Docker or a real deployment.
START_CMD="${INNSEGL_INSTALL_START_CMD:-make start}"
# Builds the binary a connected machine's hooks run, so they never run an
# old one (ENF-008).
BUILD_CMD="${INNSEGL_INSTALL_BUILD_CMD:-make build}"
# #445, ADR-0062's 2026-10-01 amendment: while no account exists yet, print
# the one-time setup link rather than leaving the operator to run
# `innsegl admin-credential enrol-code` and build the URL by hand.
SETUP_LINK_CMD="${INNSEGL_INSTALL_SETUP_LINK_CMD:-scripts/setup-link.sh}"

# The compiled innsegl binary this checkout's `make build` produces.
INNSEGL_BIN_PATH="${INNSEGL_BIN_PATH:-$ROOT/innsegl}"
LINK_CMD="${INNSEGL_INSTALL_LINK_CMD:-$INNSEGL_BIN_PATH link}"

# The gateway's CA, whose fingerprint `innsegl connect` pins.
CA_PEM="${INNSEGL_INSTALL_CA_PEM:-$HOME/.innsegl/ca/gateway-ca.pem}"

# Where an older install put the retired signer's `innsegl-commit` symlink
# (the old `make innsegl-install-signer` default), so --uninstall looks for it
# there. Nothing installs it any more.
BIN_DIR="${INNSEGL_BIN:-$HOME/.local/bin}"

# The old hook script's path, as an install from before the gateway wrote it
# into six hook entries. The script itself is gone; --uninstall-legacy matches
# entries by this path and removes them. Never installed by this script.
LEGACY_HOOK_SCRIPT="$ROOT/scripts/hooks/subagent-identity.sh"
LEGACY_MCP_URL="${INNSEGL_INSTALL_LEGACY_MCP_URL:-http://127.0.0.1:28080/}"

DRY_RUN=0
LOCAL_CLIENT=0
UNINSTALL=0
UNINSTALL_LEGACY=0
DIRS=()

usage() {
  cat <<'EOF'
usage: install.sh [--local-client] [--dry-run] [--uninstall] [--uninstall-legacy] [DIR...]

Installs the innsegl server: brings the stack up, builds the innsegl
binary, and makes each DIR signable. Every machine that runs agents, this
one included, connects to it with `innsegl connect`, which writes that
machine's managed settings, runs its client service, and can pause, update
or remove them.

  --local-client         also say how to connect THIS machine to the core
  --dry-run              print what would change; touch nothing
  --uninstall            remove the innsegl-commit symlink an older install added
  --uninstall-legacy     also remove the OLD hook-and-MCP wiring (opt-in)
EOF
}

# moved names the innsegl connect flag that replaced an install.sh one.
moved() {
  echo "install.sh: $1 moved to innsegl connect: $2" >&2
  exit 2
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --local-client) LOCAL_CLIENT=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --uninstall-legacy) UNINSTALL_LEGACY=1; shift ;;
      --hardened) moved --hardened "innsegl connect ... --hardened" ;;
      --egress-control) moved --egress-control "innsegl connect ... --hardened --egress-control <file>" ;;
      --pause) moved --pause "innsegl connect --pause" ;;
      --resume) moved --resume "innsegl connect --resume" ;;
      --managed-settings) moved --managed-settings "innsegl connect ... --managed-settings <path>" ;;
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

# ensure_ascii=False and the file's own final newline: a file this edits
# must differ only in what it changes, never in how unrelated text is spelled.
new_text = json.dumps(obj, indent=2, ensure_ascii=False)
if not old_text or old_text.endswith("\n"):
    new_text += "\n"
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
  local link="$BIN_DIR/innsegl-commit"
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -L "$link" ]; then
      printf 'install.sh: (dry run) would remove %s\n' "$link"
    else
      printf 'install.sh: %s is not present; nothing to remove\n' "$link"
    fi
  else
    echo "==> removing the old innsegl-commit symlink"
    if [ -L "$link" ]; then
      rm -f "$link"
      echo "install.sh: removed $link"
    else
      echo "install.sh: $link is not present; nothing to remove"
    fi
  fi

  cat <<'EOF'

Managed settings on a machine are innsegl connect's: `innsegl connect
--disconnect` removes them, including what an older install.sh wrote.

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
  # localhost, not 127.0.0.1: RM-260/RM-261 (ADR-0062) put the dashboard
  # behind a WebAuthn passkey sign-in, and a passkey's RP ID must be a
  # DOMAIN -- "127.0.0.1 is not a valid RP ID, localhost is". A browser
  # opened at the IP literal cannot complete a passkey ceremony against an
  # RP ID of "localhost" at all; this is the address that actually works.
  local dashboard="http://localhost:8082/"
  cat <<EOF

Ready. The server is up; this installer writes no managed settings.
Dashboard:
  $dashboard

To record agents on a machine, this one included: sign in to the
dashboard, open Account, choose "Connect a machine", and run the command it
shows on that machine. It looks like:
  innsegl connect https://<core-name>:28095 --token <ie_...> --ca-fingerprint sha256:<hex>
Add --hardened to lock the harness down, and --egress-control <file> to
limit the sandbox's network to the hosts in a file.
EOF
  if [ "$LOCAL_CLIENT" -eq 1 ]; then
    cat <<EOF
For this machine the core is https://localhost:28095, and its CA is
  $CA_PEM
EOF
  fi
  # Only while no account exists yet (scripts/setup-link.sh asks the API
  # itself, GET /api/v1/auth/setup) — a redeploy onto a database that
  # already has one prints nothing more here. A failure to ask is reported
  # by the script itself and never fails install.sh's own exit status: the
  # stack is up either way, and `scripts/setup-link.sh` can be run again by
  # hand once it is reachable.
  run_step "$SETUP_LINK_CMD" || true
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

  echo "==> building the innsegl binary"
  run_step "$BUILD_CMD"

  if [ "${#DIRS[@]}" -gt 0 ]; then
    echo "==> linking projects"
    for d in "${DIRS[@]}"; do
      run_step "$LINK_CMD $(printf '%q' "$d")"
    done
  fi

  print_finish
}

main "$@"
