#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for install.sh — RM-214.
#
# Every case runs install.sh against a scratch $HOME, with the three
# side-effecting commands (bring-up, the signer, linking) replaced by a
# recorder and a fake `docker` on PATH answering `info` and `compose
# version`. Nothing here starts Docker, brings the deployment up, or touches
# a real ~/.claude/settings.json or ~/.claude.json — see this repository's
# CLAUDE.md and the hard rule against running the real stack from an agent
# session.
#
# CASES
#   1. a missing prerequisite (curl, made unreachable via PATH) exits
#      non-zero and creates neither Claude Code file.
#   2. a fresh $HOME gets exactly the six hook entries and the one MCP entry.
#   3. a second run changes neither file and makes no second backup — the
#      merge is idempotent because it compares parsed JSON, not text.
#   4. a $HOME already holding the user's own hooks and another MCP server
#      keeps both, byte-for-byte, alongside what this installer adds.
#   5. --dry-run prints a diff and creates nothing.
#   6. --uninstall removes exactly the entries install.sh added — case 4's
#      fixture is reused so there is something of the user's to disturb —
#      and the signer symlink, leaving the user's own hooks and MCP server
#      standing.
#
# USAGE
#   scripts/install-selftest.sh
#
# Needs bash, git, make, python3 and curl on PATH (to build the stubs' own
# PATH from), and no Docker daemon.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
INSTALL="$ROOT/install.sh"
HOOK_PATH="$ROOT/scripts/hooks/subagent-identity.sh"
BASH_BIN="$(command -v bash)"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# A PATH holding every real tool install.sh's prerequisite check and its own
# logic need — git, make, python3, curl, and the coreutils install.sh and the
# stubs below call directly — plus a fake docker that answers without a
# daemon. toolbin_without removes one, so the missing-prerequisite case is
# genuinely missing rather than merely absent from a PATH that still has a
# system directory behind it.
# ---------------------------------------------------------------------------
TOOLBIN="$WORK/toolbin"
mkdir -p "$TOOLBIN"
for t in git make python3 curl dirname cat rm mkdir ln; do
  real="$(command -v "$t" 2>/dev/null)" || { echo "install-selftest: $t is not on this machine's PATH" >&2; exit 1; }
  ln -s "$real" "$TOOLBIN/$t"
done
cat > "$TOOLBIN/docker" <<'EOF'
#!/bin/sh
case "$1" in
  info) exit 0 ;;
  compose) [ "${2:-}" = version ] && exit 0 || exit 1 ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$TOOLBIN/docker"

toolbin_without() {
  local skip="$1" dir="$WORK/toolbin-no-$1"
  mkdir -p "$dir"
  local f base
  for f in "$TOOLBIN"/*; do
    base="$(basename "$f")"
    [ "$base" = "$skip" ] && continue
    ln -s "$f" "$dir/$base"
  done
  printf '%s' "$dir"
}

# ---------------------------------------------------------------------------
# Stubs that record their invocation instead of doing anything real. The
# signer stub also creates the symlink the real Makefile target would, so
# case 6 has something to prove --uninstall actually removes.
# ---------------------------------------------------------------------------
RECORD="$WORK/record"
mkdir -p "$RECORD"

make_stub() {
  local name="$1"
  local path="$WORK/stub-$name.sh"
  {
    printf '#!/bin/sh\n'
    printf 'printf '\''%%s\\n'\'' "$*" >> %s\n' "$(printf '%q' "$RECORD/$name")"
    if [ "$name" = signer ]; then
      cat <<'EOF2'
bin="${INNSEGL_BIN:-$HOME/.local/bin}"
mkdir -p "$bin"
ln -sf /bin/true "$bin/innsegl-commit"
EOF2
    fi
    printf 'exit 0\n'
  } > "$path"
  chmod +x "$path"
  printf '%s' "$path"
}
STUB_START="$(make_stub start)"
STUB_SIGNER="$(make_stub signer)"
STUB_LINK="$(make_stub link)"

# An empty override falls back to install.sh's real default ("make start"
# and friends), which is exactly what this self-test must never trigger — so
# refuse to go any further rather than run install.sh against a stub this
# test cannot prove is a stub.
[ -n "$STUB_START" ] && [ -n "$STUB_SIGNER" ] && [ -n "$STUB_LINK" ] \
  || { echo "install-selftest: a stub command came out empty — refusing to run install.sh at all" >&2; exit 1; }

run_install() {
  local home="$1" pathdir="$2"
  shift 2
  HOME="$home" PATH="$pathdir" \
    INNSEGL_INSTALL_START_CMD="$STUB_START" \
    INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
    INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
    "$BASH_BIN" "$INSTALL" "$@"
}

# check.py holds every JSON assertion below, so a case is a few short lines
# rather than an inline python -c per question asked of a fixture.
cat > "$WORK/check.py" <<'PYEOF'
import json, sys

def load(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

mode = sys.argv[1]

if mode == "hooks-ours":
    path, hook_path = sys.argv[2], sys.argv[3]
    obj = load(path)
    events = ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "PreToolUse", "PostToolUse"]
    hooks = obj.get("hooks", {})
    missing = [e for e in events if not any(
        h.get("type") == "command" and h.get("command") == hook_path
        for g in hooks.get(e, []) if isinstance(g, dict)
        for h in g.get("hooks", []) if isinstance(h, dict)
    )]
    print("ok" if not missing else "missing:" + ",".join(missing))
    sys.exit(0 if not missing else 1)

elif mode in ("hooks-command-present", "hooks-command-absent"):
    path, cmd = sys.argv[2], sys.argv[3]
    obj = load(path)
    hooks = obj.get("hooks", {})
    present = any(
        h.get("type") == "command" and h.get("command") == cmd
        for groups in hooks.values() if isinstance(groups, list)
        for g in groups if isinstance(g, dict)
        for h in g.get("hooks", []) if isinstance(h, dict)
    )
    want = mode == "hooks-command-present"
    print("ok" if present == want else ("present" if present else "absent"))
    sys.exit(0 if present == want else 1)

elif mode == "mcp-entry":
    path, name, expected_json = sys.argv[2], sys.argv[3], sys.argv[4]
    obj = load(path)
    expected = json.loads(expected_json)
    got = obj.get("mcpServers", {}).get(name)
    print("ok" if got == expected else "got:" + json.dumps(got))
    sys.exit(0 if got == expected else 1)

elif mode == "mcp-absent-entry":
    path, name = sys.argv[2], sys.argv[3]
    obj = load(path)
    absent = name not in obj.get("mcpServers", {})
    print("ok" if absent else "still present")
    sys.exit(0 if absent else 1)

elif mode == "flag-true":
    path, key = sys.argv[2], sys.argv[3]
    obj = load(path)
    is_true = obj.get(key) is True
    print("ok" if is_true else "not true")
    sys.exit(0 if is_true else 1)

else:
    print("check.py: unknown mode " + mode, file=sys.stderr)
    sys.exit(2)
PYEOF

check() { python3 "$WORK/check.py" "$@"; }

backup_count() {
  # backup_count <dir> <basename> — how many timestamped backups exist.
  local n
  n=$(find "$1" -maxdepth 1 -name "$2.bak.*" 2>/dev/null | wc -l | tr -d ' ')
  printf '%s' "$n"
}

echo "RM-214 — install.sh"

# --- case 1: a missing prerequisite refuses and changes nothing -----------
NOCURL="$(toolbin_without curl)"
home1="$WORK/home-missing"; mkdir -p "$home1"
out1="$(run_install "$home1" "$NOCURL" 2>&1)"; rc1=$?
if [ "$rc1" -ne 0 ] \
   && printf '%s' "$out1" | grep -qi 'curl' \
   && [ ! -e "$home1/.claude" ] && [ ! -e "$home1/.claude.json" ]; then
  ok "a missing prerequisite (curl) is refused and changes nothing"
else
  bad "a missing prerequisite was not refused cleanly" "exit=$rc1"$'\n'"$out1"
fi

# --- case 2: a fresh HOME gets exactly the hook and MCP entries -----------
home2="$WORK/home-fresh"; mkdir -p "$home2"
out2="$(run_install "$home2" "$TOOLBIN")"; rc2=$?
if [ "$rc2" -eq 0 ] \
   && [ "$(check hooks-ours "$home2/.claude/settings.json" "$HOOK_PATH")" = ok ] \
   && [ "$(check mcp-entry "$home2/.claude.json" innsegl '{"type": "http", "url": "http://127.0.0.1:28080/"}')" = ok ] \
   && [ "$(backup_count "$home2/.claude" settings.json)" -eq 0 ] \
   && [ "$(backup_count "$home2" .claude.json)" -eq 0 ]; then
  ok "a fresh HOME gets exactly the hook and MCP entries, with no backup to make"
else
  bad "a fresh HOME did not come out right" "exit=$rc2"$'\n'"$out2"
fi

# --- case 3: a second run is idempotent and makes no second backup --------
cp "$home2/.claude/settings.json" "$WORK/settings-before.json"
cp "$home2/.claude.json" "$WORK/claude-before.json"
run_install "$home2" "$TOOLBIN" >/dev/null 2>&1
if diff -q "$WORK/settings-before.json" "$home2/.claude/settings.json" >/dev/null 2>&1 \
   && diff -q "$WORK/claude-before.json" "$home2/.claude.json" >/dev/null 2>&1 \
   && [ "$(backup_count "$home2/.claude" settings.json)" -eq 0 ] \
   && [ "$(backup_count "$home2" .claude.json)" -eq 0 ]; then
  ok "a second run changes neither file and makes no second backup"
else
  bad "a second run was not idempotent"
fi

# --- case 4: existing user hooks and another MCP server survive ----------
home4="$WORK/home-existing"; mkdir -p "$home4/.claude"
cat > "$home4/.claude/settings.json" <<'JSON'
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/example/my-hook.sh"}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "/opt/example/session.sh"}]}
    ]
  },
  "otherUserSetting": true
}
JSON
cat > "$home4/.claude.json" <<'JSON'
{
  "mcpServers": {
    "other-server": {"type": "stdio", "command": "other-mcp"}
  }
}
JSON
out4="$(run_install "$home4" "$TOOLBIN")"; rc4=$?
if [ "$rc4" -eq 0 ] \
   && [ "$(check hooks-command-present "$home4/.claude/settings.json" /opt/example/my-hook.sh)" = ok ] \
   && [ "$(check hooks-command-present "$home4/.claude/settings.json" /opt/example/session.sh)" = ok ] \
   && [ "$(check flag-true "$home4/.claude/settings.json" otherUserSetting)" = ok ] \
   && [ "$(check hooks-ours "$home4/.claude/settings.json" "$HOOK_PATH")" = ok ] \
   && [ "$(check mcp-entry "$home4/.claude.json" other-server '{"type": "stdio", "command": "other-mcp"}')" = ok ] \
   && [ "$(check mcp-entry "$home4/.claude.json" innsegl '{"type": "http", "url": "http://127.0.0.1:28080/"}')" = ok ]; then
  ok "existing user hooks and another MCP server survive, alongside what was added"
else
  bad "existing user configuration was disturbed" "exit=$rc4"$'\n'"$out4"
fi

# --- case 5: --dry-run writes nothing --------------------------------------
home5="$WORK/home-dryrun"; mkdir -p "$home5"
before_start_n=$(wc -l < "$RECORD/start" 2>/dev/null || echo 0)
out5="$(run_install "$home5" "$TOOLBIN" --dry-run)"; rc5=$?
after_start_n=$(wc -l < "$RECORD/start" 2>/dev/null || echo 0)
if [ "$rc5" -eq 0 ] \
   && [ ! -e "$home5/.claude" ] && [ ! -e "$home5/.claude.json" ] \
   && printf '%s' "$out5" | grep -qi 'dry run' \
   && [ "$before_start_n" = "$after_start_n" ]; then
  ok "--dry-run prints what would change and writes nothing"
else
  bad "--dry-run left something behind, or ran a side-effecting step" "exit=$rc5"$'\n'"$out5"
fi

# --- case 6: --uninstall removes only what was added -----------------------
out6="$(run_install "$home4" "$TOOLBIN" --uninstall)"; rc6=$?
if [ "$rc6" -eq 0 ] \
   && [ "$(check hooks-command-present "$home4/.claude/settings.json" /opt/example/my-hook.sh)" = ok ] \
   && [ "$(check hooks-command-present "$home4/.claude/settings.json" /opt/example/session.sh)" = ok ] \
   && [ "$(check flag-true "$home4/.claude/settings.json" otherUserSetting)" = ok ] \
   && [ "$(check hooks-command-absent "$home4/.claude/settings.json" "$HOOK_PATH")" = ok ] \
   && [ "$(check mcp-entry "$home4/.claude.json" other-server '{"type": "stdio", "command": "other-mcp"}')" = ok ] \
   && [ "$(check mcp-absent-entry "$home4/.claude.json" innsegl)" = ok ] \
   && [ ! -e "$home4/.local/bin/innsegl-commit" ]; then
  ok "--uninstall removes exactly what was added, and the signer symlink"
else
  bad "--uninstall left something behind, or removed too much" "exit=$rc6"$'\n'"$out6"
fi

echo
echo "install-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
