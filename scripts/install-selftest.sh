#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for install.sh, the server installer — RM-245 (#390), RM-285
# (#461), ADR-0063.
#
# install.sh brings the stack up, builds the binary, links each DIR, and
# prints how a machine connects. It writes no harness settings: every machine,
# the core host included, connects with `innsegl connect`, whose own tests
# hold the managed settings contract (ENF-006, ENF-009, RM-312, EGR-001 in
# cmd/innsegl and internal/client).
#
# Every case runs install.sh against a scratch $HOME. The side-effecting
# commands (bring-up, the build, linking, the setup link) are
# replaced by recorders, and a fake `docker` on PATH answers `info` and
# `compose version` without a daemon. Nothing here starts Docker or touches a
# real Claude Code configuration file.
#
# USAGE
#   scripts/install-selftest.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
INSTALL="$ROOT/install.sh"
BASH_BIN="$(command -v bash)"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/install-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# A PATH holding every tool install.sh's own body and the stubs below call
# directly. python3 and the coreutils must be real. git, make, curl and uname
# are preferred real; toolbin_without removes one so the missing-prerequisite
# case is genuinely missing rather than merely absent from a PATH that still
# has a system directory behind it.
# ---------------------------------------------------------------------------
TOOLBIN="$WORK/toolbin"
mkdir -p "$TOOLBIN"

require_real() {
  local t="$1" real
  real="$(command -v "$t" 2>/dev/null)" || { echo "install-selftest: $t is not on this machine's PATH" >&2; exit 1; }
  ln -s "$real" "$TOOLBIN/$t"
}
prefer_real() {
  local t="$1" real
  real="$(command -v "$t" 2>/dev/null)" || real=""
  if [ -n "$real" ]; then
    ln -s "$real" "$TOOLBIN/$t"
  else
    # No real tool on this host. A no-op stand-in is enough: install.sh only
    # ever checks that one of these resolves (`command -v`), and every
    # side-effecting command it could run through one is stubbed below.
    printf '#!/bin/sh\nexit 0\n' > "$TOOLBIN/$t"
    chmod +x "$TOOLBIN/$t"
  fi
}
for t in python3 dirname cat rm mkdir ln mktemp grep; do require_real "$t"; done
for t in git make curl uname; do prefer_real "$t"; done

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
# Stubs that record their invocation instead of doing anything real.
# ---------------------------------------------------------------------------
RECORD="$WORK/record"
mkdir -p "$RECORD"

make_stub() {
  local name="$1"
  local path="$WORK/stub-$name.sh"
  {
    printf '#!/bin/sh\n'
    printf 'printf '\''%%s\\n'\'' "$*" >> %s\n' "$(printf '%q' "$RECORD/$name")"
    printf 'exit 0\n'
  } > "$path"
  chmod +x "$path"
  printf '%s' "$path"
}
STUB_START="$(make_stub start)"
STUB_BUILD="$(make_stub build)"
export INNSEGL_INSTALL_BUILD_CMD="$STUB_BUILD"
STUB_LINK="$(make_stub link)"
STUB_SETUP_LINK="$(make_stub setup-link)"

# The innsegl binary install.sh requires to exist. Nothing here runs it.
STUB_BIN="$WORK/stub-innsegl-bin"
printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN"
chmod +x "$STUB_BIN"

# An empty override falls back to install.sh's real default ("make start" and
# friends), which is exactly what this self-test must never trigger — so
# refuse to go any further rather than run install.sh against a stub this
# test cannot prove is a stub.
[ -n "$STUB_START" ] && [ -n "$STUB_LINK" ] && [ -n "$STUB_BIN" ] && [ -n "$STUB_SETUP_LINK" ] \
  || { echo "install-selftest: a stub command came out empty — refusing to run install.sh at all" >&2; exit 1; }

run_install_server() {
  local home="$1" pathdir="$2"
  shift 2
  HOME="$home" PATH="$pathdir" \
    INNSEGL_INSTALL_START_CMD="$STUB_START" \
    INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
    INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
    INNSEGL_BIN_PATH="$STUB_BIN" \
    "$BASH_BIN" "$INSTALL" "$@"
}

# check.py holds every JSON assertion below: two generic, path-based modes
# instead of one hand-rolled question per fixture, since the contract this
# installer writes is one JSON object with several independent corners.
cat > "$WORK/check.py" <<'PYEOF'
import json, sys

def load(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def get(obj, dotted):
    cur = obj
    if not dotted:
        return cur, True
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            idx = int(part)
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return None, False
        else:
            return None, False
    return cur, True

mode = sys.argv[1]

if mode == "json-equal":
    path, dotted, expected_json = sys.argv[2], sys.argv[3], sys.argv[4]
    obj = load(path)
    cur, present = get(obj, dotted)
    expected = json.loads(expected_json)
    same = present and cur == expected
    print("ok" if same else "got:" + json.dumps(cur))
    sys.exit(0 if same else 1)

elif mode == "json-keys":
    path, expected_json = sys.argv[2], sys.argv[3]
    keys = sorted(load(path).keys())
    same = keys == json.loads(expected_json)
    print("ok" if same else "keys:" + json.dumps(keys))
    sys.exit(0 if same else 1)

elif mode == "json-absent":
    path, dotted = sys.argv[2], sys.argv[3]
    obj = load(path)
    cur, present = get(obj, dotted)
    print("ok" if not present else "still present:" + json.dumps(cur))
    sys.exit(0 if not present else 1)

else:
    print("check.py: unknown mode " + mode, file=sys.stderr)
    sys.exit(2)
PYEOF

check() { python3 "$WORK/check.py" "$@"; }

# --- a missing prerequisite is refused, and nothing runs --------------------
home1="$WORK/home-missing"; mkdir -p "$home1"
: > "$RECORD/start"
out1="$(run_install_server "$home1" "$(toolbin_without curl)" 2>&1)"; rc1=$?
if [ "$rc1" -ne 0 ] && printf '%s' "$out1" | grep -q 'missing prerequisite: curl' && [ ! -s "$RECORD/start" ]; then
  ok "a missing prerequisite is refused before anything runs"
else
  bad "a missing prerequisite was not refused, or something ran" "exit=$rc1"$'\n'"$out1"
fi

# --- the server install runs each step, writes no settings, and says how to connect
home2="$WORK/home-server"; mkdir -p "$home2"
: > "$RECORD/start"; : > "$RECORD/build"; : > "$RECORD/link"; : > "$RECORD/setup-link"
out2="$(run_install_server "$home2" "$TOOLBIN" "$home2/project" 2>&1)"; rc2=$?
if [ "$rc2" -eq 0 ] && [ -s "$RECORD/start" ] && [ -s "$RECORD/build" ] && [ -s "$RECORD/setup-link" ] \
   && grep -q "project" "$RECORD/link" && [ ! -L "$home2/.local/bin/innsegl-commit" ] \
   && [ ! -e "$home2/.claude" ] \
   && printf '%s' "$out2" | grep -q 'innsegl connect https://<core-name>:28095'; then
  ok "the server install brings the stack up, builds, links, puts no signer on PATH, writes no harness settings, and says how to connect"
else
  bad "the server install did not run every step, or wrote harness settings" "exit=$rc2"$'\n'"$out2"
fi

# --- --local-client names this machine's core and CA ------------------------
out3="$(run_install_server "$home2" "$TOOLBIN" --local-client 2>&1)"; rc3=$?
if [ "$rc3" -eq 0 ] && printf '%s' "$out3" | grep -q 'https://localhost:28095' \
   && printf '%s' "$out3" | grep -q 'gateway-ca.pem' && [ ! -e "$home2/.claude" ]; then
  ok "--local-client says how to connect this machine, and writes nothing for it"
else
  bad "--local-client did not say how to connect this machine" "exit=$rc3"$'\n'"$out3"
fi

# --- --dry-run runs none of the steps ----------------------------------------
home4="$WORK/home-dry"; mkdir -p "$home4"
: > "$RECORD/start"; : > "$RECORD/link"
out4="$(run_install_server "$home4" "$TOOLBIN" --dry-run "$home4/project" 2>&1)"; rc4=$?
if [ "$rc4" -eq 0 ] && [ ! -s "$RECORD/start" ] && [ ! -s "$RECORD/link" ] \
   && printf '%s' "$out4" | grep -q '(dry run) would run'; then
  ok "--dry-run prints the steps and runs none"
else
  bad "--dry-run ran a step" "exit=$rc4"$'\n'"$out4"
fi

# --- the settings flags moved to innsegl connect, and say so ----------------
for flag in --hardened --egress-control --pause --resume --managed-settings; do
  out5="$(run_install_server "$home4" "$TOOLBIN" "$flag" 2>&1)"; rc5=$?
  if [ "$rc5" -eq 2 ] && printf '%s' "$out5" | grep -q "moved to innsegl connect"; then
    ok "$flag is refused and names innsegl connect"
  else
    bad "$flag was not refused with a pointer to innsegl connect" "exit=$rc5"$'\n'"$out5"
  fi
done

# --- --uninstall removes an older install's innsegl-commit symlink ----------
# The retired signer's symlink is planted the way an older install left it:
# nothing installs it now, and --uninstall still cleans it up.
mkdir -p "$home2/.local/bin"
ln -sf /bin/true "$home2/.local/bin/innsegl-commit"
out6="$(run_install_server "$home2" "$TOOLBIN" --uninstall 2>&1)"; rc6=$?
if [ "$rc6" -eq 0 ] && [ ! -L "$home2/.local/bin/innsegl-commit" ] \
   && printf '%s' "$out6" | grep -q 'innsegl connect' && printf '%s' "$out6" | grep -q -- '--disconnect'; then
  ok "--uninstall removes an old innsegl-commit symlink and names innsegl connect --disconnect"
else
  bad "--uninstall did not remove the symlink, or named nothing for the settings" "exit=$rc6"$'\n'"$out6"
fi

# --- --uninstall-legacy touches only the OLD wiring -------------------------
home9="$WORK/home-legacy"; mkdir -p "$home9/.claude"
hook_path9="$ROOT/scripts/hooks/subagent-identity.sh"
cat > "$home9/.claude/settings.json" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "$hook_path9"}]},
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/example/my-hook.sh"}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "$hook_path9"}]},
      {"hooks": [{"type": "command", "command": "/opt/example/session.sh"}]}
    ]
  },
  "otherUserSetting": true
}
JSON
cat > "$home9/.claude.json" <<'JSON'
{
  "mcpServers": {
    "innsegl": {"type": "http", "url": "http://127.0.0.1:28080/"},
    "other-server": {"type": "stdio", "command": "other-mcp"}
  }
}
JSON
out9="$(run_install_server "$home9" "$TOOLBIN" --uninstall-legacy)"; rc9=$?
if [ "$rc9" -eq 0 ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" hooks.PreToolUse.0.hooks.0.command '"/opt/example/my-hook.sh"')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" 'hooks.PreToolUse' '[{"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/example/my-hook.sh"}]}]')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" 'hooks.SessionStart' '[{"hooks": [{"type": "command", "command": "/opt/example/session.sh"}]}]')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" otherUserSetting true)" = ok ] \
   && [ "$(check json-absent "$home9/.claude.json" mcpServers.innsegl)" = ok ] \
   && [ "$(check json-equal "$home9/.claude.json" mcpServers.other-server '{"type": "stdio", "command": "other-mcp"}')" = ok ]; then
  ok "--uninstall-legacy removes only the six old hook entries and the innsegl MCP entry"
else
  bad "--uninstall-legacy touched more, or less, than the old wiring" "exit=$rc9"$'\n'"$out9"
fi

echo "install-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
