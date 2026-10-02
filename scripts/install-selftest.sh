#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for install.sh — RM-245 (#390), RM-248 (#393), epic #361 E18.
#
# install.sh used to wire an OLD hook-and-MCP design into the harness's own
# $HOME/.claude/settings.json and $HOME/.claude.json. This tests the GATEWAY
# design that replaced it: a managed-settings.json that routes every request
# through the gateway, registers the PreToolUse and session hooks, and denies a
# sandboxed shell innsegl's own stores and the container socket.
#
# Every case runs install.sh against a scratch $HOME and a scratch managed
# settings target — never the operator's real ~/.claude/*, ~/.claude.json, or
# a real /Library or /etc path. The three side-effecting commands (bring-up,
# the signer, linking) are replaced by a recorder, and a fake `docker` on
# PATH answers `info` and `compose version` without a daemon. Nothing here
# starts Docker, brings the deployment up, or touches a real Claude Code
# configuration file — see this repository's CLAUDE.md and the hard rule
# against running the real stack from an agent session.
#
# CASES
#   ENF-001 — the managed settings contract (#390):
#     - a missing prerequisite (curl) is refused and changes nothing
#     - a fresh target gets exactly the env, hook and attribution keys —
#       the route and innsegl's own hooks, no lockdown (RM-312) — with no
#       backup to make
#     - a second run changes neither file, and makes no second backup — the
#       merge is idempotent because it compares parsed JSON, not text
#     - an existing target holding the operator's own env vars, hooks and
#       sandbox settings keeps them, byte-for-byte, alongside what this
#       installer adds — and is backed up, timestamped, before that change
#     - --dry-run prints a diff and creates nothing
#     - --uninstall removes exactly the keys install.sh added, leaving the
#       operator's own settings standing
#     - a non-writable target prints the one-line admin command and changes
#       nothing
#   RM-312 — --hardened is the opt-in lockdown:
#     - it adds allowManagedHooksOnly, bypass mode disabled and the sandbox
#       (with gh excluded and the weaker network isolation gh needs), and
#       copies the user's own statusLine into the managed settings
#     - a plain run over a file the old default locked down removes exactly
#       the lockdown keys, and keeps the operator's own sandbox path,
#       permission rule and statusLine
#     - --uninstall after --hardened leaves no innsegl key, the statusLine
#       copy included
#   EGR-001 — optional egress control (#393), under --hardened:
#     - --egress-control writes the strict, managed-only allowlist with the
#       model hosts (api.anthropic.com and the configured upstream) removed
#     - a second run is idempotent
#
#   The server installer (#461): install.sh writes managed settings only with
#   --local-client, the single-host shape every case above runs under. A run
#   without it brings the server up, links, and writes no managed settings;
#   --egress-control without it is refused, since it shapes only those, and
#   so is --egress-control without --hardened, since it shapes the sandbox.
#
#   --uninstall-legacy is also covered: it is the only mode that touches the
#   OLD wiring (the six subagent-identity.sh hook entries and the `innsegl`
#   MCP entry), and only ever removes it — never installs it, never runs
#   silently alongside a plain --uninstall.
#
# USAGE
#   scripts/install-selftest.sh
#
# Needs bash and python3 on PATH for real. git, make, curl and uname are
# preferred real (so a genuinely-missing one — case ENF-001's first case
# removes curl on purpose — is genuinely missing) but fall back to a no-op
# stand-in when absent, because nothing here ever shells out to the real
# thing: every side-effecting command install.sh can run is stubbed below.

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
# Stubs that record their invocation instead of doing anything real. The
# signer stub also creates the symlink the real Makefile target would.
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
# Every case below has a gateway that answers, except ENF-007, which has none.
export INNSEGL_INSTALL_GATEWAY_PROBE_CMD=true
# The build is stubbed too; ENF-008 hands install.sh a binary that is stale.
export INNSEGL_INSTALL_BUILD_CMD=true
STUB_SIGNER="$(make_stub signer)"
STUB_LINK="$(make_stub link)"
STUB_SETUP_LINK="$(make_stub setup-link)"

# The innsegl binary the hook command points at. It never has to run
# anything real for these cases: only its path is asserted.
STUB_BIN="$WORK/stub-innsegl-bin"
printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN"
chmod +x "$STUB_BIN"

# An empty override falls back to install.sh's real default ("make start" and
# friends), which is exactly what this self-test must never trigger — so
# refuse to go any further rather than run install.sh against a stub this
# test cannot prove is a stub.
[ -n "$STUB_START" ] && [ -n "$STUB_SIGNER" ] && [ -n "$STUB_LINK" ] && [ -n "$STUB_BIN" ] && [ -n "$STUB_SETUP_LINK" ] \
  || { echo "install-selftest: a stub command came out empty — refusing to run install.sh at all" >&2; exit 1; }

run_install_server() {
  local home="$1" pathdir="$2"
  shift 2
  HOME="$home" PATH="$pathdir" \
    INNSEGL_INSTALL_START_CMD="$STUB_START" \
    INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
    INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
    INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
    INNSEGL_BIN_PATH="$STUB_BIN" \
    "$BASH_BIN" "$INSTALL" "$@"
}

# The managed-settings cases below are the single-host shape, which install.sh
# keeps behind --local-client since it became the server installer (#461).
run_install() {
  local home="$1" pathdir="$2"
  shift 2
  run_install_server "$home" "$pathdir" --local-client "$@"
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

backup_count() {
  # backup_count <dir> <basename> — how many timestamped backups exist.
  local n
  n=$(find "$1" -maxdepth 1 -name "$2.bak.*" 2>/dev/null | wc -l | tr -d ' ')
  printf '%s' "$n"
}

echo "install.sh — ENF-001 / EGR-001"

# --- a missing prerequisite refuses and changes nothing --------------------
NOCURL="$(toolbin_without curl)"
home1="$WORK/home-missing"; mkdir -p "$home1"
ms1="$home1/managed-settings.json"
out1="$(run_install "$home1" "$NOCURL" --managed-settings "$ms1" 2>&1)"; rc1=$?
if [ "$rc1" -ne 0 ] \
   && printf '%s' "$out1" | grep -qi 'curl' \
   && [ ! -e "$ms1" ]; then
  ok "a missing prerequisite (curl) is refused and changes nothing"
else
  bad "a missing prerequisite was not refused cleanly" "exit=$rc1"$'\n'"$out1"
fi

# --- ENF-001: a fresh target gets exactly the contract ----------------------
home2="$WORK/home-fresh"; mkdir -p "$home2"
ms2="$home2/managed-settings.json"
out2="$(run_install "$home2" "$TOOLBIN" --managed-settings "$ms2")"; rc2=$?
expected_env2=$(cat <<JSON
{
  "ANTHROPIC_BASE_URL": "https://127.0.0.1:28095",
  "NODE_EXTRA_CA_CERTS": "$home2/.innsegl/ca/gateway-ca.pem",
  "INNSEGL_CORE_URL": "https://127.0.0.1:28095",
  "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
  "OTEL_LOGS_EXPORTER": "otlp",
  "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
  "OTEL_EXPORTER_OTLP_ENDPOINT": "https://127.0.0.1:28095",
  "ENABLE_TOOL_SEARCH": "true"
}
JSON
)
expected_hooks2=$(cat <<JSON
{"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$STUB_BIN hook pre-tool-use"}]}],
 "SessionStart": [{"hooks": [{"type": "command", "command": "$STUB_BIN hook session"}]}],
 "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "$STUB_BIN hook session"}]}],
 "SubagentStart": [{"hooks": [{"type": "command", "command": "$STUB_BIN hook session"}]}],
 "CwdChanged": [{"hooks": [{"type": "command", "command": "$STUB_BIN hook session"}]}]}
JSON
)
if [ "$rc2" -eq 0 ] \
   && [ "$(check json-equal "$ms2" env "$expected_env2")" = ok ] \
   && [ "$(check json-equal "$ms2" hooks "$expected_hooks2")" = ok ] \
   && [ "$(check json-equal "$ms2" attribution '{"commit": ""}')" = ok ] \
   && [ "$(check json-keys "$ms2" '["attribution", "env", "hooks"]')" = ok ] \
   && [ "$(backup_count "$home2" managed-settings.json)" -eq 0 ]; then
  ok "ENF-001 a fresh target gets exactly the env, hook and attribution keys, no lockdown, with no backup to make"
else
  bad "ENF-001 a fresh target did not come out right" "exit=$rc2"$'\n'"$out2"
fi

# --- ENF-001: a second run is idempotent and makes no second backup --------
cp "$ms2" "$WORK/ms2-before.json"
run_install "$home2" "$TOOLBIN" --managed-settings "$ms2" >/dev/null 2>&1
if diff -q "$WORK/ms2-before.json" "$ms2" >/dev/null 2>&1 \
   && [ "$(backup_count "$home2" managed-settings.json)" -eq 0 ]; then
  ok "ENF-001 a second run changes nothing and makes no second backup"
else
  bad "ENF-001 a second run was not idempotent"
fi

# --- ENF-001: an operator's own settings survive, and get backed up --------
home4="$WORK/home-existing"; mkdir -p "$home4"
ms4="$home4/managed-settings.json"
cat > "$ms4" <<JSON
{
  "env": {"HTTPS_PROXY": "http://example.invalid:3128"},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/example/my-hook.sh"}]}
    ]
  },
  "permissions": {"allow": ["Read(//tmp/**)"]},
  "sandbox": {"filesystem": {"denyRead": ["/opt/example/secret"]}},
  "otherOperatorSetting": true
}
JSON
out4="$(run_install "$home4" "$TOOLBIN" --managed-settings "$ms4")"; rc4=$?
if [ "$rc4" -eq 0 ] \
   && [ "$(check json-equal "$ms4" env.HTTPS_PROXY '"http://example.invalid:3128"')" = ok ] \
   && [ "$(check json-equal "$ms4" env.ANTHROPIC_BASE_URL '"https://127.0.0.1:28095"')" = ok ] \
   && [ "$(check json-equal "$ms4" hooks.PreToolUse.0.hooks.0.command '"/opt/example/my-hook.sh"')" = ok ] \
   && [ "$(check json-equal "$ms4" hooks.PreToolUse.1.hooks.0.command "\"$STUB_BIN hook pre-tool-use\"")" = ok ] \
   && [ "$(check json-equal "$ms4" permissions '{"allow": ["Read(//tmp/**)"]}')" = ok ] \
   && [ "$(check json-equal "$ms4" sandbox '{"filesystem": {"denyRead": ["/opt/example/secret"]}}')" = ok ] \
   && [ "$(check json-equal "$ms4" otherOperatorSetting true)" = ok ] \
   && [ "$(backup_count "$home4" managed-settings.json)" -eq 1 ]; then
  ok "ENF-001 an operator's own env, hooks, permissions and sandbox settings survive, and are backed up first"
else
  bad "ENF-001 existing operator configuration was disturbed" "exit=$rc4"$'\n'"$out4"
fi

# --- ENF-001: --dry-run writes nothing --------------------------------------
home5="$WORK/home-dryrun"; mkdir -p "$home5"
ms5="$home5/managed-settings.json"
before_start_n=$(wc -l < "$RECORD/start" 2>/dev/null || echo 0)
out5="$(run_install "$home5" "$TOOLBIN" --managed-settings "$ms5" --dry-run)"; rc5=$?
after_start_n=$(wc -l < "$RECORD/start" 2>/dev/null || echo 0)
if [ "$rc5" -eq 0 ] \
   && [ ! -e "$ms5" ] \
   && printf '%s' "$out5" | grep -qi 'dry run' \
   && [ "$before_start_n" = "$after_start_n" ]; then
  ok "ENF-001 --dry-run prints what would change and writes nothing"
else
  bad "ENF-001 --dry-run left something behind, or ran a side-effecting step" "exit=$rc5"$'\n'"$out5"
fi

# --- ENF-001: --uninstall removes only what was added -----------------------
out6="$(run_install "$home4" "$TOOLBIN" --managed-settings "$ms4" --uninstall)"; rc6=$?
if [ "$rc6" -eq 0 ] \
   && [ "$(check json-equal "$ms4" env.HTTPS_PROXY '"http://example.invalid:3128"')" = ok ] \
   && [ "$(check json-absent "$ms4" env.ANTHROPIC_BASE_URL)" = ok ] \
   && [ "$(check json-absent "$ms4" env.INNSEGL_CORE_URL)" = ok ] \
   && [ "$(check json-equal "$ms4" hooks.PreToolUse.0.hooks.0.command '"/opt/example/my-hook.sh"')" = ok ] \
   && [ "$(check json-absent "$ms4" hooks.SessionStart)" = ok ] \
   && [ "$(check json-absent "$ms4" hooks.UserPromptSubmit)" = ok ] \
   && [ "$(check json-absent "$ms4" hooks.SubagentStart)" = ok ] \
   && [ "$(check json-absent "$ms4" hooks.CwdChanged)" = ok ] \
   && [ "$(check json-equal "$ms4" permissions.allow '["Read(//tmp/**)"]')" = ok ] \
   && [ "$(check json-absent "$ms4" permissions.disableBypassPermissionsMode)" = ok ] \
   && [ "$(check json-absent "$ms4" allowManagedHooksOnly)" = ok ] \
   && [ "$(check json-absent "$ms4" attribution)" = ok ] \
   && [ "$(check json-equal "$ms4" sandbox.filesystem.denyRead '["/opt/example/secret"]')" = ok ] \
   && [ "$(check json-equal "$ms4" otherOperatorSetting true)" = ok ] \
   && [ ! -e "$home4/.local/bin/innsegl-commit" ]; then
  ok "ENF-001 --uninstall removes exactly what was added, and the signer symlink"
else
  bad "ENF-001 --uninstall left something behind, or removed too much" "exit=$rc6"$'\n'"$out6"
fi

# --- RM-312: --hardened adds the lockdown and copies the user's statusLine --
home2h="$WORK/home-hardened"; mkdir -p "$home2h/.claude"
ms2h="$home2h/managed-settings.json"
cat > "$home2h/.claude/settings.json" <<'JSON'
{"theme": "dark", "statusLine": {"type": "command", "command": "/opt/example/statusline.sh"}}
JSON
out2h="$(run_install "$home2h" "$TOOLBIN" --managed-settings "$ms2h" --hardened)"; rc2h=$?
expected_sandbox2h=$(cat <<JSON
{
  "enabled": true,
  "allowUnsandboxedCommands": false,
  "failIfUnavailable": true,
  "excludedCommands": ["gh *"],
  "enableWeakerNetworkIsolation": true,
  "filesystem": {"denyRead": ["$home2h/.innsegl"], "allowRead": ["$home2h/.innsegl/ca"]},
  "network": {"allowLocalBinding": true}
}
JSON
)
if [ "$rc2h" -eq 0 ] \
   && [ "$(check json-equal "$ms2h" allowManagedHooksOnly true)" = ok ] \
   && [ "$(check json-equal "$ms2h" attribution.commit '""')" = ok ] \
   && [ "$(check json-equal "$ms2h" permissions '{"disableBypassPermissionsMode": "disable"}')" = ok ] \
   && [ "$(check json-equal "$ms2h" sandbox "$expected_sandbox2h")" = ok ] \
   && [ "$(check json-equal "$ms2h" statusLine '{"type": "command", "command": "/opt/example/statusline.sh"}')" = ok ] \
   && [ "$(check json-keys "$ms2h" '["allowManagedHooksOnly", "attribution", "env", "hooks", "permissions", "sandbox", "statusLine"]')" = ok ]; then
  ok "RM-312 --hardened adds the lockdown, excludes gh, and copies the user's statusLine"
else
  bad "RM-312 --hardened did not write the lockdown" "exit=$rc2h"$'\n'"$out2h"$'\n'"$(cat "$ms2h" 2>&1)"
fi
out2h2="$(run_install "$home2h" "$TOOLBIN" --managed-settings "$ms2h" --hardened 2>&1)"; rc2h2=$?
if [ "$rc2h2" -eq 0 ] && printf '%s' "$out2h2" | grep -q 'already up to date'; then
  ok "RM-312 a second --hardened run changes nothing"
else
  bad "RM-312 a second --hardened run was not idempotent" "exit=$rc2h2"$'\n'"$out2h2"
fi
out2h3="$(run_install "$home2h" "$TOOLBIN" --managed-settings "$ms2h" --uninstall)"; rc2h3=$?
if [ "$rc2h3" -eq 0 ] && [ "$(check json-keys "$ms2h" '[]')" = ok ]; then
  ok "RM-312 --uninstall after --hardened leaves no innsegl key, the statusLine copy included"
else
  bad "RM-312 --uninstall after --hardened left something" "exit=$rc2h3"$'\n'"$out2h3"$'\n'"$(cat "$ms2h" 2>&1)"
fi

# --- RM-312: a plain run over the old default lockdown removes only it -----
home2u="$WORK/home-update"; mkdir -p "$home2u/.claude"
ms2u="$home2u/managed-settings.json"
cat > "$home2u/.claude/settings.json" <<'JSON'
{"statusLine": {"type": "command", "command": "/opt/example/statusline.sh"}}
JSON
cat > "$ms2u" <<JSON
{
  "model": "opus",
  "env": {"ANTHROPIC_BASE_URL": "https://127.0.0.1:28095"},
  "allowManagedHooksOnly": true,
  "attribution": {"commit": ""},
  "permissions": {"deny": ["Read(./secrets/**)"], "disableBypassPermissionsMode": "disable"},
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "failIfUnavailable": true,
    "filesystem": {"denyRead": ["/opt/example/secret", "$home2u/.innsegl"], "allowRead": ["$home2u/.innsegl/ca"]},
    "network": {"allowLocalBinding": true}
  },
  "statusLine": {"type": "command", "command": "/opt/operator/managed-status.sh"}
}
JSON
out2u="$(run_install "$home2u" "$TOOLBIN" --managed-settings "$ms2u")"; rc2u=$?
if [ "$rc2u" -eq 0 ] \
   && [ "$(check json-absent "$ms2u" allowManagedHooksOnly)" = ok ] \
   && [ "$(check json-equal "$ms2u" permissions '{"deny": ["Read(./secrets/**)"]}')" = ok ] \
   && [ "$(check json-equal "$ms2u" sandbox '{"filesystem": {"denyRead": ["/opt/example/secret"]}}')" = ok ] \
   && [ "$(check json-equal "$ms2u" statusLine '{"type": "command", "command": "/opt/operator/managed-status.sh"}')" = ok ] \
   && [ "$(check json-equal "$ms2u" model '"opus"')" = ok ] \
   && [ "$(check json-keys "$ms2u" '["attribution", "env", "hooks", "model", "permissions", "sandbox", "statusLine"]')" = ok ] \
   && [ "$(backup_count "$home2u" managed-settings.json)" -eq 1 ]; then
  ok "RM-312 a plain run over the old lockdown removes exactly the lockdown keys and keeps the operator's own"
else
  bad "RM-312 a plain run over the old lockdown removed too much, or too little" "exit=$rc2u"$'\n'"$out2u"$'\n'"$(cat "$ms2u" 2>&1)"
fi

# --- ENF-001: a non-writable target prints the admin command ---------------
home7="$WORK/home-nonwritable"; mkdir -p "$home7"
blocked="$home7/blocked-file"
: > "$blocked"
ms7="$blocked/managed-settings.json"   # parent is a FILE — cannot be mkdir -p'd, root-proof
out7="$(run_install "$home7" "$TOOLBIN" --managed-settings "$ms7" 2>&1)"; rc7=$?
if [ "$rc7" -ne 0 ] \
   && printf '%s' "$out7" | grep -qi 'sudo' \
   && [ ! -e "$ms7" ] \
   && [ -f "$blocked" ]; then
  ok "ENF-001 a non-writable target prints the admin command and changes nothing"
else
  bad "ENF-001 a non-writable target did not refuse cleanly" "exit=$rc7"$'\n'"$out7"
fi

# --- ENF-001: the admin command leaves a file the harness can read ---------
# Measured on 2026-10-01: the printed `sudo cp` kept the temp file's 0600, so
# the installed settings were root-only and Claude Code, running as the user,
# could not read them. Run the printed command without sudo against a
# writable stand-in for the same path, and read the mode it leaves.
admin_line="$(printf '%s\n' "$out7" | grep '^  sudo ' | head -1)"
dest7="$WORK/admin-dest"
cmd7="${admin_line//sudo /}"
cmd7="${cmd7//$blocked/$dest7}"
if [ -n "$admin_line" ] && (eval "$cmd7") 2>/dev/null \
   && [ "$(python3 -c 'import os,sys;print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$dest7/managed-settings.json")" = 0o644 ]; then
  ok "ENF-001 the printed admin command installs the settings world-readable (0644)"
else
  bad "ENF-001 the printed admin command does not leave a readable file" "line: $admin_line"$'\n'"ran: $cmd7"$'\n'"$(ls -l "$dest7" 2>&1)"
fi

# --- ENF-007: no managed settings while the gateway does not answer --------
# The settings send every Claude Code request on this machine to the gateway.
# Measured on 2026-10-01: a plain install brought the stack up without it
# (the compose default named no gateway), so writing them would have broken
# every session. The install must stop first.
home7g="$WORK/home-no-gateway"; mkdir -p "$home7g"
ms7g="$home7g/managed-settings.json"
out7g="$(HOME="$home7g" PATH="$TOOLBIN" \
  INNSEGL_INSTALL_START_CMD="$STUB_START" \
  INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
  INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
  INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
  INNSEGL_BIN_PATH="$STUB_BIN" \
  INNSEGL_INSTALL_GATEWAY_PROBE_CMD=false INNSEGL_INSTALL_GATEWAY_TRIES=1 \
  "$BASH_BIN" "$INSTALL" --local-client --managed-settings "$ms7g" 2>&1)"
rc7g=$?
if [ "$rc7g" -ne 0 ] && [ ! -e "$ms7g" ] && printf '%s' "$out7g" | grep -q 'gateway'; then
  ok "ENF-007 a gateway that does not answer stops the install before the settings are written"
else
  bad "ENF-007 the install wrote settings, or passed, with no gateway" "exit=$rc7g file=$( [ -e "$ms7g" ] && echo present || echo absent )"$'\n'"$out7g"
fi

# --- ENF-008: no managed settings naming a hook that does not run ----------
# Measured on 2026-10-01: the settings named a binary built weeks earlier,
# which answered `hook pre-tool-use` with "unknown subcommand" and exit 2.
# For a PreToolUse hook, exit 2 blocks the tool: every Bash call in every new
# session would have been refused.
home8s="$WORK/home-stale-bin"; mkdir -p "$home8s"
ms8s="$home8s/managed-settings.json"
stale_bin="$WORK/stale-innsegl"
printf '#!/bin/sh\necho "innsegl: unknown subcommand \"$1\"" >&2\nexit 2\n' > "$stale_bin"
chmod +x "$stale_bin"
out8s="$(HOME="$home8s" PATH="$TOOLBIN" \
  INNSEGL_INSTALL_START_CMD="$STUB_START" \
  INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
  INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
  INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
  INNSEGL_BIN_PATH="$stale_bin" \
  "$BASH_BIN" "$INSTALL" --local-client --managed-settings "$ms8s" 2>&1)"
rc8s=$?
if [ "$rc8s" -ne 0 ] && [ ! -e "$ms8s" ] && printf '%s' "$out8s" | grep -q 'hook'; then
  ok "ENF-008 a hook binary that does not run stops the install before the settings are written"
else
  bad "ENF-008 the install wrote settings naming a hook that does not run" "exit=$rc8s file=$( [ -e "$ms8s" ] && echo present || echo absent )"$'\n'"$out8s"
fi

# --- EGR-001: --egress-control locks the sandbox to a managed allowlist ----
home8="$WORK/home-egress"; mkdir -p "$home8"
ms8="$home8/managed-settings.json"
allowlist8="$WORK/allowlist.txt"
cat > "$allowlist8" <<'TXT'
# operator's own list — comments and blank lines are ignored

api.anthropic.com
github.com
registry.npmjs.org
upstream.example.invalid
TXT
out8="$(HOME="$home8" PATH="$TOOLBIN" \
  INNSEGL_INSTALL_START_CMD="$STUB_START" \
  INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
  INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
  INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
  INNSEGL_BIN_PATH="$STUB_BIN" \
  INNSEGL_GATEWAY_UPSTREAM="https://upstream.example.invalid" \
  "$BASH_BIN" "$INSTALL" --local-client --hardened --managed-settings "$ms8" --egress-control "$allowlist8")"
rc8=$?
if [ "$rc8" -eq 0 ] \
   && [ "$(check json-equal "$ms8" sandbox.network.strictAllowlist true)" = ok ] \
   && [ "$(check json-equal "$ms8" sandbox.network.allowManagedDomainsOnly true)" = ok ] \
   && [ "$(check json-equal "$ms8" sandbox.network.allowedDomains '["github.com", "registry.npmjs.org"]')" = ok ] \
   && [ "$(check json-equal "$ms8" sandbox.network.allowLocalBinding true)" = ok ]; then
  ok "EGR-001 --egress-control writes the strict allowlist with the model hosts removed"
else
  bad "EGR-001 --egress-control did not write the expected allowlist" "exit=$rc8"$'\n'"$out8"
fi

out8b="$(HOME="$home8" PATH="$TOOLBIN" \
  INNSEGL_INSTALL_START_CMD="$STUB_START" \
  INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
  INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
  INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
  INNSEGL_BIN_PATH="$STUB_BIN" \
  INNSEGL_GATEWAY_UPSTREAM="https://upstream.example.invalid" \
  "$BASH_BIN" "$INSTALL" --local-client --hardened --managed-settings "$ms8" --egress-control "$allowlist8" 2>&1)"
rc8b=$?
if [ "$rc8b" -eq 0 ] && printf '%s' "$out8b" | grep -qi 'already up to date'; then
  ok "EGR-001 a second run with the same allowlist is idempotent"
else
  bad "EGR-001 a second run was not idempotent" "exit=$rc8b"$'\n'"$out8b"
fi

# --- EGR-001: the operator's own allowlist entries survive install and uninstall
home8c="$WORK/home-egress-operator"; mkdir -p "$home8c"
ms8c="$home8c/managed-settings.json"
cat > "$ms8c" <<'JSON'
{"sandbox": {"network": {"allowedDomains": ["internal.example.invalid"]}}}
JSON
egress_run() {
  HOME="$home8c" PATH="$TOOLBIN" \
    INNSEGL_INSTALL_START_CMD="$STUB_START" \
    INNSEGL_INSTALL_SIGNER_CMD="$STUB_SIGNER" \
    INNSEGL_INSTALL_LINK_CMD="$STUB_LINK" \
    INNSEGL_INSTALL_SETUP_LINK_CMD="$STUB_SETUP_LINK" \
    INNSEGL_BIN_PATH="$STUB_BIN" \
    INNSEGL_GATEWAY_UPSTREAM="https://upstream.example.invalid" \
    "$BASH_BIN" "$INSTALL" --local-client --managed-settings "$ms8c" "$@" 2>&1
}
out8c="$(egress_run --hardened --egress-control "$allowlist8")"; rc8c=$?
if [ "$rc8c" -eq 0 ] \
   && [ "$(check json-equal "$ms8c" sandbox.network.allowedDomains '["internal.example.invalid", "github.com", "registry.npmjs.org"]')" = ok ]; then
  ok "EGR-001 an allowlist the operator already had is kept, and the new domains are added to it"
else
  bad "EGR-001 the operator's own allowlist was not kept" "exit=$rc8c"$'\n'"$out8c"
fi
out8d="$(egress_run --uninstall)"; rc8d=$?
if [ "$rc8d" -eq 0 ] \
   && [ "$(check json-equal "$ms8c" sandbox.network.allowedDomains '["internal.example.invalid", "github.com", "registry.npmjs.org"]')" = ok ] \
   && printf '%s' "$out8d" | grep -q -- '--egress-control'; then
  ok "EGR-001 --uninstall without the allowlist file leaves the domains alone and says how to remove them"
else
  bad "EGR-001 --uninstall without the allowlist file touched the domains, or said nothing" "exit=$rc8d"$'\n'"$out8d"
fi
out8e="$(egress_run --uninstall --egress-control "$allowlist8")"; rc8e=$?
if [ "$rc8e" -eq 0 ] \
   && [ "$(check json-equal "$ms8c" sandbox.network.allowedDomains '["internal.example.invalid"]')" = ok ]; then
  ok "EGR-001 --uninstall with the allowlist file removes only the domains it added"
else
  bad "EGR-001 --uninstall with the allowlist file removed the wrong domains" "exit=$rc8e"$'\n'"$out8e"
fi

# --- ENF-006: the installer proves the harness loaded what it wrote ---------
# Claude Code drops a WHOLE settings file, silently, when one value has the
# wrong type (measured 2026-09-30: attribution.commit false). This stub does
# the same and writes the debug line the real harness writes, so the case
# tests install.sh's reading of it; the real harness is measured live.
CLAUDEBIN="$WORK/claudebin"; mkdir -p "$CLAUDEBIN"
cat > "$CLAUDEBIN/claude" <<'EOF'
#!/bin/sh
settings="" debug=""
while [ $# -gt 0 ]; do
  case "$1" in
    --settings) settings="$2"; shift 2 ;;
    --debug-file) debug="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$debug" ] || exit 0
python3 - "$settings" "$debug" <<'PY'
import json, sys
settings, debug = sys.argv[1], sys.argv[2]
ca = None
try:
    d = json.load(open(settings))
    if all(not isinstance(v, bool) for v in d.get("attribution", {}).values()):
        ca = d.get("env", {}).get("NODE_EXTRA_CA_CERTS")
except Exception:
    pass
open(debug, "w").write("[DEBUG] CA certs: extraCertsPath=%s\n" % (ca or "undefined"))
PY
EOF
chmod +x "$CLAUDEBIN/claude"
home10="$WORK/home-verify"; mkdir -p "$home10"
out10="$(run_install "$home10" "$TOOLBIN:$CLAUDEBIN" --managed-settings "$home10/managed-settings.json" 2>&1)"; rc10=$?
if [ "$rc10" -eq 0 ] && printf '%s' "$out10" | grep -q "Claude Code loaded"; then
  ok "ENF-006 a file the harness loads is reported as loaded"
else
  bad "ENF-006 a loaded file was not reported as loaded" "exit=$rc10"$'\n'"$out10"
fi
cat > "$home10/managed-settings.json" <<'JSON'
{"attribution": {"pr": false}}
JSON
out11="$(run_install "$home10" "$TOOLBIN:$CLAUDEBIN" --managed-settings "$home10/managed-settings.json" 2>&1)"; rc11=$?
if [ "$rc11" -ne 0 ] && printf '%s' "$out11" | grep -q "did NOT load" \
   && printf '%s' "$out11" | grep -qF "$home10/managed-settings.json"; then
  ok "ENF-006 a file the harness discards fails the install, by name"
else
  bad "ENF-006 a discarded file did not fail the install by name" "exit=$rc11"$'\n'"$out11"
fi
home12="$WORK/home-noclaude"; mkdir -p "$home12"
out12="$(run_install "$home12" "$TOOLBIN" --managed-settings "$home12/managed-settings.json" 2>&1)"; rc12=$?
if [ "$rc12" -eq 0 ] && printf '%s' "$out12" | grep -q "could not be checked"; then
  ok "ENF-006 with no harness installed, the check says it could not run"
else
  bad "ENF-006 with no harness installed, the check said nothing or failed" "exit=$rc12"$'\n'"$out12"
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
ms9="$home9/managed-settings.json"
out9="$(run_install "$home9" "$TOOLBIN" --managed-settings "$ms9" --uninstall-legacy)"; rc9=$?
if [ "$rc9" -eq 0 ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" hooks.PreToolUse.0.hooks.0.command '"/opt/example/my-hook.sh"')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" 'hooks.PreToolUse' '[{"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/example/my-hook.sh"}]}]')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" 'hooks.SessionStart' '[{"hooks": [{"type": "command", "command": "/opt/example/session.sh"}]}]')" = ok ] \
   && [ "$(check json-equal "$home9/.claude/settings.json" otherUserSetting true)" = ok ] \
   && [ "$(check json-absent "$home9/.claude.json" mcpServers.innsegl)" = ok ] \
   && [ "$(check json-equal "$home9/.claude.json" mcpServers.other-server '{"type": "stdio", "command": "other-mcp"}')" = ok ] \
   && [ ! -e "$ms9" ]; then
  ok "--uninstall-legacy removes only the six old hook entries and the innsegl MCP entry"
else
  bad "--uninstall-legacy touched more, or less, than the old wiring" "exit=$rc9"$'\n'"$out9"
fi

# The matcher: "*" PreToolUse group and one SessionStart entry held only our
# old hook, so both were pruned to nothing and dropped; my-hook.sh and
# session.sh were never ours and survive exactly as given.

# --- --pause and --resume: the operator takes the harness off the gateway
# and puts it back, with the settings kept byte for byte ---------------------
home10="$WORK/home-pause"; mkdir -p "$home10"
ms10="$home10/managed-settings.json"
run_install "$home10" "$TOOLBIN" --managed-settings "$ms10" >/dev/null 2>&1
cp "$ms10" "$WORK/ms10-installed.json"
out10="$(run_install "$home10" "$TOOLBIN" --managed-settings "$ms10" --pause)"; rc10=$?
if [ "$rc10" -eq 0 ] && [ ! -e "$ms10" ] && diff -q "$WORK/ms10-installed.json" "$ms10.paused" >/dev/null \
   && printf '%s' "$out10" | grep -q 'paused'; then
  ok "--pause moves the managed settings aside, unchanged, so the harness runs without the gateway"
else
  bad "--pause did not set the managed settings aside" "exit=$rc10"$'\n'"$out10"
fi
out11="$(run_install "$home10" "$TOOLBIN" --managed-settings "$ms10" --resume)"; rc11=$?
if [ "$rc11" -eq 0 ] && [ ! -e "$ms10.paused" ] && diff -q "$WORK/ms10-installed.json" "$ms10" >/dev/null; then
  ok "--resume puts the same managed settings back"
else
  bad "--resume did not restore the managed settings" "exit=$rc11"$'\n'"$out11"
fi
out12="$(run_install "$home10" "$TOOLBIN" --managed-settings "$ms10" --resume 2>&1)"; rc12=$?
if [ "$rc12" -ne 0 ] && printf '%s' "$out12" | grep -q 'nothing is paused'; then
  ok "--resume with nothing paused refuses and says so"
else
  bad "--resume with nothing paused did not refuse" "exit=$rc12"$'\n'"$out12"
fi

# --- the server installer writes no managed settings (#461) ---------------
home13="$WORK/home-server"; mkdir -p "$home13"
ms13="$home13/managed-settings.json"
: > "$RECORD/link"
out13="$(run_install_server "$home13" "$TOOLBIN" --managed-settings "$ms13" "$home13/project" 2>&1)"; rc13=$?
if [ "$rc13" -eq 0 ] && [ ! -e "$ms13" ] \
   && grep -q "project" "$RECORD/link" \
   && printf '%s' "$out13" | grep -q 'innsegl connect'; then
  ok "a server-only install brings the stack up and links, and writes no managed settings"
else
  bad "a server-only install wrote managed settings, or did not finish" "exit=$rc13 file=$( [ -e "$ms13" ] && echo present || echo absent )"$'\n'"$out13"
fi
out14="$(run_install_server "$home13" "$TOOLBIN" --managed-settings "$ms13" --egress-control "$WORK/allowlist.txt" 2>&1)"; rc14=$?
if [ "$rc14" -ne 0 ] && [ ! -e "$ms13" ] && printf '%s' "$out14" | grep -q -- '--local-client'; then
  ok "--egress-control without --local-client is refused: there are no managed settings to shape"
else
  bad "--egress-control without --local-client was not refused" "exit=$rc14"$'\n'"$out14"
fi

home15="$WORK/home-egress-plain"; mkdir -p "$home15"
ms15="$home15/managed-settings.json"
out15="$(run_install "$home15" "$TOOLBIN" --managed-settings "$ms15" --egress-control "$WORK/allowlist.txt" 2>&1)"; rc15=$?
if [ "$rc15" -ne 0 ] && [ ! -e "$ms15" ] && printf '%s' "$out15" | grep -q -- '--hardened'; then
  ok "RM-312 --egress-control without --hardened is refused: there is no sandbox to shape"
else
  bad "RM-312 --egress-control without --hardened was not refused" "exit=$rc15"$'\n'"$out15"
fi

echo
echo "install-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
