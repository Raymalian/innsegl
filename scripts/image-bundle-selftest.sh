#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/image-bundle.sh, watched failing before it existed (ADR-0070).
#
# WHY THIS EXISTS. A deployment host can take its images from a bundle built
# on another machine instead of building them. The host must accept a bundle
# only when every image in it was built from the inputs of the commit it is
# deploying, and refuse anything else before a single image is retagged. A
# check that refuses nothing looks exactly like a working one until the day it
# matters, so every refusal below is driven here.
#
# WHAT IS STUBBED. `docker` is a fake on PATH that keeps its images as small
# text records in this file's temp directory. A "bundle" is those records,
# gzipped. Nothing here talks to a real daemon, builds, loads or starts
# anything, and nothing touches this checkout: the repository the script
# checks is a throwaway one.
#
# CASES
#   create  1. a tracked change anywhere              -> refused, nothing built
#           2. an untracked file under an image input  -> refused, nothing built
#           3. an expected commit that is dirty         -> refused, nothing built
#           4. a clean tree                             -> three images built for
#              linux/amd64, one bundle and its .sha256, a one-line scp command
#              naming no host
#           5. INNSEGL_IMAGE_PLATFORM                   -> builds and names that
#   find    6. no bundle for this commit               -> prints nothing
#           7. the bundle for this commit and platform  -> prints its path
#           8. a bundle for another platform only       -> prints nothing
#           9. INNSEGL_IMAGE_BUNDLE                      -> prints that path
#          10. a dirty checkout                          -> prints nothing
#   load   11. a good bundle                             -> all three retagged
#          12. a checksum that does not match            -> refused, not loaded
#          13. no .sha256 beside it                       -> refused, not loaded
#          14. a missing bundle                           -> refused
#          15. one image's Go commit is wrong             -> refused, no retag
#          16. the api image's UI commit is wrong         -> refused, no retag
#          17. the backup image's commit is wrong         -> refused, no retag
#          18. an image missing from the bundle           -> refused, no retag
#          19. an extra image in the bundle               -> refused, no retag
#          20. the images are for another platform        -> refused, no retag
#          21. the checkout is dirty                      -> refused, not loaded
#
# USAGE
#   scripts/image-bundle-selftest.sh
#
# Needs bash, git and gzip. No Docker, no network.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
BUNDLE="$ROOT/scripts/image-bundle.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2" >&2; return 0; }

if [ ! -x "$BUNDLE" ]; then
  echo "image-bundle-selftest: $BUNDLE is missing or not executable" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ---------------------------------------------------------------------------
# the fake docker
# ---------------------------------------------------------------------------
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
# A docker that keeps images as text records under $DOCKER_STUB_DIR/img.
set -u
S="$DOCKER_STUB_DIR"
mkdir -p "$S/img"
printf '%s\n' "$*" >> "$S/calls"
rec() { printf '%s/img/%s' "$S" "$(printf '%s' "$1" | tr ':/' '__')"; }
case "$1" in
  version)
    printf '%s\n' "${DOCKER_STUB_SERVER:-linux/amd64}" ;;
  buildx)
    shift 2
    tag='' plat='' args=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -t) tag="$2"; shift 2 ;;
        --platform) plat="$2"; shift 2 ;;
        --build-arg) args+=("$2"); shift 2 ;;
        *) shift ;;
      esac
    done
    {
      printf 'IMAGE %s\nPLATFORM %s\n' "$tag" "$plat"
      for a in "${args[@]}"; do
        case "$a" in
          COMMIT=*) printf 'LABEL dev.innsegl.commit %s\n' "${a#COMMIT=}" ;;
          UI_COMMIT=*) printf 'LABEL dev.innsegl.ui-commit %s\n' "${a#UI_COMMIT=}" ;;
        esac
      done
    } > "$(rec "$tag")" ;;
  save)
    shift
    for t in "$@"; do cat "$(rec "$t")" || exit 1; done ;;
  load)
    [ "$2" = -i ] || exit 2
    gunzip -c "$3" > "$S/loading" || exit 1
    cur=''
    while read -r kind a b; do
      if [ "$kind" = IMAGE ]; then
        cur="$(rec "$a")"; : > "$cur"; printf 'Loaded image: %s\n' "$a"
      fi
      printf '%s %s %s\n' "$kind" "$a" "$b" >> "$cur"
    done < "$S/loading" ;;
  image)
    fmt="$4" f="$(rec "$5")"
    [ -f "$f" ] || { echo "no such image: $5" >&2; exit 1; }
    case "$fmt" in
      *.Os*) awk '$1 == "PLATFORM" { print $2 }' "$f" ;;
      *Labels*)
        key="$(printf '%s' "$fmt" | sed 's/.*"\(.*\)".*/\1/')"
        awk -v k="$key" '$1 == "LABEL" && $2 == k { print $3 }' "$f" ;;
    esac ;;
  tag)
    sed "s|^IMAGE .*|IMAGE $3|" "$(rec "$2")" > "$(rec "$3")" ;;
  *) echo "fake docker: unhandled: $*" >&2; exit 2 ;;
esac
STUB
chmod +x "$TMP/bin/docker"

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

REPO="$TMP/repo"
git init -q -b main "$REPO"
git -C "$REPO" config user.email "selftest@innsegl.invalid"
git -C "$REPO" config user.name "selftest"
git -C "$REPO" config commit.gpgsign false
mkdir -p "$REPO/cmd" "$REPO/web" "$REPO/docs-x"
printf 'FROM scratch\n' > "$REPO/Dockerfile"
printf 'package main\n' > "$REPO/cmd/main.go"
printf '{}\n' > "$REPO/web/package.json"
printf 'notes\n' > "$REPO/docs-x/notes.md"
printf 'dist/\n' > "$REPO/.gitignore"
git -C "$REPO" add -A
git -C "$REPO" commit -q --no-gpg-sign -m fixture

GO=aaaaaaaaaaaa UI=bbbbbbbbbbbb BK=cccccccccccc HEADC=dddddddddddd

# run <case-dir> <script args...> — the script under a clean environment,
# with the fake docker first on PATH. Extra settings come in as env.
run() {
  local stub="$1"; shift
  mkdir -p "$stub"
  env PATH="$TMP/bin:$PATH" DOCKER_STUB_DIR="$stub" \
    INNSEGL_BUNDLE_REPO="$REPO" \
    INNSEGL_DEPLOY_COMMIT="${C_DEPLOY-$HEADC}" \
    INNSEGL_GO_IMAGE_COMMIT="${C_GO-$GO}" \
    INNSEGL_UI_IMAGE_COMMIT="${C_UI-$UI}" \
    INNSEGL_BACKUP_IMAGE_COMMIT="${C_BK-$BK}" \
    INNSEGL_IMAGE_INPUTS="cmd web Dockerfile" \
    INNSEGL_IMAGE_BUNDLE="${C_BUNDLE-}" \
    INNSEGL_IMAGE_PLATFORM="${C_PLATFORM-}" \
    DOCKER_STUB_SERVER="${C_SERVER-linux/amd64}" \
    "$BUNDLE" "$@"
}

# calls <case-dir> <pattern> — how many docker calls matched; 0 if none ran.
calls() { { cat "$1/calls" 2>/dev/null || true; } | grep -c "$2" || true; }
built() { calls "$1" '^buildx build'; }
retagged() { calls "$1" '^tag '; }
loaded() { calls "$1" '^load '; }

# make_bundle <path> <records> — a bundle with a correct .sha256 beside it.
make_bundle() {
  mkdir -p "$(dirname "$1")"
  printf '%s\n' "$2" | gzip -c > "$1"
  printf '%s  %s\n' "$(sha "$1")" "$(basename "$1")" > "$1.sha256"
}

# good_records [platform] [runtime Go commit] [api Go commit] [UI commit]
# [backup commit] — what a bundle built for this checkout holds.
good_records() {
  local p="${1:-linux/amd64}"
  printf 'IMAGE innsegl:bundle\nPLATFORM %s\nLABEL dev.innsegl.commit %s\n' "$p" "${2:-$GO}"
  printf 'IMAGE innsegl-api:bundle\nPLATFORM %s\nLABEL dev.innsegl.commit %s\nLABEL dev.innsegl.ui-commit %s\n' "$p" "${3:-$GO}" "${4:-$UI}"
  printf 'IMAGE innsegl-backup:bundle\nPLATFORM %s\nLABEL dev.innsegl.commit %s\n' "$p" "${5:-$BK}"
}

echo "image-bundle create"

# 1
printf 'edited\n' >> "$REPO/docs-x/notes.md"
out="$(run "$TMP/c1" create 2>&1)"; rc=$?
git -C "$REPO" checkout -q -- docs-x/notes.md
if [ "$rc" -ne 0 ] && [ "$(built "$TMP/c1")" = 0 ] && printf '%s' "$out" | grep -q 'dirty'; then
  ok "a tracked change anywhere is refused, and nothing is built"
else bad "a tracked change anywhere is refused" "rc=$rc built=$(built "$TMP/c1") out=$out"; fi

# 2
printf 'x\n' > "$REPO/web/stray.ts"
out="$(run "$TMP/c2" create 2>&1)"; rc=$?
rm -f "$REPO/web/stray.ts"
if [ "$rc" -ne 0 ] && [ "$(built "$TMP/c2")" = 0 ] && printf '%s' "$out" | grep -q 'web/stray.ts'; then
  ok "an untracked file under an image input is refused, and named"
else bad "an untracked file under an image input is refused" "rc=$rc out=$out"; fi

# an untracked file outside the inputs is not the images' business
printf 'x\n' > "$REPO/docs-x/scratch.md"

# 3
out="$(C_UI="$UI-dirty" run "$TMP/c3" create 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(built "$TMP/c3")" = 0 ]; then
  ok "an expected commit that is dirty is refused, and nothing is built"
else bad "an expected commit that is dirty is refused" "rc=$rc out=$out"; fi

# 4
out="$(run "$TMP/c4" create 2>&1)"; rc=$?
B4="$REPO/dist/innsegl-images-$HEADC-linux-amd64.tar.gz"
if [ "$rc" -eq 0 ] && [ "$(built "$TMP/c4")" = 3 ] \
   && [ "$(grep '^buildx build' "$TMP/c4/calls" | grep -c -- '--platform linux/amd64')" = 3 ] \
   && [ -s "$B4" ] && [ -s "$B4.sha256" ] \
   && [ "$(cut -d' ' -f1 "$B4.sha256")" = "$(sha "$B4")" ]; then
  ok "a clean tree builds three amd64 images into one bundle with its checksum"
else bad "a clean tree builds the bundle" "rc=$rc out=$out calls=$(cat "$TMP/c4/calls" 2>/dev/null)"; fi
for want in "--target runtime" "--target api" "--target backup" "COMMIT=$GO" "UI_COMMIT=$UI" "COMMIT=$BK" "VERSION=compose" "DATE=unknown"; do
  if ! grep -q -- "$want" "$TMP/c4/calls"; then bad "create passes $want to the build"; fi
done
scp_lines="$(printf '%s\n' "$out" | grep -c 'scp ')"
if [ "$scp_lines" = 1 ] && printf '%s' "$out" | grep 'scp ' | grep -q '<host>' \
   && printf '%s' "$out" | grep 'scp ' | grep -q "innsegl-images-$HEADC-linux-amd64.tar.gz.sha256"; then
  ok "it prints one scp line, with the host as a placeholder"
else bad "it prints one scp line with a placeholder host" "$out"; fi
# the bundle holds exactly the three staging images
if [ "$(gunzip -c "$B4" | grep -c '^IMAGE ')" = 3 ]; then
  ok "the bundle holds the three images"
else bad "the bundle holds the three images" "$(gunzip -c "$B4")"; fi

# 5
out="$(C_PLATFORM=linux/arm64 run "$TMP/c5" create 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(grep '^buildx build' "$TMP/c5/calls" | grep -c -- '--platform linux/arm64')" = 3 ] \
   && [ -s "$REPO/dist/innsegl-images-$HEADC-linux-arm64.tar.gz" ]; then
  ok "INNSEGL_IMAGE_PLATFORM chooses the platform, and the file says which"
else bad "INNSEGL_IMAGE_PLATFORM chooses the platform" "rc=$rc out=$out"; fi
rm -rf "$REPO/dist"

echo "image-bundle find"

# 6
out="$(run "$TMP/f6" find 2>/dev/null)"; rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then ok "no bundle for this commit: nothing found"
else bad "no bundle: nothing found" "rc=$rc out=$out"; fi

# 7
FB="$REPO/dist/innsegl-images-$HEADC-linux-amd64.tar.gz"
make_bundle "$FB" "$(good_records)"
out="$(run "$TMP/f7" find 2>/dev/null)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "$FB" ]; then ok "the bundle for this commit and platform is found"
else bad "the bundle for this commit is found" "rc=$rc out=$out"; fi

# 8
out="$(C_SERVER=linux/arm64 run "$TMP/f8" find 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && ! printf '%s' "$out" | grep -q '^/'; then ok "a bundle for another platform is not found"
else bad "a bundle for another platform is not found" "rc=$rc out=$out"; fi

# 9
out="$(C_BUNDLE="$TMP/elsewhere.tar.gz" run "$TMP/f9" find 2>/dev/null)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "$TMP/elsewhere.tar.gz" ]; then ok "INNSEGL_IMAGE_BUNDLE names the bundle"
else bad "INNSEGL_IMAGE_BUNDLE names the bundle" "rc=$rc out=$out"; fi

# 10
out="$(C_DEPLOY="$HEADC-dirty" run "$TMP/f10" find 2>/dev/null)"; rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then ok "a dirty checkout finds no bundle, and builds"
else bad "a dirty checkout finds no bundle" "rc=$rc out=$out"; fi
rm -rf "$REPO/dist"

echo "image-bundle load"

LB="$TMP/b/innsegl-images.tar.gz"

# 11
make_bundle "$LB" "$(good_records)"
out="$(run "$TMP/l11" load "$LB" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(retagged "$TMP/l11")" = 3 ] \
   && grep -qx 'tag innsegl:bundle innsegl:local' "$TMP/l11/calls" \
   && grep -qx 'tag innsegl-api:bundle innsegl-api:local' "$TMP/l11/calls" \
   && grep -qx 'tag innsegl-backup:bundle innsegl-backup:local' "$TMP/l11/calls"; then
  ok "a good bundle is loaded and its three images retagged to what compose runs"
else bad "a good bundle is loaded and retagged" "rc=$rc out=$out"; fi

# 12
make_bundle "$LB" "$(good_records)"
printf '%s  x\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$LB.sha256"
out="$(run "$TMP/l12" load "$LB" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(loaded "$TMP/l12")" = 0 ] && printf '%s' "$out" | grep -qi 'checksum'; then
  ok "a checksum that does not match is refused before anything is loaded"
else bad "a bad checksum is refused" "rc=$rc out=$out"; fi

# 13
make_bundle "$LB" "$(good_records)"
rm -f "$LB.sha256"
out="$(run "$TMP/l13" load "$LB" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(loaded "$TMP/l13")" = 0 ]; then ok "a bundle with no .sha256 is refused"
else bad "a bundle with no .sha256 is refused" "rc=$rc out=$out"; fi

# 14
out="$(run "$TMP/l14" load "$TMP/nothing-here.tar.gz" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(loaded "$TMP/l14")" = 0 ]; then ok "a missing bundle is refused"
else bad "a missing bundle is refused" "rc=$rc out=$out"; fi

# refused_load <n> <description> <records> — refused, and nothing retagged.
refused_load() {
  local n="$1" what="$2" records="$3"
  make_bundle "$LB" "$records"
  out="$(run "$TMP/l$n" load "$LB" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && [ "$(retagged "$TMP/l$n")" = 0 ]; then ok "$what"
  else bad "$what" "rc=$rc out=$out"; fi
}

# 15
refused_load 15 "an image built from other Go sources is refused, nothing retagged" \
  "$(good_records linux/amd64 eeeeeeeeeeee)"
# 16
refused_load 16 "an api image built from another UI is refused, nothing retagged" \
  "$(good_records linux/amd64 "$GO" "$GO" eeeeeeeeeeee)"
# 17
refused_load 17 "a backup image from another Dockerfile is refused, nothing retagged" \
  "$(good_records linux/amd64 "$GO" "$GO" "$UI" eeeeeeeeeeee)"
# 18
refused_load 18 "a bundle missing an image is refused, nothing retagged" \
  "$(good_records | awk '/^IMAGE innsegl-backup:bundle/ { skip = 1 } !skip')"
# 19
refused_load 19 "a bundle carrying an image it should not is refused, nothing retagged" \
  "$(good_records; printf 'IMAGE innsegl:local\nPLATFORM linux/amd64\nLABEL dev.innsegl.commit %s\n' "$GO")"
# 20
refused_load 20 "images for another platform are refused, nothing retagged" \
  "$(good_records linux/arm64)"

# 21
make_bundle "$LB" "$(good_records)"
out="$(C_GO="$GO-dirty" run "$TMP/l21" load "$LB" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(loaded "$TMP/l21")" = 0 ] && printf '%s' "$out" | grep -q 'dirty'; then
  ok "a dirty checkout refuses every bundle before loading it"
else bad "a dirty checkout refuses every bundle" "rc=$rc out=$out"; fi

echo
echo "image-bundle-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
