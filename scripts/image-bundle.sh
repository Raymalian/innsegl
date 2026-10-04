#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# image-bundle — build the stack's images once, carry them to the deployment
# host as one file, and let the host accept that file only when it was built
# from the commit the host is deploying (ADR-0070).
#
#   create       build the three images for INNSEGL_IMAGE_PLATFORM and save
#                them into one bundle with a .sha256 beside it. Run on the
#                machine that builds; `make image-bundle` is how.
#   find         print the bundle to use for this checkout, or nothing: the
#                one INNSEGL_IMAGE_BUNDLE names, else the one in the bundle
#                directory for this commit and the daemon's platform.
#   load <file>  check the bundle and load it. Refuses, with nothing retagged
#                and nothing started, unless the checksum matches, the bundle
#                holds exactly the three images, each is for the daemon's
#                platform, and each carries the commit of every input it is
#                built from. Then retags them to the names compose runs.
#
# `make innsegl-here-services` runs `find`, then `load` when it found one, or
# builds on the host when it did not. A bundle that is found and fails is a
# refusal: there is no fallback to a build, because a deployment that quietly
# built something else is the case this exists to rule out.
#
# THE EXPECTED COMMITS come from the Makefile, which computes them from git
# exactly as it does for a host build (GO_IMAGE_COMMIT and its siblings):
#
#   INNSEGL_DEPLOY_COMMIT        HEAD, -dirty if a tracked file differs
#   INNSEGL_GO_IMAGE_COMMIT      the Go inputs'      -> dev.innsegl.commit
#   INNSEGL_UI_IMAGE_COMMIT      the UI's inputs'    -> dev.innsegl.ui-commit
#   INNSEGL_BACKUP_IMAGE_COMMIT  the backup stage's  -> dev.innsegl.commit
#   INNSEGL_IMAGE_INPUTS         every image's input paths, for the dirty check
#   INNSEGL_IMAGE_PLATFORM       create only. Default linux/amd64
#   INNSEGL_IMAGE_BUNDLE         find only: a bundle named explicitly
#
# Also, for scripts/image-bundle-selftest.sh: INNSEGL_BUNDLE_REPO (the
# checkout; default this script's own) and INNSEGL_BUNDLE_DIR (default
# <checkout>/dist). INNSEGL_DEPLOY_HOST and INNSEGL_DEPLOY_DIR fill the scp
# line `create` prints; unset, it prints placeholders.
#
# Exit status: 0 done, 1 refused, 2 usage.

set -euo pipefail

REPO="${INNSEGL_BUNDLE_REPO:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"
DIR="${INNSEGL_BUNDLE_DIR:-$REPO/dist}"

# No default build attestations: they stamp the build time, so an unchanged
# build would have a new image ID and compose would restart every service on
# it. The Makefile exports the same for host builds.
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

refuse() {
  echo "image-bundle: refused — $*" >&2
  exit 1
}

usage() {
  echo "usage: image-bundle.sh create | find | load <bundle>" >&2
  exit 2
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# The three images. staging tag | the name compose runs | Dockerfile target.
# The staging tags keep a bundle's images apart from what is running until
# every check has passed; the second column is compose's own default, and
# test/deploy holds the two files to the same names.
IMAGES="innsegl:bundle|${INNSEGL_IMAGE:-innsegl:local}|runtime
innsegl-api:bundle|${INNSEGL_API_IMAGE:-innsegl-api:local}|api
innsegl-backup:bundle|${INNSEGL_BACKUP_IMAGE:-innsegl-backup:local}|backup"

# expected <staging tag> — "label value" lines that image must carry. The api
# image is the runtime plus the built UI, so it carries both commits.
expected() {
  case "$1" in
    innsegl:bundle)
      echo "dev.innsegl.commit $GO_COMMIT" ;;
    innsegl-api:bundle)
      echo "dev.innsegl.commit $GO_COMMIT"
      echo "dev.innsegl.ui-commit $UI_COMMIT" ;;
    innsegl-backup:bundle)
      echo "dev.innsegl.commit $BACKUP_COMMIT" ;;
  esac
}

# need_clean_commits — every expected commit is set and none is dirty. A dirty
# tree's images are built from sources no commit names, so no bundle can
# match them, and none is ever made from them.
need_clean_commits() {
  local name value
  for name in INNSEGL_DEPLOY_COMMIT INNSEGL_GO_IMAGE_COMMIT INNSEGL_UI_IMAGE_COMMIT INNSEGL_BACKUP_IMAGE_COMMIT; do
    value="${!name:-}"
    [ -n "$value" ] || refuse "$name is not set; run this through make"
    case "$value" in
      *-dirty) refuse "the checkout is dirty ($name=$value); a bundle is only ever made from, or accepted for, a clean commit" ;;
    esac
  done
  GO_COMMIT="$INNSEGL_GO_IMAGE_COMMIT"
  UI_COMMIT="$INNSEGL_UI_IMAGE_COMMIT"
  BACKUP_COMMIT="$INNSEGL_BACKUP_IMAGE_COMMIT"
}

bundle_name() {  # bundle_name <os/arch>
  printf 'innsegl-images-%s-%s.tar.gz' "$INNSEGL_DEPLOY_COMMIT" "$(printf '%s' "$1" | tr '/' '-')"
}

server_platform() {
  docker version -f '{{.Server.Os}}/{{.Server.Arch}}'
}

# --- create -------------------------------------------------------------------
cmd_create() {
  local platform="${INNSEGL_IMAGE_PLATFORM:-linux/amd64}" untracked line staging final target
  local -a build_args tags

  # A tracked change anywhere makes HEAD the wrong name for what is built.
  # An untracked file under an image's inputs would be copied into it. One
  # outside them is not the images' business.
  if ! git -C "$REPO" diff --quiet HEAD --; then
    refuse "the working tree is dirty; commit or stash first"
  fi
  # shellcheck disable=SC2086 # the inputs are a list of paths
  untracked="$(git -C "$REPO" ls-files --others --exclude-standard -- ${INNSEGL_IMAGE_INPUTS:-.})"
  if [ -n "$untracked" ]; then
    refuse "untracked files under the image inputs would be built in: $(printf '%s' "$untracked" | tr '\n' ' ')"
  fi
  need_clean_commits

  tags=()
  while IFS='|' read -r staging final target; do
    # The same arguments compose passes on a host build. VERSION and DATE are
    # compose's constant defaults, not the commit or the time: either would
    # make every bundle a new image and restart every service on it.
    build_args=(--build-arg VERSION=compose --build-arg DATE=unknown)
    case "$target" in
      runtime) build_args+=(--build-arg "COMMIT=$GO_COMMIT") ;;
      api) build_args+=(--build-arg "COMMIT=$GO_COMMIT" --build-arg "UI_COMMIT=$UI_COMMIT") ;;
      backup) build_args+=(--build-arg "COMMIT=$BACKUP_COMMIT") ;;
    esac
    echo "image-bundle: building $target for $platform as $staging"
    docker buildx build --platform "$platform" --target "$target" \
      "${build_args[@]}" -t "$staging" --load -f "$REPO/Dockerfile" "$REPO"
    tags+=("$staging")
  done <<< "$IMAGES"

  mkdir -p "$DIR"
  local name out tmp
  name="$(bundle_name "$platform")"
  out="$DIR/$name"
  tmp="$out.partial"
  echo "image-bundle: saving ${#tags[@]} images into $out"
  docker save "${tags[@]}" | gzip -c > "$tmp"
  mv "$tmp" "$out"
  printf '%s  %s\n' "$(sha256_of "$out")" "$name" > "$out.sha256"

  local host="${INNSEGL_DEPLOY_HOST:-<host>}" dest="${INNSEGL_DEPLOY_DIR:-<checkout>}"
  local rel="${out#"$PWD"/}"
  echo
  echo "image-bundle: $out"
  echo "copy it to the deployment host, then run make update there:"
  echo "  ssh $host mkdir -p $dest/dist && scp $rel $rel.sha256 $host:$dest/dist/"
}

# --- find ---------------------------------------------------------------------
cmd_find() {
  if [ -n "${INNSEGL_IMAGE_BUNDLE:-}" ]; then
    printf '%s\n' "$INNSEGL_IMAGE_BUNDLE"
    return 0
  fi
  case "${INNSEGL_DEPLOY_COMMIT:-}" in
    ''|*-dirty) return 0 ;;
  esac
  # No bundle here at all: the usual case on a host that builds for itself,
  # answered without asking the container runtime anything.
  local any
  [ -d "$DIR" ] || return 0
  any="$(find "$DIR" -maxdepth 1 -name 'innsegl-images-*.tar.gz' | head -n 1)" || true
  [ -n "$any" ] || return 0
  local platform candidate
  platform="$(server_platform)" || refuse "cannot ask the container runtime for its platform"
  candidate="$DIR/$(bundle_name "$platform")"
  if [ -f "$candidate" ]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  # Not a refusal: no bundle for this commit means the host builds, as it
  # always has. But a bundle for another commit is worth saying out loud,
  # because it is usually one that was meant for this deployment.
  local other
  for other in "$DIR"/innsegl-images-*.tar.gz; do
    [ -e "$other" ] || continue
    echo "image-bundle: ignoring $other: it is not for $INNSEGL_DEPLOY_COMMIT on $platform" >&2
  done
}

# --- load ---------------------------------------------------------------------
cmd_load() {
  local bundle="${1:-}"
  [ -n "$bundle" ] || usage
  need_clean_commits
  [ -f "$bundle" ] || refuse "no bundle at $bundle"
  [ -f "$bundle.sha256" ] || refuse "no checksum at $bundle.sha256"

  local want got
  want="$(cut -d' ' -f1 < "$bundle.sha256")"
  got="$(sha256_of "$bundle")"
  [ "$want" = "$got" ] || refuse "checksum mismatch for $bundle: $bundle.sha256 says $want, the file is $got"

  echo "image-bundle: checksum ok; loading $bundle"
  local loaded
  loaded="$(docker load -i "$bundle")" || refuse "docker load failed for $bundle"
  printf '%s\n' "$loaded"

  # Exactly the three staging images, by name. Anything else -- an image by
  # ID only, another name, one missing -- means the bundle is not what
  # `create` makes.
  local names expect_names
  names="$(printf '%s\n' "$loaded" | sed -n 's/^Loaded image: //p' | sort)"
  expect_names="$(printf '%s\n' "$IMAGES" | cut -d'|' -f1 | sort)"
  if printf '%s\n' "$loaded" | grep -q '^Loaded image ID: '; then
    refuse "the bundle holds an image with no name"
  fi
  [ "$names" = "$expect_names" ] ||
    refuse "docker load may have moved the tags it carries; nothing was started. The bundle holds [$(printf '%s' "$names" | tr '\n' ' ')], want [$(printf '%s' "$expect_names" | tr '\n' ' ')]"

  local platform staging final target label value actual image_platform failures=0
  platform="$(server_platform)" || refuse "cannot ask the container runtime for its platform"
  while IFS='|' read -r staging final target; do
    image_platform="$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$staging")" ||
      refuse "cannot inspect $staging"
    if [ "$image_platform" != "$platform" ]; then
      echo "image-bundle: $staging is for $image_platform; this host runs $platform" >&2
      failures=$((failures + 1))
    fi
    while read -r label value; do
      actual="$(docker image inspect -f "{{index .Config.Labels \"$label\"}}" "$staging")" ||
        refuse "cannot inspect $staging"
      if [ "$actual" != "$value" ]; then
        echo "image-bundle: $staging has $label=${actual:-<none>}; this checkout needs $value" >&2
        failures=$((failures + 1))
      fi
    done < <(expected "$staging")
  done <<< "$IMAGES"
  [ "$failures" -eq 0 ] ||
    refuse "$bundle was not built from this checkout's commit ($INNSEGL_DEPLOY_COMMIT); nothing was retagged or started"

  while IFS='|' read -r staging final target; do
    docker tag "$staging" "$final"
    echo "image-bundle: $final <- $staging (verified)"
  done <<< "$IMAGES"
}

case "${1:-}" in
  create) cmd_create ;;
  find) cmd_find ;;
  load) shift; cmd_load "$@" ;;
  *) usage ;;
esac
