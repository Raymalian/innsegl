#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Root site gate for innsegl.dev (RM-058, #66; doc 05 §3).
#
# The site in this directory exists for one load-bearing reason: the module
# path in go.mod is `innsegl.dev/innsegl`, and without a `go-import` meta tag
# served at https://innsegl.dev/innsegl?go-get=1 that path resolves to nothing.
# Everything else here — the project page, the repo redirect — is ordinary web
# content that a human notices is broken. The meta tag is not: it is invisible
# in a browser, it is consumed only by a toolchain, and the failure it causes
# is somebody else's `go get` failing on a machine we will never see.
#
# So it gets a gate rather than a review pass.
#
# WHAT THIS CHECKS
# ----------------
# A. Layout. The files a Cloudflare Pages project serves from web/site/ exist.
#
# B. The go-import tag, derived from go.mod rather than restated. The module
#    path is read out of go.mod and the tag must name exactly that path. A
#    module rename that forgot this directory fails here instead of shipping a
#    site that resolves the old name.
#
# C. Where the tag may and may not appear. Exactly one page carries it, and it
#    is NOT the index: a go-import tag served at `/` claims innsegl.dev itself
#    is a module root, which is false and which turns a clean "not a module"
#    404 into a confusing mismatch error for anyone typoing a path.
#
# D. go-source, if present, must be well formed and agree with go-import.
#
# E. Tokens. web/site/tokens.css is a byte-identical copy of the shipped sheet
#    at web/src/tokens/tokens.css. ADR-0038 decision 2 makes that sheet the
#    single source of truth for every colour on every Innsegl surface, and a
#    Pages project with no build command cannot reach outside its output
#    directory — so the copy is the only way to obey the ADR, and this check is
#    what stops a copy from becoming a fork.
#
# F. Colour discipline, doc 06 §5.3 and ADR-0038 decision 4. Every colour on
#    this site comes from a `--innsegl-color-*` semantic token; the palette
#    layer is not reachable from a page; and the verification family — the only
#    green in the system — appears nowhere, because this site verifies nothing.
#    A project page that invents its own palette contradicts the ADR it ships
#    under, and a green marketing accent is doc 06 §8's anti-pattern 3 on the
#    project's own front door.
#
# G. Self-contained. No third-party stylesheet, script, font or image: doc 06
#    §7 and ADR-0038 decision 7 both refuse a request to somebody else's server
#    to render this project's own words.
#
# H. No JavaScript at all. ADR-0038's argument for the public verification page
#    — "it is HTML plus tokens.css, no React, no Lit, no framework runtime" —
#    is an argument about single-purpose pages, and this is one. The theme
#    follows the operating system through `color-scheme: light dark` in the
#    token sheet, which needs no script.
#
# DEPLOYING
# ---------
# Cloudflare Pages project, connected to this repository:
#
#     Framework preset     None
#     Build command        (none)
#     Output directory     web/site/public
#     Root directory       (repository root)
#
# There is no build step and there is nothing to install. Everything in
# public/ is served as-is; _headers and _redirects are consumed by Pages and
# are not themselves served. doc 05 §3 requires valid TLS from the first
# request because all of .dev is HSTS-preloaded; Pages provisions that
# automatically for a custom domain, which is why it was chosen.
#
# Usage:
#   web/site/check-site.sh              # static checks only, no network
#   web/site/check-site.sh --resolve    # additionally drive the real Go module
#                                       # resolver against a local copy of this
#                                       # site (needs Go, git and network)
#
# --resolve is separate because it reaches github.com. The static half is the
# one that belongs in every CI run.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Everything Cloudflare Pages publishes, and nothing else, lives in public/.
# The gates live beside it rather than inside it, so a check script or a
# fixture can never be uploaded to the site by being in the wrong directory.
SITE_DIR="${SCRIPT_DIR}/public"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
GO_MOD="${REPO_ROOT}/go.mod"
SHIPPED_TOKENS="${REPO_ROOT}/web/src/tokens/tokens.css"

RESOLVE=0
if [ "${1:-}" = "--resolve" ]; then
  RESOLVE=1
elif [ -n "${1:-}" ]; then
  printf 'usage: %s [--resolve]\n' "$0" >&2
  exit 2
fi

fails=0
checks=0

fail() {
  fails=$((fails + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

ok() {
  checks=$((checks + 1))
}

need_file() {
  ok
  if [ ! -f "$1" ]; then
    fail "missing file: ${1#"${REPO_ROOT}/"}"
    return 1
  fi
  return 0
}

printf '==> Root site — doc 05 §3, ADR-0038\n'
printf '    site   %s\n' "${SITE_DIR}"
printf '    go.mod %s\n' "${GO_MOD}"

# ---------------------------------------------------------------------------
# A. Layout
# ---------------------------------------------------------------------------
INDEX="${SITE_DIR}/index.html"
MODULE_PAGE="${SITE_DIR}/innsegl.html"
SITE_CSS="${SITE_DIR}/site.css"
SITE_TOKENS="${SITE_DIR}/tokens.css"
REDIRECTS="${SITE_DIR}/_redirects"
HEADERS="${SITE_DIR}/_headers"
NOT_FOUND="${SITE_DIR}/404.html"

need_file "${INDEX}" || true
need_file "${MODULE_PAGE}" || true
need_file "${SITE_CSS}" || true
need_file "${SITE_TOKENS}" || true
need_file "${REDIRECTS}" || true
need_file "${HEADERS}" || true
need_file "${NOT_FOUND}" || true
need_file "${GO_MOD}" || true
need_file "${SHIPPED_TOKENS}" || true

if [ "${fails}" -gt 0 ]; then
  printf '\n%d of %d checks failed.\n' "${fails}" "${checks}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# B. The go-import tag, derived from go.mod
# ---------------------------------------------------------------------------
MODULE_PATH="$(awk '$1 == "module" { print $2; exit }' "${GO_MOD}")"
ok
if [ -z "${MODULE_PATH}" ]; then
  fail "go.mod has no module line"
  MODULE_PATH="<unknown>"
fi

# The module path must live under the domain this site is served from, or the
# tag cannot be served for it at all.
ok
case "${MODULE_PATH}" in
  innsegl.dev/*) : ;;
  *) fail "module path ${MODULE_PATH} is not under innsegl.dev; this site cannot serve its go-import tag" ;;
esac

REPO_URL="https://github.com/Raymalian/innsegl"
WANT_IMPORT="<meta name=\"go-import\" content=\"${MODULE_PATH} git ${REPO_URL}\">"

printf '    module %s\n' "${MODULE_PATH}"
printf '    tag    %s\n' "${WANT_IMPORT}"

ok
if ! grep -qF -- "${WANT_IMPORT}" "${MODULE_PAGE}"; then
  fail "innsegl.html does not carry the exact go-import tag:
    want: ${WANT_IMPORT}
    got : $(grep -o '<meta name="go-import"[^>]*>' "${MODULE_PAGE}" || echo '(no go-import tag at all)')"
fi

# One tag, not two. Two go-import tags for the same prefix is ambiguous and the
# go command picks by prefix match, so a stale second tag is a silent wrong answer.
ok
n_import="$(grep -c '<meta name="go-import"' "${MODULE_PAGE}" || true)"
if [ "${n_import}" != "1" ]; then
  fail "innsegl.html carries ${n_import} go-import tags; want exactly 1"
fi

# ---------------------------------------------------------------------------
# C. Where the tag may not appear
# ---------------------------------------------------------------------------
for page in "${INDEX}" "${NOT_FOUND}"; do
  ok
  if grep -q '<meta name="go-import"' "${page}"; then
    fail "${page#"${SITE_DIR}/"} carries a go-import tag; only the module page may. A tag served at / claims innsegl.dev is itself a module root."
  fi
done

# ---------------------------------------------------------------------------
# D. go-source, if present
# ---------------------------------------------------------------------------
ok
if grep -q '<meta name="go-source"' "${MODULE_PAGE}"; then
  src_content="$(sed -n 's/.*<meta name="go-source" content="\([^"]*\)">.*/\1/p' "${MODULE_PAGE}")"
  set -- ${src_content}
  if [ "$#" -ne 4 ]; then
    fail "go-source needs exactly 4 space-separated fields (root home dir file), got $#: ${src_content}"
  elif [ "$1" != "${MODULE_PATH}" ]; then
    fail "go-source root is $1, want ${MODULE_PATH}"
  fi
fi

# ---------------------------------------------------------------------------
# E. Tokens are a copy, not a fork
# ---------------------------------------------------------------------------
ok
if ! cmp -s "${SITE_TOKENS}" "${SHIPPED_TOKENS}"; then
  fail "web/site/public/tokens.css has drifted from web/src/tokens/tokens.css.
    A Pages project with no build command cannot read outside its output
    directory, so this file is a copy. Re-copy it; do not edit it here:
      cp web/src/tokens/tokens.css web/site/public/tokens.css"
fi

# ---------------------------------------------------------------------------
# F. Colour discipline — doc 06 §5.3, ADR-0038 decisions 1 and 4
# ---------------------------------------------------------------------------

# No raw colour values anywhere in the site's own CSS or markup.
ok
raw="$(grep -nE '#[0-9a-fA-F]{3}([0-9a-fA-F]{1,5})?\b|\b(rgba?|hsla?|oklch|oklab|lab|lch|color-mix)\(' \
        "${SITE_CSS}" "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}" || true)"
if [ -n "${raw}" ]; then
  fail "raw colour value outside the token sheet (ADR-0038: every colour comes from tokens.css):
${raw}"
fi

# Every colour-bearing declaration resolves through a semantic token.
ok
bad_decl="$(awk '
  /^[[:space:]]*(color|background|background-color|border|border-top|border-right|border-bottom|border-left|border-color|outline|outline-color|fill|stroke|text-decoration-color|accent-color|caret-color|box-shadow)[[:space:]]*:/ {
    if ($0 ~ /var\(--innsegl-/) next
    if ($0 ~ /:[[:space:]]*(transparent|currentColor|inherit|initial|unset|none|0)[[:space:];]*$/) next
    printf "%s:%d: %s\n", FILENAME, FNR, $0
  }
' "${SITE_CSS}" || true)"
if [ -n "${bad_decl}" ]; then
  fail "colour declaration that does not resolve through a --innsegl-color-* token:
${bad_decl}"
fi

# The palette layer is not reachable from a page (ADR-0038's two-layer rule).
ok
palette="$(grep -n -- '--innsegl-palette-' "${SITE_CSS}" "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}" || true)"
if [ -n "${palette}" ]; then
  fail "page reaches past the semantic layer into --innsegl-palette-*:
${palette}"
fi

# doc 06 §5.3: green is cryptographic verification and nothing else. This site
# verifies nothing, so it may not name the one family that holds the greens.
ok
green="$(grep -nE 'proof-verified|innsegl-palette-verification' \
          "${SITE_CSS}" "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}" || true)"
if [ -n "${green}" ]; then
  fail "the verification (green) tokens appear on a page that verifies nothing — doc 06 §5.3, §8 anti-pattern 3:
${green}"
fi

# ---------------------------------------------------------------------------
# G. Self-contained — no third-party request to render our own words
# ---------------------------------------------------------------------------
ok
external="$(grep -nE '<(link|script|img|iframe|source|video|audio)[^>]+(href|src)="(https?:)?//' \
             "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}" || true)"
external="${external}$(grep -nE '@import|url\((["'\''"]?)(https?:)?//' "${SITE_CSS}" || true)"
if [ -n "${external}" ]; then
  fail "page loads a resource from another origin (doc 06 §7, ADR-0038 decision 7):
${external}"
fi

# ---------------------------------------------------------------------------
# H. No JavaScript
# ---------------------------------------------------------------------------
ok
scripts="$(grep -nE '<script|javascript:|[[:space:]]on[a-z]+=' "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}" || true)"
if [ -n "${scripts}" ]; then
  fail "the root site runs JavaScript; it has nothing that needs any:
${scripts}"
fi

# ---------------------------------------------------------------------------
# I. Ordinary page hygiene
# ---------------------------------------------------------------------------
for page in "${INDEX}" "${MODULE_PAGE}" "${NOT_FOUND}"; do
  rel="${page#"${SITE_DIR}/"}"
  ok
  grep -q '<html lang="en">' "${page}" || fail "${rel}: no <html lang=\"en\">"
  ok
  grep -q '<meta name="viewport"' "${page}" || fail "${rel}: no viewport meta"
  ok
  grep -q '<title>' "${page}" || fail "${rel}: no <title>"
  ok
  grep -q 'href="/tokens.css"' "${page}" || fail "${rel}: does not load /tokens.css"
done

# ---------------------------------------------------------------------------
# J. Redirects
# ---------------------------------------------------------------------------
ok
grep -qE "^/repo[[:space:]/*]*[[:space:]]+${REPO_URL}" "${REDIRECTS}" \
  || fail "_redirects has no /repo rule pointing at ${REPO_URL} (doc 05 §3: the root serves a redirect to the repository)"

# Nothing may shadow the module path itself: a redirect on /innsegl would send
# the go command somewhere other than the meta tag.
ok
shadow="$(awk -v p="/${MODULE_PATH#*/}" '$1 == p { print FNR": "$0 }' "${REDIRECTS}" || true)"
if [ -n "${shadow}" ]; then
  fail "_redirects shadows the module path itself:
${shadow}"
fi

# ---------------------------------------------------------------------------
# K. Optional: drive the real Go module resolver against this site
# ---------------------------------------------------------------------------
if [ "${RESOLVE}" = "1" ]; then
  printf '\n==> Resolver proof — the go command follows the tag\n'
  "${SCRIPT_DIR}/resolve-proof.sh" "${SITE_DIR}" "${MODULE_PATH}" "${REPO_URL}" || fails=$((fails + 1))
  ok
fi

printf '\n'
if [ "${fails}" -gt 0 ]; then
  printf '%d of %d checks failed.\n' "${fails}" "${checks}" >&2
  exit 1
fi
printf 'OK: %d checks passed.\n' "${checks}"
