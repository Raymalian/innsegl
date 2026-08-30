#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Token sheet gate for the Innsegl dashboard (RM-039, #47; ADR-0038).
#
# doc 06 §5.3 governs the palette, and it is the rule most likely to be broken
# later by somebody adding a "success green" for something that is not a
# cryptographic verification:
#
#   "Green = cryptographic verification passed. Nothing else is ever green.
#    Not 'run completed,' not 'healthy,' not positive trends."
#
# doc 06 §8 makes that a defect ("3. Green used for anything other than
# cryptographic verification"), and §6.4 makes contrast in BOTH modes gating
# rather than aspirational. A review pass finds those the day someone looks.
# This finds them on the commit that introduces them.
#
# WHAT THIS CHECKS, IN SIX PARTS
# ------------------------------
# A. Layering. Every --innsegl-palette-* token is a literal #rrggbb; every
#    --innsegl-color-* token is a light-dark() of exactly two palette
#    references. A semantic token holding a raw hex is a value that escaped the
#    palette; a semantic token that is not light-dark() is a colour with only
#    one mode, which is the failure that stays invisible until somebody
#    switches themes.
#
# B. Resolution. Every var() a semantic token names must exist. An unresolved
#    custom property is not a CSS error — it renders as `unset` and inherits,
#    silently, which in a verification badge means a verdict rendered in the
#    wrong colour rather than a broken page.
#
# C. Family confinement. This is §5.3 as a gate. Each semantic group may draw
#    from exactly one palette family, and the verification family may be drawn
#    from by the proof-verified group ALONE. Nothing else in the sheet can be
#    green, because nothing else can name the family that holds the greens.
#
# D. Naming. No token name may contain a hue word, and none may contain
#    success/healthy/positive/good/ok. Both halves matter: a hue-named token
#    invites "I need a green here", and a success-named token IS the
#    anti-pattern, already spelled. Tokens are named for what they claim.
#
# E. Theme mechanics. `color-scheme: light dark` on :root, plus the two
#    [data-theme] overrides doc 06 §5.1 asks for ("honoring prefers-color-scheme
#    with a manual override").
#
# F. Contrast. Every pair in contrast-pairs.txt, in the light arm AND in the
#    dark arm, against WCAG 2.1 relative luminance.
#
# Usage:
#   web/src/tokens/check-tokens.sh                 # check the shipped sheet
#   web/src/tokens/check-tokens.sh path/to/x.css   # check another sheet (self-test)
#
# Environment:
#   TOKENS_PAIRS_FILE   contrast manifest to use (default: the one beside this
#                       script)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOKENS_FILE="${1:-${SCRIPT_DIR}/tokens.css}"
PAIRS_FILE="${TOKENS_PAIRS_FILE:-${SCRIPT_DIR}/contrast-pairs.txt}"

if [ ! -f "${TOKENS_FILE}" ]; then
  printf 'FAIL: token sheet not found: %s\n' "${TOKENS_FILE}" >&2
  exit 1
fi
if [ ! -f "${PAIRS_FILE}" ]; then
  printf 'FAIL: contrast manifest not found: %s\n' "${PAIRS_FILE}" >&2
  exit 1
fi

printf '==> Token sheet — doc 06 §§5.1, 5.3, 6.4\n'
printf '    sheet %s\n' "${TOKENS_FILE}"
printf '    pairs %s\n' "${PAIRS_FILE}"

awk -v tokens_file="${TOKENS_FILE}" '
# ---------------------------------------------------------------------------
# The permitted mapping, semantic group -> palette family. This table IS
# doc 06 §5.3. Adding a row is a design decision; it is meant to be awkward.
# ---------------------------------------------------------------------------
function init_policy() {
  # Green. The whole reason the sheet is governed.
  allowed["proof-verified"]      = "verification"
  # Red — verification failed or integrity alert (§5.3), and the mismatch
  # highlight in the three-check panel (§4.1), which is a failed comparison.
  allowed["proof-failed"]        = "failure"
  allowed["integrity-alert"]     = "failure"
  allowed["mismatch"]            = "failure"
  # Amber — degraded/unavailable: verification unavailable, anchoring lag,
  # staleness (§5.3).
  allowed["proof-unavailable"]   = "degraded"
  allowed["degraded"]            = "degraded"
  # The one semantically meaningless accent (§5.3), and the focus ring, which
  # is interactive chrome and carries no verdict.
  allowed["accent"]              = "accent"
  allowed["focus"]               = "accent"
  # Everything else is neutral grey: structure, chrome, and run status
  # including Retired/Expired (§5.3).
  allowed["text"]                = "neutral"
  allowed["surface"]             = "neutral"
  allowed["border"]              = "neutral"
  allowed["status"]              = "neutral"

  # A palette family that is not in this list is a fifth hue nobody decided on.
  known_family["neutral"]     = 1
  known_family["verification"] = 1
  known_family["failure"]      = 1
  known_family["degraded"]     = 1
  known_family["accent"]       = 1

  # §5.3 says colour is a claim, so a token may not be named for its hue, and
  # may not be named for a claim the palette does not make.
  split("green red amber yellow blue indigo violet teal cyan orange purple pink gray grey white black", banned_words, " ")
  for (i in banned_words) banned[banned_words[i]] = "a hue is not a meaning (§5.3)"
  split("success successful ok okay good positive healthy passed", claim_words, " ")
  for (i in claim_words) banned[claim_words[i]] = "green is only ever cryptographic verification (§5.3, §8.3)"

  # Hex digits, for parsing.
  for (i = 0; i <= 9; i++) hexval[i "" ] = i
  hexval["a"] = 10; hexval["b"] = 11; hexval["c"] = 12
  hexval["d"] = 13; hexval["e"] = 14; hexval["f"] = 15
}

function fail(msg) { failures[++nfail] = msg }

function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }

# Remove /* */ comments, including across lines.
function strip(line,    p, q, rest) {
  while (1) {
    if (incomment) {
      p = index(line, "*/")
      if (p == 0) return ""
      line = substr(line, p + 2)
      incomment = 0
    } else {
      p = index(line, "/*")
      if (p == 0) return line
      rest = substr(line, p + 2)
      q = index(rest, "*/")
      if (q == 0) { incomment = 1; return substr(line, 1, p - 1) }
      line = substr(line, 1, p - 1) substr(rest, q + 2)
    }
  }
}

# Split the top-level arguments of a fn(...) expression into args[1..n].
function fnargs(v, args,    open, inner, depth, i, c, cur, n) {
  open = index(v, "(")
  if (open == 0) return 0
  if (substr(v, length(v), 1) != ")") return 0
  inner = substr(v, open + 1, length(v) - open - 1)
  depth = 0; cur = ""; n = 0
  for (i = 1; i <= length(inner); i++) {
    c = substr(inner, i, 1)
    if (c == "(") depth++
    else if (c == ")") depth--
    if (c == "," && depth == 0) { args[++n] = trim(cur); cur = "" }
    else cur = cur c
  }
  args[++n] = trim(cur)
  return n
}

# Resolve a token to a #rrggbb in one mode. mode is 1 (light) or 2 (dark).
# Returns "" when it cannot, recording why in resolve_err.
function resolve(name, mode, depth,    v) {
  if (depth > 12) { resolve_err = "cycle through " name; return "" }
  if (!(name in val)) { resolve_err = "undefined token " name; return "" }
  return resolve_value(val[name], mode, depth + 1, name)
}

function resolve_value(v, mode, depth, origin,    args, n, inner) {
  v = trim(v)
  if (v ~ /^#[0-9a-f]{6}$/) return v
  if (v ~ /^light-dark[ \t]*\(/) {
    n = fnargs(v, args)
    if (n != 2) { resolve_err = origin ": light-dark() needs exactly two arms, found " n; return "" }
    return resolve_value(args[mode], mode, depth + 1, origin)
  }
  if (v ~ /^var[ \t]*\(/) {
    n = fnargs(v, args)
    if (n < 1) { resolve_err = origin ": malformed var()"; return "" }
    return resolve(args[1], mode, depth + 1)
  }
  resolve_err = origin ": not a colour this gate can resolve: " v
  return ""
}

function hex2dec(h,    i, n) { n = 0; for (i = 1; i <= length(h); i++) n = n * 16 + hexval[substr(h, i, 1)]; return n }

function channel(c) { c = c / 255.0; return (c <= 0.03928) ? c / 12.92 : ((c + 0.055) / 1.055) ^ 2.4 }

function luminance(hex,    r, g, b) {
  r = hex2dec(substr(hex, 2, 2)); g = hex2dec(substr(hex, 4, 2)); b = hex2dec(substr(hex, 6, 2))
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function contrast(a, b,    la, lb, hi, lo) {
  la = luminance(a); lb = luminance(b)
  hi = (la > lb) ? la : lb; lo = (la > lb) ? lb : la
  return (hi + 0.05) / (lo + 0.05)
}

BEGIN { init_policy(); mode_name[1] = "light"; mode_name[2] = "dark" }

# ---- pass 1: the contrast manifest -----------------------------------------
FNR == NR {
  line = $0
  sub(/#.*$/, "", line)
  if (trim(line) == "") next
  npair++
  split(line, f, /[ \t]+/)
  pair_fg[npair] = f[1]; pair_bg[npair] = f[2]; pair_min[npair] = f[3] + 0
  if (pair_fg[npair] == "" || pair_bg[npair] == "" || pair_min[npair] <= 0)
    fail("contrast manifest line " FNR " is malformed: " $0)
  next
}

# ---- pass 2: the token sheet -----------------------------------------------
{
  l = strip($0)
  if (trim(l) == "") next
  raw = raw l "\n"
  if (match(l, /--innsegl-[A-Za-z0-9-]+[ \t]*:/)) {
    name = substr(l, RSTART, RLENGTH)
    sub(/[ \t]*:$/, "", name)
    v = substr(l, RSTART + RLENGTH)
    sub(/;.*$/, "", v)
    v = trim(v)
    if (name in val) {
      # Only the motion tokens are legitimately redefined, by the
      # prefers-reduced-motion block. Anything else is a drifted duplicate.
      if (name !~ /^--innsegl-motion-/) fail("token defined twice: " name)
    } else {
      order[++ntok] = name
    }
    if (!(name in val)) val[name] = v
    lineno[name] = FNR
  }
}

END {
  if (ntok == 0) fail("no --innsegl-* tokens found in " tokens_file " — is this a token sheet?")

  # ---- D. naming ----------------------------------------------------------
  for (i = 1; i <= ntok; i++) {
    name = order[i]
    stem = name; sub(/^--innsegl-/, "", stem)
    nseg = split(stem, seg, "-")
    for (j = 1; j <= nseg; j++)
      if (seg[j] in banned)
        fail("token name contains \"" seg[j] "\": " name " (line " lineno[name] ") — " banned[seg[j]])
  }

  # ---- A. layering + B. resolution ---------------------------------------
  for (i = 1; i <= ntok; i++) {
    name = order[i]
    v = val[name]
    if (name ~ /^--innsegl-palette-/) {
      if (v !~ /^#[0-9a-f]{6}$/)
        fail("palette token must be a literal #rrggbb: " name " = " v " (line " lineno[name] ")")
      npalette++
      stem = name; sub(/^--innsegl-palette-/, "", stem)
      split(stem, seg, "-")
      family = seg[1]
      if (!(family in known_family))
        fail("palette family \"" family "\" is not one of the five doc 06 §5.3 sanctions: " name)
      seen_family[family]++
      continue
    }
    if (name !~ /^--innsegl-color-/) continue
    nsemantic++
    if (v !~ /^light-dark[ \t]*\(/) {
      fail("semantic colour must be light-dark(light, dark): " name " = " v " (line " lineno[name] ")")
      continue
    }
    n = fnargs(v, args)
    if (n != 2) {
      fail("semantic colour needs exactly two light-dark() arms: " name " has " n " (line " lineno[name] ")")
      continue
    }
    for (m = 1; m <= 2; m++) {
      arm = args[m]
      if (arm !~ /^var[ \t]*\([ \t]*--innsegl-palette-/) {
        fail("the " mode_name[m] " arm of " name " is not a palette reference: " arm " (line " lineno[name] ")")
        continue
      }
      fnargs(arm, refargs)
      ref = refargs[1]
      if (!(ref in val)) {
        fail("the " mode_name[m] " arm of " name " names a token that does not exist: " ref " (line " lineno[name] ")")
        continue
      }
      # ---- C. family confinement ------------------------------------------
      refstem = ref; sub(/^--innsegl-palette-/, "", refstem)
      split(refstem, rseg, "-")
      reffamily = rseg[1]
      stem = name; sub(/^--innsegl-color-/, "", stem)
      # Recorded BEFORE the group check, not after: recorded after, the
      # verification reserve below could only ever see the group that is
      # already allowed the family, and would be a check that cannot fail.
      group = ""
      # Longest matching group prefix wins, so proof-verified beats nothing
      # and status-expired resolves through "status".
      for (g in allowed)
        if (index(stem, g "-") == 1 && length(g) > length(group)) group = g
      family_used_by[reffamily] = family_used_by[reffamily] " " group
      if (group == "") {
        fail("no doc 06 §5.3 group governs " name " — add it to the policy table in this script, deliberately (line " lineno[name] ")")
        continue
      }
      if (reffamily != allowed[group]) {
        fail("§5.3 violation: " name " (group \"" group "\", may use the \"" allowed[group] "\" family) draws its " mode_name[m] " arm from the \"" reffamily "\" family via " ref " (line " lineno[name] ")")
        continue
      }
    }
  }

  if (npalette == 0) fail("no --innsegl-palette-* tokens found — the semantic layer has nothing to draw from")
  if (nsemantic == 0) fail("no --innsegl-color-* tokens found — there is no semantic layer")

  # The verification family is the one doc 06 §5.3 reserves outright.
  nfam = split(family_used_by["verification"], vusers, " ")
  for (i = 1; i <= nfam; i++)
    if (vusers[i] != "" && vusers[i] != "proof-verified")
      fail("§5.3 violation: the verification (green) family is drawn from by group \"" vusers[i] "\" — green is only ever cryptographic verification")

  # ---- E. theme mechanics -------------------------------------------------
  if (raw !~ /color-scheme:[ \t]*light[ \t]+dark/)
    fail("no `color-scheme: light dark` on :root — prefers-color-scheme is not honoured and light-dark() has nothing to switch on (§5.1)")
  if (raw !~ /\[data-theme="light"\]/)
    fail("no [data-theme=\"light\"] override — §5.1 requires a manual override in both directions")
  if (raw !~ /\[data-theme="dark"\]/)
    fail("no [data-theme=\"dark\"] override — §5.1 requires a manual override in both directions")

  # ---- F. contrast, in both modes ----------------------------------------
  for (p = 1; p <= npair; p++) {
    for (m = 1; m <= 2; m++) {
      resolve_err = ""
      fg = resolve(pair_fg[p], m, 0)
      if (fg == "") { fail("contrast pair " p ": cannot resolve " pair_fg[p] " in " mode_name[m] " — " resolve_err); continue }
      resolve_err = ""
      bg = resolve(pair_bg[p], m, 0)
      if (bg == "") { fail("contrast pair " p ": cannot resolve " pair_bg[p] " in " mode_name[m] " — " resolve_err); continue }
      r = contrast(fg, bg)
      nchecked++
      if (r < pair_min[p])
        fail(sprintf("contrast %s on %s in %s mode is %.2f:1, below the required %.1f:1 (%s on %s)",
             pair_fg[p], pair_bg[p], mode_name[m], r, pair_min[p], fg, bg))
      else if (r < worst_ratio || worst_ratio == 0) { worst_ratio = r; worst_desc = sprintf("%s on %s (%s) %.2f:1", pair_fg[p], pair_bg[p], mode_name[m], r) }
    }
  }

  printf "    %d palette values, %d semantic colours, %d contrast assertions (%d pairs x 2 modes)\n", npalette, nsemantic, nchecked, npair
  if (worst_ratio > 0) printf "    tightest passing margin: %s\n", worst_desc

  if (nfail > 0) {
    printf "\nFAIL: %d problem(s) in the token sheet:\n", nfail
    for (i = 1; i <= nfail; i++) printf "  %s\n", failures[i]
    printf "\n"
    exit 1
  }
  printf "\nToken sheet: OK\n"
}
' "${PAIRS_FILE}" "${TOKENS_FILE}"
