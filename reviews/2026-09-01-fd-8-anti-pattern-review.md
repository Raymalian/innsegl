# doc 06 §8 anti-pattern review — Phase 4 sign-off

**Deliverable:** doc 06 §9, last item — "A review pass against Section 8 with each
anti-pattern explicitly checked and recorded as absent — measured from rendered
output, not asserted from code reading."

**Issue:** RM-050 (#58). **Branch:** `dev/e6-wave5`. **Date:** 2026-09-01.

**Scope of what was reviewed:** `web/src/app/`, `web/src/components/common/`,
`web/src/components/verification/`, the six views under `web/src/views/`, and
`web/src/tokens/`, as compiled by `npm run build` at the working tree recorded in
each evidence file.

---

## Verdicts

| # | doc 06 §8 | Verdict | Where the measurement is |
|---|---|---|---|
| 1 | A "verified" state rendered from cache while the live check errored | **Absent** — with one gap in the structural claim | `evidence/01-cached-verdict.txt` |
| 2 | Any collapse of *failed* and *unavailable* into one visual state | **Absent** | `evidence/02-failed-vs-unavailable.txt` |
| 3 | Green used for anything other than cryptographic verification | **Absent from every rendered view.** One **defect** in the shipped stylesheet | `evidence/03-green.txt` |
| 4 | A verification summary that cannot be expanded to the three checks and their inputs | **Absent** — with one route the claim does not close | `evidence/04-summary-expands.txt` |
| 5 | Mutating controls of any kind in the UI | **Absent** | `evidence/05-mutating-controls.txt` |
| 6 | Identifiers rendered in proportional type, or truncated so the trust domain is lost | **Absent** | `evidence/06-identifiers.txt` |
| 7 | Silent staleness — degraded data without the §4.4 marker | **Absent** for the five ledger-backed views; §3.6 is out of §4.4's scope and is recorded as a boundary | `evidence/07-staleness.txt` |
| 8 | Spinners without timeout-to-error | **Absent** | `evidence/08-spinner-timeout.txt` |
| 9 | Celebratory or reassuring copy substituting for evidence | **Absent** | `evidence/09-copy.txt` |
| 10 | Metrics chosen to look good rather than to inform | **Present in shape — recorded as a defect, contested.** One card is a cumulative lifetime count with no window, which is §8.10's own first example. The named failures §8.10 warns about are otherwise absent | `evidence/10-metrics.txt` |

Two defects and three residual gaps are itemised under **Defects and findings**
below. None has been fixed: the issue forbids it.

---

## How this was measured, and what that is worth

doc 06 §9 forbids one method by name, so the method matters as much as the
verdicts.

**Rendered output, not source.** Fifty scenes are mounted in jsdom —
every component in the states that would expose a defect, and each of the six
views of doc 06 §3 in its calm, empty, failed, degraded and alerting states.
Every measurement below is taken from the resulting DOM, from
`web/dist/assets/*.css` as `npm run build` compiled it, from the built
JavaScript bundle, or from a command's own output. `reviews/harness/gallery.tsx`
is the mounting; nothing in it asserts.

**Colour is resolved the way a browser resolves it.** jsdom implements no
cascade for custom properties: `getComputedStyle(el).color` on an element
painted by `var(--innsegl-color-proof-verified-text)` returns the literal
`var(...)` string, and `light-dark()` is not evaluated at all. So the harness
joins the two artefacts a browser would itself combine — an element's class
attribute and the built stylesheet — chases `var()` through the `:root` block
the build inlined from `tokens.css`, evaluates `light-dark()` once per mode, and
converts the result to a hue. Both inputs are build output. A colour reported
here is one the build produced.

**Where a claim is structural, it was attacked.** ADR-0038 argues several of
these are unrepresentable rather than merely absent. Eleven violations were
written and fed to the toolchain that is supposed to refuse them — `tsc` for the
prop contracts, `@tailwindcss/node` for the palette deletion,
`web/src/tokens/check-tokens.sh` for the token sheet. Each refusal is quoted in
the evidence. Two attempts were *not* refused, and both are recorded as findings.

**The instrument was tested before the product.** The brief carries a warning
from this repository's own history: a test proved two states differed by
stripping `class` and `style` while leaving a `data-*` attribute in place, so the
assertion could not fail. `probes/00-instrument.probe.tsx` exists because of it.
The colour classifier is shown returning "green" for the shipped verification
ramp, for a synthetic `bg-[#00ff00]` element pushed through the same code path,
and across a printed 10°-step sweep of the whole wheel. Probe 2 runs its
difference test over a pair that is genuinely identical and reports "identical".
Probe 9 runs its banned-vocabulary scan over an invented sentence containing the
banned copy and shows 10 of 15 patterns firing.

**Nothing reads an attribute where a difference is claimed.**
`reviews/harness/perceptible.ts` builds a perception from the channels a person
has — the visible words with `sr-only` subtrees removed, the drawn path geometry
of every icon, the colours the built stylesheet paints — and discards `class`,
`style` and every `data-*` rather than trusting them. Three channels are compared
separately: sighted (both modes), **greyscale** with every colour deleted, and
announced.

### What this method cannot see

Stated plainly, because an "absent" that rests on the wrong instrument is worth
less than an honest "not determinable".

- **No layout.** jsdom computes no boxes. Nothing here can say whether an
  element is visible, on screen, overlapped, or whether an identifier fits its
  column.
- **No user-agent stylesheet for `<details>`.** jsdom does not hide a closed
  disclosure's content, so probe 4 can prove the three checks are *reachable*
  from a rollup and cannot show you the collapsed rendering.
- **Base state only.** Rules carrying a pseudo-class (`:hover`,
  `:focus-visible`) or a media condition are parsed and indexed but never folded
  into an element's paint. A defect reachable only on hover is out of range.
- **No perceptual model.** The classifier is arithmetic on hue and chroma. It
  does not know what a reader with a colour vision deficiency sees.

Each of these is a browser measurement. The browser harness is #57, running in
parallel on this branch; this review may not and does not depend on its output.
Where one of the ten turns partly on something in this list, the sub-question is
named as **not determinable here** in its section rather than folded into the
verdict.

---

## 1. A "verified" state rendered from cache while the live check errored

**Verdict: absent.** One gap in the structural claim, recorded below.

**What was done.** Four panels were mounted carrying *the same three passing
checks*, differing only in where the proof came from and whether anything
answered. The rollup badge was located by its position and its drawn mark, never
by `data-verdict`, and its colour resolved in both modes.

```
panel/verified-live               badge reads "Verified"
                                  color=#116039/#6ccf95 (green/green)
panel/cached-verified-live-errored badge reads "Verification unavailable"
                                  color=#6f4e03/#dfb144 (amber/amber)
panel/cached-verified-no-error    badge reads "Verification unavailable"
                                  color=#6f4e03/#dfb144 (amber/amber)
panel/live-upstream-unreachable   badge reads "Verification unavailable"
                                  color=#6f4e03/#dfb144 (amber/amber)
```

The green appears once, on the live check. The panel also states its reason in
visible prose rather than only withholding the colour:

> Reported as unavailable — The live check could not run, so an earlier verdict
> is not repeated here. … `fulcio: connection refused`

**The structural half, tested rather than trusted.** The brief records that
`liveness` was optional and defaulted to live, and is now required. Three
omissions were written and compiled:

```
export const attempt = <VerificationPanel proof={verifiedProof()} />;
  -> error TS2741: Property 'liveness' is missing in type '{ proof: Proof; }'
     but required in type 'VerificationPanelProps'.
```

The same refusal for `VerificationSummary`, and for `PassRateCard`'s `rate`
prop, whose `MeasuredLiveness` requires `source` outright.

**Not determinable here:** nothing. This one is fully measurable without a
browser.

---

## 2. Any collapse of *failed* and *unavailable* into one visual state

**Verdict: absent.**

**What was done.** `panel/failed` and `panel/unavailable` were compared in four
channels. The first line at which they part is quoted in each:

```
sighted, light mode: differ
  failed:      <span [background-color=#fdecec border-color=#c02029 color=#9b1921 …]>
  unavailable: <span [background-color=#fbf2da border-color=#8c6404 color=#6f4e03 …]>

sighted, dark mode: differ
  failed:      <span [background-color=#480a0e border-color=#e5626a color=#f0989d …]>
  unavailable: <span [background-color=#332401 border-color=#c6951d color=#dfb144 …]>

greyscale (colour deleted): differ
  failed:      <drawn path(d=M8 2 14.5 13.5h-13z) path(d=M8 6.5v3.5) path(d=M8 12v.5)>
  unavailable: <drawn circle(cx=8 cy=8 r=5.5) path(d=M6.5 6.5a1.5 1.5 0 1 1 1.5 1.5V9.5) …>

announced: differ
  failed:      <span title=A check ran and what it checked does not hold.>
  unavailable: <span title=A check could not run, so nothing here is proven either way.>
```

The greyscale row is the one that matters for doc 06 §6.4's "never color alone":
a triangle against a questioned ring, with colour deleted entirely. The three
verdict words also differ ("Failed" / "Verification unavailable" / "Verified"),
and all three pairwise comparisons of the rollup badge differ in sighted,
greyscale and announced channels.

At page level, the public verification page with unreachable upstreams and the
same page with checks that ran and failed render different words.

**Not determinable here:** whether the two hues are distinguishable to a reader
with a colour vision deficiency. The greyscale channel makes that question
non-load-bearing — the shapes and words already carry it — but the question
itself needs a perceptual model this review does not have.

---

## 3. Green used for anything other than cryptographic verification

**Verdict: absent from every rendered view. One defect in the shipped stylesheet.**

**What was done — four sweeps from four directions.**

*From the rendered output.* 5,940 elements across 50 scenes were walked, each
element's classes joined to the built stylesheet, `var()` chased and
`light-dark()` evaluated in both modes. 78 green declarations were found. The
words beside every one of them, deduplicated, are a single string:

```
    "Verified"
```

The four scenes a careless build would have made green were checked by name and
are not:

```
    view/overview-calm       green present: no
    badge/status-active      green present: no
    heartbeat/within-bound   green present: no
    view/runs-ready          green present: no
```

No rendered element carries a class the build compiled nothing for, and no
element in any scene carries a `style` attribute at all.

*From the stylesheet.* 30 green-valued declarations exist in the whole built
file. 28 name a `--innsegl-palette-verification-*` ramp or a
`--innsegl-color-proof-verified-*` token. Two do not — see the defect below.

*From the source.* Two occurrences of an arbitrary colour value exist in
`web/src`, both inside comments explaining the rule; zero in code. Every
arbitrary-*property* class is enumerated in the evidence and each names an
`--innsegl-*` token. The built JavaScript bundle contains **no colour literal at
all**.

*By attacking the gate.* Four violating token sheets were written and
`check-tokens.sh` was handed each. All four were refused:

```
ATTEMPT: a green for "run completed", as a status token drawing from the
         verification family              -> FAIL: 4 problem(s)
ATTEMPT: a raw green hex in a semantic token, past the palette
                                          -> FAIL: 2 problem(s)
ATTEMPT: a new palette family named for the claim it wants to make
                                          -> FAIL: 2 problem(s)
ATTEMPT: a green that exists in light mode only
                                          -> FAIL: 3 problem(s)
```

ADR-0038 decision 4's claim was tested by feeding candidates to the same
compiler `npm run build` uses:

```
bg-green-500, text-green-600, bg-emerald-50, text-emerald-500, text-lime-400,
bg-teal-500, text-red-600, bg-amber-400, text-xs, text-9xl, p-13, shadow-2xl,
animate-bounce, animate-pulse, dark:text-green-500   -> no CSS emitted
bg-[#00ff00]        -> background-color:#0f0
text-proof-verified -> color:var(--innsegl-color-proof-verified-text)
```

**DEFECT — a green in the shipped production stylesheet.** See below.

**Not determinable here:** whether the green is legible against its surface at
render. The token gate asserts 66 contrast values over 33 declared pairs (the
tightest passing margin is 3.19:1), but a component may compose any token over
any background, and only the manifest's pairs are checked. Composed contrast
needs a browser.

---

## 4. A verification summary that cannot be expanded to the three checks and their inputs

**Verdict: absent.** One route the claim does not close, recorded below.

**What was done.** Every verdict badge in the gallery was located by what it
*says* and what it *draws* — an element whose visible words are one of doc 06
§4.2's four verdict words and which carries a drawn mark — and no attribute was
consulted. 71 badges were found. For each, either the three named checks are
already beside it on the page, or it sits inside a disclosure that reveals them:

```
badges located: 71;  badges that cannot reach three checks: 0
```

One rollup from the runs table was opened in full and the *inputs* doc 06 §8.4
names were measured individually:

```
present  all three check names
present  the Rekor log index          (82914)
present  the commit SHA
present  the trailer identity
present  a raw-material disclosure    (commit object, cert PEM, Fulcio root, Rekor key)
present  a per-check tri-state word
```

**The structural half.** `VerificationSummary`'s file comment claims "There is
no prop that turns the panel off and no variant that renders the badge alone."
Both were written; both were refused by `tsc`.

**Not determinable here:** whether a closed `<details>` visually hides its
content. jsdom implements no user-agent rule for it. This does not affect the
verdict — §8.4 forbids a summary that *cannot* expand, and reachability is what
was measured — but the collapsed rendering itself is a browser question.

---

## 5. Mutating controls of any kind in the UI

**Verdict: absent.**

**What was done.** Every `button`, `a[href]`, `form`, `input`, `select`,
`textarea`, `[role=button]`, `[contenteditable]` and `[onclick]` in every scene
was enumerated from the DOM with the words a reader would act on, then classified
against doc 06 P6's four permitted actions. Every control resolves to copy,
navigate, filter/paginate, re-read, disclose, or set a local theme preference.

No control in the gallery carries a word from the mutation vocabulary — delete,
remove, revoke, retire, edit, update, save, create, add, submit, approve, reject,
disable, enable, rotate, publish, upload, import, write, modify, archive,
restore. The one `<form>` in the product carries no `method`, so it is an HTML
GET, and its submit handler calls `history.pushState`.

The other half of a mutation is a method, so the **built bundle** was read rather
than the source:

```
method: options found in the bundle: GET

fetch(m.href,v)
fetch(eb(i),{signal:c,headers:{accept:"application/json"}})
fetch(i,{signal:c,headers:{Accept:"application/json"}})
fetch(h0(i),{signal:c,headers:{accept:"application/json"}})
fetch(`/api/v1/proof/${encodeURIComponent(i)}`,{signal:c})
fetch(`/api/v1/runs/${encodeURIComponent(i)}`,{signal:c})
fetch(i,{signal:c,method:"GET",cache:"no-store",headers:{accept:"application/json"}})
```

No `POST`, `PUT`, `PATCH` or `DELETE` string appears anywhere in the shipped
JavaScript; no `XMLHttpRequest`, no `sendBeacon`. The one write the product
performs is `localStorage.setItem("innsegl.theme", …)`, which leaves nothing but
the reader's own browser; it is named in the evidence rather than left out.

**Not determinable here:** nothing at the frontend. Whether the *server* refuses
non-GET is a Go question outside this review's scope.

---

## 6. Identifiers rendered in proportional type, or truncated so the trust domain is lost

**Verdict: absent.**

**What was done.** Identifier-shaped strings were found by *shape* rather than by
the component that drew them — a SPIFFE URI, a 40-hex SHA, a `sha256:` digest, a
ULID, a log index — and the `font-family` was resolved from the built stylesheet
walking ancestors for inheritance the way a browser does. 178 were found:

```
commit SHA   34 occurrence(s), 34 in mono
Rekor index  27 occurrence(s), 27 in mono
SPIFFE ID    53 occurrence(s), 53 in mono
digest       43 occurrence(s), 43 in mono
ULID         21 occurrence(s), 21 in mono
-> ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace

Identifiers rendered in a font other than the mono token: none.
```

The other half of doc 06 §5.2 was measured too: every string the sheet paints
mono on is an identifier, digest, timestamp, PEM block, upstream URL or verbatim
error message.

Every rendered truncation was compared against the full value the same control
carries; head, tail and trust domain survive in all of them. The component was
then pushed past its stated width:

```
requested maxLength: 12
rendered glyphs:     "spiffe://innsegl.dev/…/run-7f3a2c"  (33 characters)
full value:          "spiffe://innsegl.dev/agent/fix-ci/task-1481/attempt-3/shard-11/run-7f3a2c"
trust domain "spiffe://innsegl.dev" present in the glyphs: YES
```

The width loses, as `identifier.ts` claims it does. The abbreviated glyphs carry
`aria-hidden="true"`, so the ellipsis never reaches a reader who cannot see it is
one, and the full value is in the `title` and in the control's accessible name.

**Not determinable here:** whether an untruncated identifier overflows the column
it is drawn in. That is layout.

---

## 7. Silent staleness — degraded data without the §4.4 marker

**Verdict: absent** for the five ledger-backed views. §3.6 is outside §4.4's
scope; recorded as a boundary rather than a defect.

**What was done.** Each of doc 06 §3's six views was mounted **twice** against
the same data and the same clock, once with the read path healthy and once
degraded, and the two renderings were diffed on what a reader perceives. A view
that renders identically in both is serving degraded data silently.

| view | differ? | says "data as of"? |
|---|---|---|
| 3.1 overview | yes | yes |
| 3.2 runs | yes | yes |
| 3.3 run detail | yes | yes |
| 3.4 repo | yes | yes |
| 3.5 agent type | yes | yes |
| 3.6 public verification | **no** | no |

What the degradation adds, quoted from the overview:

> Data as of 2026-08-31 11:31:00 UTC (29 min ago). The ledger read path is
> degraded, so this view may be behind.

The marker is amber in both modes (`#6f4e03` / `#dfb144`), which is doc 06 §5.3's
assignment for staleness.

**The sixth view.** §4.4 scopes the marker to "whenever the **dashboard** serves
data while the **ledger read path** is degraded". §3.6's page reads no ledger —
it "performs **live** checks against Fulcio/Rekor" and "offers nothing
database-only in their place" — so there is no ledger read for it to be serving
staleness from, and its honesty about a degraded dependency is the
unreachable-upstream state instead, which is quoted in the evidence. **Recorded
for the human:** if a deployment ever routes §3.6 through a cached ledger read,
§4.4 begins to apply and nothing in the view would notice. Today it does not.

**Not determinable here:** whether the marker is *visible* on a real page rather
than merely in the DOM.

---

## 8. Spinners without timeout-to-error

**Verdict: absent.**

**What was done.** Every view was handed a promise that **never settles** — not a
rejection, not a slow resolve, which is what a hung dependency is — under fake
timers, and the clock advanced to 60 s, four times the longest bound in the
build.

The component's own transition happens at the bound and not before it:

```
t = 0 s                       "Loading runs…"
t = 14.999 s                  "Loading runs…"        (unchanged)
t = 15 s + 1 ms               "Couldn't load runs — timed out after 15 s
                               Showing nothing rather than guessing. Retry"
```

The timed-out element carries `role="alert"`; the busy state is replaced, not
annotated. All six views moved out of loading and said so explicitly:

```
3.1 overview      -> Couldn't load the overview — timed out after 15 s …
3.2 runs          -> Couldn't load runs — timed out after 15 s …
3.3 run detail    -> Couldn't load the run — timed out after 15 s …
3.4 repo          -> Couldn't load the runs for this repository — timed out after 15 s …
3.5 agent type    -> Couldn't load the runs of this agent type — timed out after 15 s …
3.6 public verify -> (its own request bound, from client.DEFAULT_REQUEST_TIMEOUT_MS)

views still loading after 60 s with a hung read: 0
```

The other half of the anti-pattern's name was measured against the built
stylesheet:

```
@keyframes blocks in the built stylesheet:      0
animation / animation-* declarations:           0
```

Nothing in this build can spin. The loading indicator draws three static discs.
`prefers-reduced-motion` collapses both duration tokens to `1ms` in the sheet
itself, so a component that forgot to ask still complies.

**Not determinable here:** whether the timed-out state is on screen and legible.
The DOM changes at the bound; a browser is needed to confirm a reader sees it.

---

## 9. Celebratory or reassuring copy substituting for evidence

**Verdict: absent.**

**What was done.** Copy was scanned where a reader meets it — 50 scenes, both
channels — rather than in the catalogue, because a catalogue entry nobody renders
is not copy and a string assembled from three fragments at render time is not in
the catalogue at all. The announced channel includes `sr-only` text, `title`,
`aria-label` and `alt`, which a sighted scan would miss.

doc 06 §6.1's four banned items, verbatim, and a wider register scan for §8.9's
own example ("You're all set!") which §6.1 does not list:

```
successfully           not found
seamless               not found
trusted by             not found
an exclamation mark    not found
… 11 further register patterns … not found

total occurrences: 0
```

A second pass over all string catalogues, comments stripped, found nothing
either — so this is not copy waiting to appear.

**Falsifiability.** The same patterns over one invented sentence
("You're all set! Everything looks good — your commits were successfully
verified through our seamless pipeline. Trusted by thousands. 🎉 The system is
healthy, so don't worry.") fire 10 of 15 times. The scan can return "present".

What the calm states say instead is quoted in full in the evidence. The healthy
anchoring pulse reads "Ledger segment 4181 anchored 3 min ago"; the verified
panel names the log index; the empty state says what matched nothing.

**Not determinable here:** nothing.

---

## 10. Metrics chosen to look good rather than to inform

**Verdict: present in shape — recorded as a defect, contested.** The two failures
§8.10 names by example are otherwise absent: the pass rate is not hidden, and
nothing is rounded.

**What was done.** Each of the overview's four metric cards was located in the
DOM and classified by the *shape* of its count — windowed, current-state,
cumulative, or not-a-count:

| card | value | shape |
|---|---|---|
| Active agents | 3 | current-state — "runs registered and neither retired nor expired" goes down as well as up |
| Runs today | Not counted | windowed — names its period, and says so when the read failed |
| **Commits attributed** | **4,181** | **cumulative — a lifetime total, no window in any channel** |
| Verification pass rate | Not measured | not-a-count in this build |

The pass-rate card was rendered in all six states it can be in:

```
nothing measured        "Not measured"  amber   — reason stated, link to verify
live, 7 failed          "90% … 7 failed, 3 could not be checked"   RED
live, 7 unavailable     "93% … 0 failed, 7 could not be checked"   amber
live, 100%              "100%"                                     neutral grey
retained from a cache   "Not measured"  amber   — no number stated
live attempt errored    "Not measured"  amber   — no number stated
```

doc 06 §3.1's "below 100% is rendered as a warning state, not a neutral number"
holds, and the warning says *which kind* it is: failures are red, unavailables
amber, and the two counts are always spelled out beside the rate, so a scalar
never collapses §8.2's two states. No state of this card is ever green. The 100%
state is neutral grey — which settles, in the build, the open question ADR-0038's
final consequence left for RM-044.

Rounding, through the real formatters:

```
formatCount(1000000) = "1,000,000"     no abbreviation anywhere
formatRate(4180, 4181) = "99.9%"       a near-miss does not become 100%
formatRate(0, 0) = ""                  no rate is invented from no data
```

Alerts pin above everything on the alerting overview, as §3.1 requires.

**Not determinable here:** whether a metric was *chosen* to flatter is a
judgement about what is absent, and no probe can enumerate the numbers a designer
did not render. What is measured is the two failures §8.10 names by example, plus
the rounding §6.2 forbids.

---

# Defects and findings

## D1 — A green in the shipped production stylesheet (anti-pattern 3)

**Severity:** low. It is dead CSS. **But it is a green outside the verification
family in a shipped artifact, and §8.3 does not have a "dead code" exemption, so
it is recorded as a defect rather than a note.**

`web/dist/assets/index-*.css` contains:

```css
.bg-\[\#00ff00\]{background-color:#0f0}
```

No component uses it: the render walk over 5,940 elements found no element
carrying the class, and no call site exists in code — the only three occurrences
of the literal in `web/src` are inside prose that *explains the rule it breaks*:

```
src/components/common/colour-discipline.test.ts:19: * … so `bg-[#00ff00]` is legal CSS. It is
src/tokens/README.md:70:                            `bg-[#00ff00]` still compiles, deliberately. …
src/tokens/tailwind-theme.css:24:                   * `bg-[#00ff00]`. That is deliberate — …
```

**Cause, demonstrated rather than assumed.** Tailwind v4 detects its own sources
and extracts candidates from every file in the project. `@tailwindcss/oxide`'s
`Scanner` — the component the Vite plugin uses — was run directly:

```
a directory holding one empty file
    file contents:      "\n"
    candidates scanned: []
the same directory, the literal inside a // comment
    file contents:      "// the escape hatch this project keeps on purpose: bg-[#00ff00]\n"
    candidates scanned: ["bg-[#00ff00]","escape","hatch","keeps","on","project","purpose","the","this"]

the real tree, one file at a time:
    web/src/components/common/colour-discipline.test.ts  ->  yields bg-[#00ff00]: YES
    web/src/tokens/README.md                             ->  yields bg-[#00ff00]: YES
    web/src/tokens/tailwind-theme.css                    ->  yields bg-[#00ff00]: no
```

Prose about the rule became CSS. The `.css` file's own comment is not the source
— Tailwind does not scan stylesheets for candidates — the test file and the
README are.

**Where ADR-0038's claim did not hold.** ADR-0038 decision 4 and
`tailwind-theme.css` both say the arbitrary-value syntax "still compiles" as a
deliberate, greppable escape hatch. Measured, it is stronger than that: the
utility is *already compiled and shipped*, so a future component needs only to
reference the class. The hatch is open, not merely unlocked.

**Not fixed** (the issue forbids it). The fix is one of: exclude the two files
from Tailwind's source detection with `@source not`, change the illustrative
literal to something that is not a colour, or accept the dead rule explicitly in
the ADR. The choice belongs to whoever owns `web/src/tokens/`.

## D2 — A cumulative lifetime count with no window (anti-pattern 10)

**Severity:** contested; a specification tension a human must rule on.

"Commits attributed" renders `4,181` — a number that only ever goes up — with no
window stated in the meaning line, on hover, or to assistive technology:

```
Commits attributed 4,181 Commits the ledger holds a commit_recorded event for.
A record, not a verification.
```

doc 06 §8.10 names this shape as its first example of the defect: "cumulative
counts with no window". doc 06 §3.1 asks for the metric by name — "Metric cards:
active agents, runs today, commits attributed, verification pass rate" — and
states no window for it. **The two sentences are in tension and this review does
not resolve a specification against itself.** It is reported as doc 06 requires
conflicts to be reported, not amended.

What is measured, and is not a matter of reading:

- the number is a lifetime total;
- the card states *what* it counts and disclaims what it is not ("A record, not
  a verification"), so it is not a number with no statement of meaning;
- it states no *period*, and the adjacent "Runs today" card shows the same view
  already knows how to render one;
- it is neutral grey and claims nothing.

**Not fixed.** A human doing sign-off should either rule that §3.1's naming of
the metric settles it, or file the window as work.

## F1 — `liveness` is a required prop whose every field is optional (anti-pattern 1)

`VerificationPanel.tsx` states the guarantee as: *"Required, a view that caches
and stays quiet does not compile."* Measured, that holds for an **omitted** prop
and not for an **empty** one. `Liveness.source` is declared optional, so:

```tsx
export const attempt = <VerificationPanel proof={verifiedProof()} liveness={{}} />;
```

**compiles**, and paints:

```
badge reads   "Verified"
painted       color=#116039/#6ccf95 (green/green)
```

Two facts bound how much this matters, and both are measured. Nothing in
`web/src` passes an empty object — every `liveness=` call site is listed in the
evidence. And the two callers that actually hold retained answers narrow the type
so `source` is required: `views/runs/proofs.ts`'s `StatedLiveness` and
`views/overview/types.ts`'s `MeasuredLiveness`. `proofs.ts` already names this
hole in its own file comment. So anti-pattern 1 is **absent from the product**,
and the barrier is one step weaker than the comment claims.

Not refusable by any type, and recorded as such: a caller may write
`liveness={{ source: "live" }}` over a proof it took from a cache. What the
required prop removes is the caller that says *nothing*; what the optional field
lets back in is the caller that says `{}`.

## F2 — `VerificationBadge` is exported and compiles alone (anti-pattern 4)

```tsx
import { VerificationBadge } from "../../src/components/verification";
export const attempt = <VerificationBadge verdict="verified" />;
```

**accepted by the compiler.** A table author who imports it directly gets a green
rollup with nothing behind it — anti-pattern 4 exactly. The package index says so
itself ("which a table should not reach for on its own"). Measured, no view does:
the only importer in `web/src` is `VerificationSummary`. The anti-pattern is
absent from the rendered product; the barrier against it is a comment rather than
a type.

## F3 — ADR-0038's CI caveat is stale

ADR-0038 records as a live consequence: *"The token gate is not wired into CI,
and until it is, it is a script somebody has to remember to run."* Measured:

```
.github/workflows/ci.yml:196:        run: ./web/src/tokens/check-tokens.sh
.github/workflows/ci.yml:201:        run: ./web/src/tokens/check-tokens-selftest.sh
```

Both run in CI. The caveat is superseded and the ADR has not been updated to say
so. No action for this issue; noted so a reader does not act on a stale warning.

## F4 — Two different reasons share one sentence on the pass-rate card

A rate held from a **cache** and a rate whose **live attempt errored** render the
identical sentence: *"The rate in hand was retained from an earlier check rather
than measured now, so it is not shown as a current rate."* The second is not a
retained rate. The **verdict** is correct in both — "Not measured", amber, no
number — so this is neither anti-pattern 1 nor anti-pattern 2. It is a reason
given inaccurately one level below the verdict, against doc 06 §6.1's "say what
was checked and what happened". Recorded as an observation.

---

# Specification conflicts found

1. **doc 06 §3.1 against doc 06 §8.10** — §3.1 names "commits attributed" as a
   required metric card and states no window; §8.10 names "cumulative counts with
   no window" as a defect. See D2. Not resolved here.
2. **doc 06 §4.4 against doc 06 §3.6** — §4.4 says "every affected view" carries
   the staleness marker; §3.6's page reads no ledger and so is arguably not
   affected. The build reads it that way. See section 7. Reported, not amended.

Neither doc was edited. Per `.claude/CLAUDE.md`, a conflict is a question for the
human.

---

# Test-catalog identifiers

**No FE-* id is claimed, and none is needed.** This issue produced no production
code. The probes are review instruments: they live under `reviews/`, are excluded
from `web`'s vitest include glob, and leave the dashboard suite at its 1,459
tests. doc 06 §9's acceptance criteria are the verification, as the issue states
for a deliverable that is documents rather than code.

If a human wants these promoted into doc 07 as standing gates, the range
**FE-100 – FE-110** is proposed, deliberately leaving a gap above FE-090 so it
cannot collide with the ids #57 is taking. Eleven probes map to eleven ids in
file order. **doc 07 was not edited.**

---

# Verification run for this review

```
cd web && npx tsc --noEmit && npx vitest run && npm run build
cd .. && go build ./... && go vet ./... && ./scripts/spdx-check.sh
cd web && npx vitest run --config ../reviews/harness/vitest.config.ts
```

Results are recorded in the commit message. The dashboard suite is unchanged at
1,459 tests; the eleven probes are a separate project.

---

# Measured facts versus assumptions

**Measured** — every number, colour, class name, refusal and quoted string in
this document and in `reviews/evidence/` came from a render, from the built
stylesheet or bundle, or from a command's own output at the working tree named in
each evidence file's header.

**Assumed, and named as such:**

- That the 50 scenes cover the states that would expose these ten defects. They
  were chosen by reading doc 06 §§3, 4 and 8, and they include every view in its
  calm, empty, failed, degraded and alerting states — but a state nobody thought
  to mount was not measured.
- That an element's base-state paint is what a reader sees. Hover and focus
  variants are indexed and deliberately excluded.
- That the green band (hue 65°–175°, saturation ≥ 0.06, chroma ≥ 0.05) is what a
  reader would read as a verdict colour. The band is printed at 10° steps in
  `evidence/00-instrument.txt` so the choice is reviewable rather than implicit.
- That the classification of controls in section 5 against doc 06 P6's four
  permitted actions is correct. The classifier's unmatched controls are printed
  in full rather than waved through, so a human can check the residue.
- That `role="alert"` and `aria-live` are announced as intended. Screen-reader
  behaviour was not tested; only the markup that requests it.
