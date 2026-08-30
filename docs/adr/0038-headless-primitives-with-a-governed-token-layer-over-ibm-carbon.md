# ADR-0038: Build on headless primitives with a governed token layer rather than IBM Carbon, ship the tokens as plain CSS, and make doc 06 §5.3's colour rule a build failure

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike

## Context

doc 06 §5.1 poses the question and does not answer it:

> Build on a neutral, token-based open-source foundation rather than a bespoke
> system — the project is open source and adopters will theme it. Recommended:
> headless accessible primitives (e.g., Radix UI) with a Tailwind token layer,
> or IBM Carbon if a fuller enterprise-audit look is preferred out of the box.
> **Decision goes in an ADR before Phase 4 code**; whichever is chosen, all
> colors, spacing, and type flow through design tokens so a downstream
> deployment can rebrand without touching components.

Both options are credible, and a generic comparison of them decides nothing.
Four forces in this project's own documents do.

**1. The rebrand is the stated purpose of the token layer, not a bonus.**
doc 06 §5.1's clause is "so a downstream deployment can rebrand without
touching components", and doc 06 §1 puts a **third-party verifier** third in
the audience list — someone who "trusts nothing about this deployment". The
theming layer therefore has to be reachable by an adopter who did not write the
components and will not fork them.

**2. The public verification page is a single-purpose page with a payload
budget, and it is the adoptability showcase.** doc 06 §7:

> the public verification page stays lightweight enough to load fast from an
> audit context (no heavy framework payloads for a single-purpose page)

and doc 06 §3.6: "it must work as a standalone artifact someone screenshots
into an audit report." That page takes a commit SHA and renders a proof chain.
It is the one view an outsider ever sees.

**3. Accessibility is load-bearing rather than aspirational.** doc 06 §6.4 is
titled "(gating, not aspirational)", doc 06 §7 requires "accessibility checks
(automated axe pass + keyboard-path tests) in CI", and doc 07 already carries
**FE-009** — "axe pass + keyboard-only walkthrough of all six views" — as an
(A) test. So the accessibility of the primitives is a real input, and the
project already owns a compensating control if the primitives supply less of it.

**4. Colour is a governed claim, and the governing rule is the one most likely
to be broken later.** doc 06 §5.3:

> **Green = cryptographic verification passed.** Nothing else is ever green.
> Not "run completed," not "healthy," not positive trends.

doc 06 §8 makes a violation a defect ("3. Green used for anything other than
cryptographic verification"), and doc 07's **FE-013** checks it — from rendered
output, at the end of Phase 4. That is the right place to catch it and the
wrong place to be catching it for the first time.

### What was measured

Nothing below about package size is quoted from memory. Measured 2026-08-30
against the live npm registry, with the version each number belongs to:

| package | version | `dist.unpackedSize` | files | installed |
|---|---|---|---|---|
| `@carbon/react` | 1.115.0 | 5,222,380 B | 1,991 | 10 MB |
| `@carbon/styles` | 1.114.0 | 3,498,208 B | 366 | 4.3 MB |
| `@carbon/themes` | 11.80.0 | — | — | 1.5 MB |
| `@carbon/web-components` | 2.62.0 | 23,369,454 B | 4,808 | — |
| `@radix-ui/react-tooltip` | 1.2.16 | 139,023 B | 9 | 164 KB |
| `@radix-ui/react-dialog` | 1.1.23 | 99,377 B | 9 | — |
| seven Radix primitives together | — | — | — | 2.7 MB |
| `tailwindcss` | 4.3.3 | 772,893 B | 34 | — |

These are **install** sizes, not bundle sizes. Nobody ships an unpacked npm
tree to a browser and this ADR does not claim otherwise; the numbers are here
because the ratio between a per-primitive package and a component suite is
stable under bundling, and because the shape of the dependency is what decision
2 below actually turns on.

The green is not an inference either. Read out of `@carbon/themes@11.80.0`:
`supportSuccess` is `#24a148` in the `white` and `g10` themes and `#42be65` in
`g90` and `g100`. Fourteen references to `$support-success` appear in
`@carbon/styles@1.114.0`'s shipped SCSS, across six components:

```
components/inline-loading/_inline-loading.scss
components/notification/_actionable-notification.scss
components/notification/_inline-notification.scss
components/notification/_toast-notification.scss
components/progress-bar/_progress-bar.scss
components/toggle/_toggle.scss
```

A toggle that is on. A progress bar that finished. A notification that says
something went well. Not one of them is a cryptographic verification.

## Decision

**1. Headless accessible primitives with a Tailwind token layer. Not IBM
Carbon.**

Three reasons decided it, in order of weight.

*The green.* Carbon ships a green named `supportSuccess` and spends it, in its
own stylesheets, on six components whose meaning is "this went well". Adopting
Carbon means adopting doc 06 §8's anti-pattern 3 as a vendor default and then
policing it back out of six component stylesheets, in a theme layer, forever —
and doing it in a system whose token vocabulary tells every contributor that
green means success. The rule doc 06 §5.3 states is not a preference this
project can hold while building on a foundation that disagrees with it. Under
headless primitives there is no vendor stylesheet at all: the colour of every
pixel comes from `web/src/tokens/`, so the rule is enforceable at its source
rather than at each of its consequences.

*The public page.* doc 06 §3.6's page is a form field and a proof chain. Under
this decision it takes **no component library at all** — it is HTML plus
`tokens.css`, no React, no Lit, no framework runtime — and it still looks
identical to the dashboard, because the design language lives in the tokens and
not in the components. Carbon's React suite would put a framework runtime on
that page for a disclosure widget; `@carbon/web-components` would put a custom
element runtime there, and a custom element renders nothing at all until its
JavaScript executes, which is a poor property for a page whose job is to be
screenshotted into an audit report from a locked-down machine. Headless
primitives are per-primitive packages: the dashboard imports the four or five it
needs and the public page imports none, and that is a property of how the
dependency is shaped rather than of how carefully anyone treeshakes.

*The rebrand.* doc 06 §5.1's requirement is that an adopter rebrand without
touching components. Under this decision the entire surface of a rebrand is five
palette ramps at the top of one CSS file, editable by someone who has never
opened the repository's TypeScript and needs no Sass toolchain to compile it.
Carbon is themeable — this is not a claim that it is not — but its themeable
surface is Carbon's token vocabulary, which does not carry this product's
meanings, so we would be maintaining a second semantic layer on top of it and an
adopter would have to understand both.

**2. The token sheet is plain CSS custom properties, not a TypeScript module
and not a Sass theme.**

`web/src/tokens/tokens.css` has no build step and no framework. The public page
imports it directly; the dashboard reaches the same values through
`tailwind-theme.css`. A token sheet expressed in TypeScript would have to be
compiled before the public page could use a colour, which puts a bundler
between an auditor and a hex value for no gain — and the values are static
data, so nothing is lost by expressing them as data.

**3. Both modes are made structural, not tested for.**

Every semantic colour is a `light-dark(light, dark)` over two palette
references, with `color-scheme: light dark` on `:root` and two `[data-theme]`
rules as the manual override doc 06 §5.1 requires. The consequence is the point:
**a token that exists in one mode and not the other is not something a checker
finds, it is something the sheet cannot express.** The obvious alternative —
a light `:root` block and a dark one under `@media (prefers-color-scheme: dark)`
plus `[data-theme="dark"]` — writes every colour three times and makes a missing
dark value a silent, invisible defect until somebody switches themes. This is
the same argument ADR-0037 decision 1 made about resolving a commit range:
remove the step that can be wrong rather than check it afterwards.

It also removes the `dark:` variant from the component layer entirely. A `dark:`
class in a component is a colour decision that escaped the token sheet, and
after this decision there is nothing for one to do.

**4. The palette is named for meaning, and doc 06 §5.3 is enforced in three
places that must each be defeated separately.**

The palette families are `verification`, `failure`, `degraded`, `accent`,
`neutral`. The words "green", "red" and "amber" appear nowhere in the sheet, so
a component author cannot ask for one — the only route to a green is
`--innsegl-color-proof-verified-*`, and spending that on "run completed" is a
visible lie in the diff rather than a plausible-looking token name.

- `web/src/tokens/check-tokens.sh` holds a table mapping each semantic group to
  the one palette family it may draw from. The `verification` family is
  reachable from the `proof-verified` group and from nothing else. Adding a row
  to that table is a decision someone defends in review.
- The same gate refuses a semantic token that is not a `light-dark()` of exactly
  two palette references — which catches both a raw value that escaped the
  palette and a colour that exists in one mode.
- It refuses a token name containing a hue word (`green`, `amber`, …) or a
  claim word (`success`, `healthy`, `positive`, `ok`, `good`, `passed`).
- `tailwind-theme.css` sets `--color-*: initial`, deleting **every** Tailwind
  default colour. Measured against `tailwindcss@4.3.3`: after that line
  `bg-green-500`, `text-red-600` and `bg-emerald-50` generate no CSS, while
  `text-proof-verified` compiles to `color: var(--innsegl-color-proof-verified-text)`.
  The same treatment removes the default type scale, the spacing multiplier, the
  radius scale, every shadow but the one doc 06 §5.4 permits, and every
  keyframe animation — doc 06 §5.5 allows "state transitions and focus movement
  only", and P3 says success is quiet.

What survives is Tailwind's arbitrary-value syntax: `bg-[#00ff00]` still
compiles, verified in the same build. That is deliberate. It is greppable, it
reads in review as exactly what it is, and doc 07's FE-013 and RM-050's
anti-pattern pass (#58) are where it gets hunted. What these decisions remove is
the escape hatch that *looks* like compliance.

**5. Contrast is a committed manifest, asserted in both modes, not a claim in a
comment.**

`web/src/tokens/contrast-pairs.txt` names 32 pairs and the ratio each must
clear; `check-tokens.sh` resolves both `light-dark()` arms of each token and
computes WCAG 2.1 relative luminance. That is 64 assertions, and they pass with
a tightest margin of 3.19:1 against a 3.0 floor. doc 06 §6.4 asks for "WCAG 2.1
AA contrast in both modes, including semantic colors on their backgrounds"; a
palette nobody measured in dark mode satisfies half of that sentence and reads
as satisfying all of it.

**6. The accent is indigo, and it is outside the verdict band.**

doc 06 §5.3 wants "one accent color … semantically meaningless, and never one of
the three semantic hues above". The rule this ADR adds is stronger than "not
green, red or amber": the accent must sit **outside the red–amber–green band a
reader scans for a verdict**. A teal or a lime accent satisfies the literal
requirement and sits at the edge of the verification hue, which is exactly the
misreading §5.3 exists to prevent in a product where colour is a claim. Indigo
is not adjacent to any of the three.

**7. No webfont.**

Both families in doc 06 §5.2 resolve to what the reader's operating system
already has. doc 06 §7 asks the public page to load fast from an audit context,
and doc 06 §3.6 wants it to work as a standalone artifact; a page whose job is
to render a hash for someone who trusts nothing should not fetch a font from a
third party to do it. This also removes a request that a locked-down or offline
audit machine would fail, and IBM Plex — which Carbon assumes — would have been
that request.

## Alternatives considered

- **IBM Carbon (`@carbon/react`).** The strongest alternative, and it loses on
  the green. Carbon's shipped SCSS spends `$support-success` (`#24a148`) on a
  toggle that is on, a progress bar that finished, and four notification
  variants — six components' worth of doc 06 §8 anti-pattern 3 arriving as a
  vendor default, in a token vocabulary that teaches every contributor that
  green means success. Removing it is not a one-line theme override; it is a
  standing obligation against a dependency that is updated by someone else. The
  secondary reasons are the public page (a component runtime on a page doc 06
  §7 budgets for none) and the double semantic layer a rebrand would have to
  understand. Carbon's genuine advantage — a fuller enterprise-audit look with
  no design work — is real and is not worth a foundation that disagrees with the
  product's central rule about colour.

- **`@carbon/web-components` instead of the React suite, to keep the public
  page framework-free.** Rejected on a worse version of the same problem. A
  custom element renders *nothing* until its JavaScript executes, so the public
  verification page's proof chain would be blank in any context that blocks or
  fails to run the module — which is a real context for a page doc 06 §3.6
  expects to be screenshotted into an audit report. The package is also the
  largest of the candidates measured (23.4 MB unpacked, 4,808 files at 2.62.0).

- **Carbon's design language with our own tokens layered on top.** The
  compromise, and rejected because it is the worst of both: two token
  vocabularies to keep in agreement, an adopter who must learn Carbon's before
  reaching ours, and `$support-success` still sitting under six components
  waiting for a theme override to be forgotten.

- **A component suite with the styling already made — MUI, Chakra, or a shadcn
  copy-in.** Rejected for one reason each. MUI and Chakra own their colour
  systems the way Carbon does, so they inherit Carbon's disqualifying problem
  without Carbon's audit-console credibility. shadcn is not a dependency but a
  copy of components into the repository — which is attractive here and is the
  wrong shape for Phase 4's start: it would land ~30 components' worth of code
  the project has not decided it needs, each of which then has to be brought
  into the token rules by hand. It remains a reasonable source to copy an
  individual component from later, over these tokens.

- **Build the primitives ourselves and depend on nothing.** Rejected on
  doc 06 §6.4. A keyboard-operable, screen-reader-correct popover, listbox and
  disclosure is the part of a UI that is hardest to get right and easiest to get
  subtly wrong, and this project has no accessibility specialist. doc 06 §5.1
  also says the foundation should not be bespoke, in as many words.

- **Hue-named palette primitives (`--innsegl-palette-green-600`), the
  conventional layering.** Rejected, and this is a deliberate departure from
  normal practice. The usual argument for hue-named primitives is that they are
  meaning-free and therefore reusable. Here that is precisely the defect: a
  primitive named `green` is an invitation to reach past the semantic layer, and
  §5.3 exists to make that impossible to do accidentally. The cost is real —
  the ramps are no longer reusable across meanings, and a designer who wants
  "some green somewhere else" has nowhere to get one. That is the intended
  outcome.

- **Two mode blocks (`:root` light, `@media (prefers-color-scheme: dark)` plus
  `[data-theme="dark"]`) with a name-parity checker.** The conventional design,
  and the one this ADR was expected to produce. Rejected because it writes every
  colour three times, and a parity checker verifies that both blocks name the
  same tokens without verifying that the values are the ones intended — the
  copy-paste error where a dark token was updated and its light twin was not
  passes parity cleanly. `light-dark()` removes the class of bug rather than
  detecting it. The exit cost of being wrong about this is bounded and stated
  in Consequences.

- **A TypeScript token module (`tokens.ts`) generating CSS at build time.**
  Rejected on doc 06 §3.6 and on IP §2. It puts a bundler between the public
  page and a colour value, and it converts a declarative sheet into code — code
  that would then need tests observed failing first, for a module whose entire
  content is static data. The Tailwind bridge already gives the dashboard typed
  autocompletion over the same names.

- **Keep Tailwind's default palette and forbid it with an ESLint rule.**
  Rejected: a lint rule is a second copy of doc 06 §5.3 that drifts from the
  first, it is disableable per line, and it does not exist until someone
  configures it. `--color-*: initial` makes `bg-green-500` compile to nothing,
  which needs no configuration and cannot be silenced.

- **Assert contrast in a table in the README rather than in a gate.** Rejected
  for the reason ADR-0037 rejected a warning annotation: a measured number
  written into prose is correct on the day it is written and unfalsifiable
  afterwards. The manifest is read by the same script that computes the ratios,
  so the two cannot disagree.

- **APCA rather than WCAG 2.1 relative luminance.** APCA is the better model of
  perceived contrast and is not what doc 06 §6.4 asks for. The spec names WCAG
  2.1 AA; changing the standard a spec cites is a question for the human, not an
  improvement to make quietly.

## Consequences

- **Composition-level accessibility is now this project's own work, and that is
  the price of decision 1.** Headless primitives supply the ARIA patterns;
  nobody supplies the correctness of how they are assembled into a three-check
  panel with per-check status announced (doc 06 §6.4). Carbon would have
  supplied more of that. The compensating control already exists and is not
  being invented here — doc 07's **FE-009** is an (A) test requiring an axe pass
  and a keyboard-only walkthrough of all six views, and doc 06 §7 puts both in
  CI. This ADR makes that test load-bearing rather than confirmatory, and
  RM-049 (#57) is where it is written.

- **Carbon's accessibility was not measured, and this ADR does not claim it is
  worse.** IBM's accessibility work on Carbon is well regarded and nothing here
  tested it. The decision is not "Carbon is less accessible"; it is that
  Carbon's colour semantics conflict with doc 06 §5.3 in a way no amount of
  accessibility quality compensates for.

- **Bundle sizes were not measured, install sizes were.** The table in Context
  says which. A claim about the public page's shipped weight belongs to the
  performance work in doc 06 §7 and can only be made against a real build,
  which does not exist yet.

- **`light-dark()` is load-bearing, and a browser without it renders no colour
  rather than a fallback colour.** It has been Baseline since May 2024. If a
  deployment must support something older, the fix is mechanical and confined to
  one file: expand each `light-dark(a, b)` into a light `:root` block and a dark
  block under `@media (prefers-color-scheme: dark)` plus `[data-theme="dark"]`,
  and extend `check-tokens.sh` with the name-parity check that decision 3 made
  unnecessary. **Exit cost: one file, one afternoon, no component changes** —
  which is the property that made the risk acceptable.

- **`web/package.json` was not created.** Nothing in this issue needs one: the
  token sheet is CSS, the gate is `bash` and `awk`, and the Tailwind bridge was
  validated against a Tailwind install outside the repository. The first
  `package.json` belongs to RM-041 (#49), which is where a build actually
  begins, and the epic's shared-write note about the lockfile applies from
  there.

- **The token gate is not wired into CI, and until it is, it is a script
  somebody has to remember to run.** `.github/workflows/` and `scripts/` were
  not RM-039's to change. The wiring is two lines — `web/src/tokens/check-tokens.sh`
  and `web/src/tokens/check-tokens-selftest.sh` in a job that needs no Go, no
  Docker and no Node — and it belongs with whoever next owns `.github/`. Until
  then doc 06 §5.3 is enforced by the naming and by `--color-*: initial`, both
  of which hold without CI, and the contrast floor is enforced by nothing
  automatic.

- **The gate reads CSS with `awk`, not with a CSS parser.** It understands the
  shapes this sheet is written in: one declaration per line, `light-dark()` over
  `var()` over `#rrggbb`. `color-mix()`, `oklch()` and a multi-line declaration
  would each need it extended, and it fails closed on anything it cannot
  resolve rather than skipping it.

- **doc 07 has no ID for the token layer's half of the colour rule.** FE-013 is
  "scan rendered views for green tokens", which is the right check at the end of
  Phase 4 and is measured from rendered output; it cannot run until there are
  views. The structural half — that the sheet cannot express a green outside
  `proof-verified`, and that every declared contrast pair holds in both modes —
  runs today, on every commit, with no browser. Proposed **FE-014** (U), and
  the ten-case self-test that proves the gate still bites is proposed
  **FE-015** (U). Both are written and green; neither is numbered, because
  RM-039 does not edit doc 07.

- **One question for the human, and it is about a metric rather than a
  component.** doc 06 §3.1 puts "verification pass rate" on the overview and
  says "Pass rate below 100% is rendered as a warning state, not a neutral
  number". It does not say what a pass rate *at* 100% is. Read one way it is an
  aggregate of cryptographic verifications and may be green under §5.3; read the
  other it is a metric about the fleet, which §5.3 assigns to neutral grey, and
  a green number that means "nothing has failed lately" is close to the
  "positive trends" §5.3 names. The tokens permit either — `proof-verified` for
  the first reading, `text-primary` for the second — and RM-044 (#52) will have
  to pick one. The narrower reading (neutral at 100%, `degraded` below it) is
  the safer default and is not what this ADR decides.

- **A hairline border is deliberately absent from the contrast manifest.**
  doc 06 §5.4 asks for hairline borders for structure; WCAG 1.4.11's 3:1 applies
  to what identifies a component or its state, not to decorative separation, and
  a 1px rule that clears 3:1 is not a hairline. `--innsegl-color-border-hairline`
  therefore carries no information anywhere it is used, and any border that
  *does* carry information — the expired-status outline, the three verification
  badge outlines, `border-strong` — is in the manifest at 3:1. If a later
  component uses the hairline to mean something, that component has a defect and
  the manifest is where the argument gets settled.

- **`check-tokens.sh` and its self-test live under `web/src/tokens/`, which
  reads like source and is not.** They are gates. `scripts/` is where this
  repository keeps its other seven, and RM-039 owns no path there. This is the
  same scope artefact ADR-0031 recorded for `sigstore-testscope.yml` and
  ADR-0037 for `author-policy.json`; moving them to `scripts/` is a rename for
  whoever owns that directory, and doing it costs nothing because the gate takes
  its sheet as an argument.

- **What becomes irreversible.** Very little. The tokens are consumed by
  components that do not exist yet, so the naming can still change cheaply
  today and cannot in six views' time. The genuinely one-way door is decision 1:
  once six views are built on headless primitives, moving to Carbon is a rewrite
  of every component, not a dependency swap. The reverse — Carbon to headless —
  would have been the same. That is why doc 06 §5.1 asked for the decision
  before Phase 4 code rather than during it.
