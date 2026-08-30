# Design tokens

The token sheet doc 06 §9 asks for, and the gate that keeps it honest.
Decided in [ADR-0038](../../../docs/adr/0038-headless-primitives-with-a-governed-token-layer-over-ibm-carbon.md).

| file | what it is |
|---|---|
| `tokens.css` | the single source of truth. Plain CSS custom properties, no build step, no framework. |
| `tailwind-theme.css` | the dashboard's Tailwind bridge. Exposes the tokens as utilities and **deletes** Tailwind's default scales. |
| `contrast-pairs.txt` | the colour pairs that must clear WCAG 2.1 AA, in both modes. Declarative. |
| `check-tokens.sh` | the gate. Layering, resolution, colour semantics, naming, theme mechanics, contrast. |
| `check-tokens-selftest.sh` | plants ten defects and asserts the gate refuses each one. A gate nobody has watched fail is not a gate. |

## Using them

**The dashboard** imports the bridge, and gets tokens as Tailwind utilities:

```css
@import "tailwindcss";
@import "./src/tokens/tailwind-theme.css";  /* pulls in tokens.css */
```

```html
<span class="text-proof-verified bg-proof-verified-surface border-proof-verified-line">
```

**The public verification page** (doc 06 §3.6) imports `tokens.css` alone and
uses the properties directly. It carries no framework and no webfont, which is
doc 06 §7's performance budget taken literally — "no heavy framework payloads
for a single-purpose page":

```css
@import "./src/tokens/tokens.css";
.verdict-pass { color: var(--innsegl-color-proof-verified-text); }
```

## The two layers

```
--innsegl-palette-<family>-<step>   raw values. Only the semantic layer may name these.
--innsegl-color-<group>-<role>      what components use. Always light-dark(light, dark).
```

Families are named for **meaning**, not hue: `verification`, `failure`,
`degraded`, `accent`, `neutral`. The words "green", "red" and "amber" appear
nowhere in the sheet, so a component author cannot ask for one.

## The colour rule, and why it is a gate

doc 06 §5.3:

> **Green = cryptographic verification passed.** Nothing else is ever green.
> Not "run completed," not "healthy," not positive trends.

doc 06 §8 makes a violation a defect. The rule survives review; what it does not
survive is a hurried afternoon six months from now. So it is enforced in three
places at once, and each one has to be defeated separately:

1. **The names.** There is no `--innsegl-color-success-*`. The only route to a
   green is `--innsegl-color-proof-verified-*`, and using that token for "run
   completed" is a visible lie in the diff.
2. **The gate.** `check-tokens.sh` holds a table of which semantic group may
   draw from which palette family. The `verification` family is reachable from
   the `proof-verified` group and nothing else. Adding a row to that table is a
   design decision someone has to defend in review.
3. **The build.** `tailwind-theme.css` sets `--color-*: initial`, which removes
   every one of Tailwind's built-in colours. `bg-green-500` does not compile.

The remaining escape hatch is Tailwind's arbitrary-value syntax —
`bg-[#00ff00]` still compiles, deliberately. It is greppable and it looks
exactly like what it is. RM-050's anti-pattern pass (#58) is where it gets
hunted; the point of the three layers above is to remove the escape hatch that
looks like compliance.

## Both modes, by construction

Every semantic colour is a `light-dark(light, dark)`. A token that exists in one
mode and not the other is not something the gate catches — it is something the
sheet cannot express. `color-scheme` on `:root` does the switching:

```css
:root                     { color-scheme: light dark; }  /* follow the OS */
:root[data-theme="light"] { color-scheme: light; }       /* manual override */
:root[data-theme="dark"]  { color-scheme: dark; }
```

The tokens involve no JavaScript. The app shell (RM-041, #49) owns setting and
persisting `data-theme` on `<html>`; removing the attribute returns the page to
`prefers-color-scheme`. No component needs a `dark:` variant, and none should
have one — a `dark:` variant in a component is a colour decision that escaped
this file.

## Running the gate

```bash
web/src/tokens/check-tokens.sh            # 32 contrast pairs x 2 modes, plus the structural rules
web/src/tokens/check-tokens-selftest.sh   # prove the gate still bites
```

Neither is wired into CI yet: `.github/workflows/` and `scripts/` were not
RM-039's to change. Wiring them is named as a follow-up in ADR-0038.

## Rebranding

doc 06 §5.1's reason for this layer is that "a downstream deployment can rebrand
without touching components". The whole surface of that is the five palette
ramps at the top of `tokens.css`. Change the hex values, run `check-tokens.sh`,
and fix whatever contrast it reports. Nothing below the palette needs editing,
and no component does.

What a rebrand may **not** do is repoint a semantic group at a different family
— make the accent green, say, or the alert amber. The gate refuses it, and the
refusal cites doc 06 §5.3. That is not a limitation of the theming system; it is
the product's claim about what colour means, and a deployment that changes it is
shipping a different claim under the same name.

## Known limits

- `light-dark()` is the load-bearing CSS feature here. It has been Baseline
  since May 2024, but a browser without it renders **no** colour rather than a
  fallback colour. If a deployment has to support one, the fix is a mechanical
  expansion of this one file into two `@media`/`[data-theme]` blocks, and the
  parity property that is currently structural becomes something the gate has
  to check instead. ADR-0038 records the exit cost.
- The gate reads CSS with `awk`, not with a CSS parser. It understands the
  shapes this sheet is written in — one declaration per line, `light-dark()`
  over `var()` over hex — and would need extending before it understood
  `color-mix()`, `oklch()` or a multi-line declaration.
- Contrast is measured against WCAG 2.1 relative luminance, which is the
  standard doc 06 §6.4 names. It is a known-imperfect model of perceived
  contrast; APCA is better and is not what the spec asks for.
