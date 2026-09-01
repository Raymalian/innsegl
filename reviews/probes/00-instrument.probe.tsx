// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 0 — the instrument, and whether it can say "present".
 *
 * The brief for this review carries a warning drawn from this repository's own
 * history: a test once proved two states differed by stripping `class` and
 * `style` while leaving a `data-*` attribute in place, so the assertion could
 * not fail. Everything below exists so that the same cannot be said of these
 * probes.
 *
 * Three things are measured here and nothing about the product is concluded:
 *
 *   1. The built stylesheet parses, and the parse is complete enough to be
 *      worth reading a verdict out of.
 *   2. The colour instrument returns "green" for a green — on the shipped
 *      sheet, on a hand-built violation, and across the whole band a reader
 *      would read as a verdict. A checker that cannot fail is not evidence.
 *   3. ADR-0038 decision 4 claims Tailwind's default palette does not compile.
 *      That is a structural claim, so it is tested by trying to violate it:
 *      the candidates are fed to the same Tailwind compiler the build uses,
 *      against the product's own theme, and what comes back is recorded.
 */

import { describe, expect, it } from "vitest";
import { compile } from "@tailwindcss/node";

import { Evidence, WEB_DIR } from "../harness/evidence";
import {
  builtStylesheetPath,
  familyOf,
  parseColour,
  parseStylesheet,
  paintOf,
  resolveValue,
  soleClassOf,
} from "../harness/paint";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** The candidates a hurried afternoon would reach for. */
const VIOLATIONS = [
  "bg-green-500",
  "text-green-600",
  "bg-emerald-50",
  "text-emerald-500",
  "text-lime-400",
  "bg-teal-500",
  "text-red-600",
  "bg-amber-400",
  "text-xs",
  "text-9xl",
  "p-13",
  "shadow-2xl",
  "animate-bounce",
  "animate-pulse",
  "dark:text-green-500",
  "bg-[#00ff00]",
  "text-[rgb(0,200,0)]",
  "text-proof-verified",
  "bg-proof-verified-surface",
];

async function compileCandidates(candidates: readonly string[]): Promise<string> {
  const source = `@import "tailwindcss";\n@import "./src/tokens/tailwind-theme.css";\n`;
  const compiler = await compile(source, { base: WEB_DIR, onDependency: () => undefined });
  return compiler.build([...candidates]);
}

describe("probe 0 — the instrument", () => {
  it("records what it measured", async () => {
    const e = new Evidence(
      "00-instrument.txt",
      "Probe 0 — the measuring instrument, and proof that it can return \"present\"",
    );

    e.section("the built stylesheet this review reads");
    e.say(`    path                 ${sheet.path.replace(WEB_DIR, "web")}`);
    e.say(`    rules parsed         ${sheet.rules.length}`);
    e.say(`    :root custom props   ${sheet.rootVariables.size}`);
    e.say(
      `    single-class rules   ${sheet.byClass.size} (base state; pseudo-class and media` +
        ` rules are indexed but never folded in)`,
    );
    const innsegl = [...sheet.rootVariables.keys()].filter((n) => n.startsWith("--innsegl-"));
    e.say(`    --innsegl-* tokens   ${innsegl.length}`);

    e.section("1. the resolver, on the shipped sheet");
    e.say("    Each is a declaration the build emitted, resolved the way a browser");
    e.say("    would: var() chased through :root, light-dark() evaluated per mode.");
    e.say();
    for (const token of [
      "--innsegl-color-proof-verified-text",
      "--innsegl-color-proof-verified-surface",
      "--innsegl-color-proof-failed-text",
      "--innsegl-color-proof-unavailable-text",
      "--innsegl-color-accent-text",
      "--innsegl-color-text-primary",
    ]) {
      const light = resolveValue(sheet, `var(${token})`, "light");
      const dark = resolveValue(sheet, `var(${token})`, "dark");
      const l = parseColour(light);
      const d = parseColour(dark);
      e.say(
        `    ${token.padEnd(42)} light ${light} (${l?.family}, hue ${l?.hue.toFixed(0)}°)  ` +
          `dark ${dark} (${d?.family}, hue ${d?.hue.toFixed(0)}°)`,
      );
    }

    e.section("2. the instrument returns \"green\" for a green");
    e.say("    A checker that cannot fail is not evidence. Three demonstrations.");
    e.say();
    e.say("    (a) the shipped verification palette, classified:");
    for (const step of ["50", "100", "300", "400", "600", "700", "800", "900"]) {
      const name = `--innsegl-palette-verification-${step}`;
      const value = sheet.rootVariables.get(name) ?? "MISSING";
      const c = parseColour(value);
      e.say(
        `        ${name.padEnd(38)} ${value}  hue ${c?.hue.toFixed(0)}°  sat ` +
          `${c?.saturation.toFixed(2)}  -> ${c?.family}`,
      );
    }

    e.say();
    e.say("    (b) a synthetic element painted with a class the build DOES compile,");
    e.say("        run through the same paintOf() the product's elements go through:");
    const violation = await compileCandidates(["bg-[#00ff00]"]);
    const violationSheet = parseStylesheet(writeTemp(violation));
    const el = document.createElement("span");
    el.className = "bg-[#00ff00]";
    const painted = paintOf(violationSheet, el);
    expect(painted).toHaveLength(1);
    for (const p of painted) {
      e.say(
        `        class="${p.className}"  ${p.property}: ${p.declared}  ->  light ` +
          `${p.lightRaw} (${p.light?.family}), dark ${p.darkRaw} (${p.dark?.family})`,
      );
    }
    expect(painted[0]?.light?.family).toBe("green");

    e.say();
    e.say("    (c) the whole band the classifier calls green, at 10° steps, so the");
    e.say("        range is on the record rather than in a comment:");
    const band: string[] = [];
    for (let hue = 0; hue < 360; hue += 10) {
      band.push(`${hue}°:${familyOf(hue, 0.5)}`);
    }
    e.block(band.join("  "));
    e.say();
    e.say(
      `    A desaturated sage (hue 120°, sat 0.08) classifies as ` +
        `${familyOf(120, 0.08)}; a true grey (sat 0.02) as ${familyOf(120, 0.02)}.`,
    );
    expect(familyOf(120, 0.08)).toBe("green");
    expect(familyOf(90, 0.5)).toBe("green");
    expect(familyOf(160, 0.5)).toBe("green");

    e.section("3. ADR-0038 decision 4, tested by trying to violate it");
    e.say("    Each candidate below is fed to @tailwindcss/node — the same compiler");
    e.say("    `npm run build` uses — over web/src/tokens/tailwind-theme.css. What");
    e.say("    is printed is what that compiler emitted for it.");
    e.say();
    const compiled = await compileCandidates(VIOLATIONS);
    const emitted = new Map<string, string>();
    for (const rule of parseStylesheet(writeTemp(compiled)).rules) {
      const sole = soleClassOf(rule.selector);
      if (sole === null) continue;
      const decls = [...rule.declarations]
        .map(([k, v]) => `${k}:${v}`)
        .join("; ");
      emitted.set(sole, decls);
    }
    for (const candidate of VIOLATIONS) {
      const decls = emitted.get(candidate);
      e.say(
        `    ${candidate.padEnd(26)} ${decls === undefined ? "— no CSS emitted" : decls}`,
      );
    }

    e.say();
    e.say("    Read: every Tailwind default colour, size, spacing step, shadow and");
    e.say("    keyframe in the list compiles to nothing. Two things do compile —");
    e.say("    the arbitrary-value syntax, which ADR-0038 keeps deliberately as a");
    e.say("    greppable escape hatch and names this review as its hunter, and the");
    e.say("    token-backed utilities, which resolve to var(--innsegl-…).");

    // The claim, asserted rather than merely printed.
    for (const candidate of VIOLATIONS.filter((c) => !c.startsWith("bg-[") && !c.startsWith("text-[") && !c.startsWith("text-proof") && !c.startsWith("bg-proof"))) {
      expect(emitted.has(candidate), `${candidate} compiled to CSS`).toBe(false);
    }
    expect(emitted.get("bg-[#00ff00]")).toContain("#00ff00");
    expect(emitted.get("text-proof-verified")).toContain(
      "var(--innsegl-color-proof-verified-text)",
    );

    e.write();
  });
});

/* A compiled stylesheet has to reach parseStylesheet, which takes a path. */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let temp: string | null = null;
let n = 0;
function writeTemp(css: string): string {
  temp ??= mkdtempSync(join(tmpdir(), "innsegl-review-"));
  const path = join(temp, `candidate-${n++}.css`);
  writeFileSync(path, css, "utf8");
  return path;
}
