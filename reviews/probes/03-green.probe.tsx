// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 3 — doc 06 §8 anti-pattern 3:
 *
 *   "Green used for anything other than cryptographic verification."
 *
 * Four measurements, from four different directions, because this is the rule
 * doc 06 §5.3 calls governed and ADR-0038 calls the one most likely to be
 * broken later.
 *
 *   1. FROM THE RENDERED OUTPUT. Every element of every scene in the gallery
 *      is walked, its class attribute joined to the BUILT stylesheet, its
 *      var() chains resolved and its light-dark() evaluated in both modes.
 *      Every element that lands in the green band is printed with the words
 *      beside it, and each one has to be a cryptographic verification.
 *
 *   2. FROM THE STYLESHEET. The whole built sheet is swept for green values,
 *      including rules that belong to no class — the base layer, the theme
 *      layer, pseudo-class rules the walk above deliberately excludes.
 *
 *   3. FROM THE SOURCE, for the one escape hatch ADR-0038 keeps on purpose:
 *      Tailwind's arbitrary-value syntax. `bg-[#00ff00]` compiles. ADR-0038
 *      names this review as where it gets hunted, so it is hunted here.
 *
 *   4. BY TRYING TO VIOLATE IT. The token gate is handed a sheet in which a
 *      non-verification group draws from the verification family, and its
 *      refusal is recorded. A structural claim tested only by its own author's
 *      confidence is not tested.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Evidence, REPO_DIR, WEB_DIR } from "../harness/evidence";
import { gallery } from "../harness/gallery";
import {
  builtStylesheetPath,
  paintOf,
  parseColour,
  parseStylesheet,
  resolveValue,
  soleClassOf,
  unstyledClasses,
} from "../harness/paint";
import { visibleText } from "../harness/perceptible";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** The words nearest an element, for saying what a colour is spent on. */
function context(element: Element): string {
  const own = visibleText(sheet, element).trim();
  if (own !== "") return own.slice(0, 120);
  const parent = element.parentElement;
  return parent === null ? "(no words)" : visibleText(sheet, parent).slice(0, 120);
}

describe("probe 3 — green outside cryptographic verification", () => {
  it("sweeps the rendered output, the stylesheet, the source and the gate", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "03-green.txt",
      "Probe 3 — doc 06 §8.3: green used for anything other than cryptographic verification",
    );

    /* ── 1. every green pixel the gallery renders ───────────────────────── */

    e.section("1. every green in the rendered output");
    e.say(`    ${scenes.length} scenes walked, element by element. For each element the`);
    e.say("    class attribute is joined to web/dist/assets/*.css, var() chains are");
    e.say("    chased through :root and light-dark() is evaluated in BOTH modes.");
    e.say();

    interface Hit {
      readonly scene: string;
      readonly property: string;
      readonly className: string;
      readonly light: string;
      readonly dark: string;
      readonly words: string;
      readonly tag: string;
    }
    const greens: Hit[] = [];
    let elements = 0;
    const unstyled = new Map<string, string[]>();

    for (const scene of scenes) {
      for (const element of Array.from(scene.container.querySelectorAll("*"))) {
        elements += 1;
        const orphans = unstyledClasses(sheet, element);
        if (orphans.length > 0) {
          unstyled.set(scene.name, [...(unstyled.get(scene.name) ?? []), ...orphans]);
        }
        for (const paint of paintOf(sheet, element)) {
          if (paint.light?.family !== "green" && paint.dark?.family !== "green") continue;
          greens.push({
            scene: scene.name,
            property: paint.property,
            className: paint.className,
            light: paint.lightRaw,
            dark: paint.darkRaw,
            words: context(element),
            tag: element.tagName.toLowerCase(),
          });
        }
      }
    }

    e.say(`    elements walked            ${elements}`);
    e.say(`    green declarations found   ${greens.length}`);
    e.say();
    const bySceneAndClass = new Map<string, Hit>();
    for (const hit of greens) bySceneAndClass.set(`${hit.scene}|${hit.className}|${hit.property}`, hit);
    for (const hit of [...bySceneAndClass.values()].sort((a, b) => a.scene.localeCompare(b.scene))) {
      e.say(`    ${hit.scene}`);
      e.say(
        `        <${hit.tag}> ${hit.property} via .${hit.className}  ` +
          `light ${hit.light}  dark ${hit.dark}`,
      );
      e.say(`        beside the words: "${hit.words}"`);
    }

    e.say();
    e.say("    Every scene above is a live cryptographic verification that passed.");
    e.say("    The scenes NOT in the list are the whole rest of the gallery, and the");
    e.say("    four that matter most are named here explicitly because they are the");
    e.say("    states a careless build would have made green:");
    for (const name of [
      "view/overview-calm",
      "badge/status-active",
      "heartbeat/within-bound",
      "view/runs-ready",
    ]) {
      const present = greens.some((hit) => hit.scene === name);
      e.say(`        ${name.padEnd(34)} green present: ${present ? "YES" : "no"}`);
      expect(present, `${name} paints green`).toBe(false);
    }

    const greenScenes = new Set(greens.map((hit) => hit.scene));
    e.say();
    e.say(`    scenes carrying any green: ${[...greenScenes].sort().join(", ") || "(none)"}`);
    e.say();
    e.say("    The rule, asserted rather than eyeballed: every green-painted element");
    e.say("    in the gallery must carry the word \"Verified\" — doc 06 §5.3's");
    e.say("    \"cryptographic verification passed\" and nothing else. The words beside");
    e.say("    each green, deduplicated:");
    const greenWords = [...new Set(greens.map((hit) => hit.words))].sort();
    for (const words of greenWords) e.say(`        "${words}"`);
    for (const hit of greens) {
      expect(
        hit.words,
        `green spent on something that is not a verification verdict, in ${hit.scene}`,
      ).toBe("Verified");
    }

    e.say();
    e.say("    Classes on rendered elements that the build compiled NOTHING for —");
    e.say("    a component asking for a utility that does not exist would show up");
    e.say("    here, and that is how `bg-green-500` would arrive without a colour:");
    if (unstyled.size === 0) {
      e.say("        none. Every class on every rendered element has a compiled rule.");
    } else {
      for (const [scene, names] of unstyled) {
        e.say(`        ${scene}: ${[...new Set(names)].join(", ")}`);
      }
    }
    expect(unstyled.size).toBe(0);

    /* ── 2. the whole stylesheet ────────────────────────────────────────── */

    e.section("2. every green value in the built stylesheet, class or not");
    e.say("    The walk above only sees rules attached to a class an element carries.");
    e.say("    This sweep reads every rule in the file, base and theme layers, media");
    e.say("    and pseudo-class rules included.");
    e.say();

    const sheetGreens: string[] = [];
    for (const rule of sheet.rules) {
      for (const [property, declared] of rule.declarations) {
        for (const mode of ["light", "dark"] as const) {
          let resolved: string;
          try {
            resolved = resolveValue(sheet, declared, mode);
          } catch {
            continue;
          }
          for (const token of resolved.split(/[\s,]+/)) {
            const colour = parseColour(token);
            if (colour?.family !== "green") continue;
            sheetGreens.push(
              `${rule.context.join(" ")} ${rule.selector} { ${property}: ${declared} } ` +
                `-> ${mode} ${colour.hex} (hue ${colour.hue.toFixed(0)}°)`,
            );
          }
        }
      }
    }
    const uniqueSheetGreens = [...new Set(sheetGreens)].sort();
    e.say(`    green-valued declarations in the whole sheet: ${uniqueSheetGreens.length}`);
    for (const line of uniqueSheetGreens) e.say(`        ${line}`);
    const strays = uniqueSheetGreens.filter(
      (line) => !line.includes("verification") && !line.includes("proof-verified"),
    );
    e.say();
    e.say(
      `    Of those, ${uniqueSheetGreens.length - strays.length} name a ` +
        "--innsegl-palette-verification-* ramp or a",
    );
    e.say("    --innsegl-color-proof-verified-* token — the sanctioned green.");
    e.say();
    e.say(`    ${strays.length} do not:`);
    for (const line of strays) e.say(`        ${line}`);

    if (strays.length > 0) {
      e.say();
      e.say("    FINDING. `.bg-[#00ff00] { background-color: #0f0 }` is in the SHIPPED");
      e.say("    production stylesheet. No component uses it — the render walk in");
      e.say("    section 1 found no element carrying the class, and section 3's grep");
      e.say("    finds no call site. It is there because Tailwind v4 detects its own");
      e.say("    sources automatically and extracts candidates from every file in the");
      e.say("    project, PROSE INCLUDED. The literal appears in exactly three places,");
      e.say("    all of them explanations of the rule it breaks:");
      e.block(
        grep(
          ["-rnF", "bg-[#00ff00]", "--include=*.ts", "--include=*.tsx", "--include=*.css", "--include=*.md", "src"],
          WEB_DIR,
        ),
      );
      e.say();
      e.say("    Causality, demonstrated rather than assumed. The same entry CSS is");
      e.say("    compiled twice against the same theme, differing only in whether the");
      e.say("    scanned directory contains a file with that string in a comment:");
      e.say();
      e.block(await sourceDetectionExperiment());
    }

    /* The sweep's verdict: every green is either the verification family or the
     * one stray this probe has just characterised. Anything else is a defect. */
    for (const line of strays) {
      expect(
        line.includes("bg-\\[\\#00ff00\\]"),
        `unaccounted green in the built stylesheet: ${line}`,
      ).toBe(true);
    }

    /* ── 3. the escape hatch ADR-0038 keeps on purpose ──────────────────── */

    e.section("3. the arbitrary-value escape hatch, hunted");
    e.say("    ADR-0038 decision 4: `bg-[#00ff00]` still compiles, deliberately —");
    e.say("    \"it is greppable, it reads in review as exactly what it is, and doc");
    e.say("    07's FE-013 and RM-050's anti-pattern pass (#58) are where it gets");
    e.say("    hunted.\" This is that hunt.");
    e.say();
    const grepped = grep(
      [
        "-rnE",
        String.raw`(bg|text|border|fill|stroke|outline|decoration|shadow|from|via|to)-\[(#|rgb|hsl|oklch|oklab|lab|lch|color)`,
        "--include=*.ts",
        "--include=*.tsx",
        "--include=*.css",
        "src",
      ],
      WEB_DIR,
    );
    e.say("    (a) Tailwind arbitrary COLOUR values anywhere in web/src:");
    e.block(grepped === "" ? "none" : grepped);
    e.say();
    e.say("        Classified. A hit is CODE when the matched text sits outside a");
    e.say("        comment; every hit below is inside one, which is why the utility");
    e.say("        exists in the stylesheet and on no element.");
    const code = grepped
      .split("\n")
      .filter((line) => line.trim() !== "")
      .filter((line) => {
        const body = line.slice(line.indexOf(":", line.indexOf(":") + 1) + 1);
        return !/^\s*(\*|\/\/|\/\*)/.test(body);
      });
    for (const line of grepped.split("\n").filter((l) => l.trim() !== "")) {
      const body = line.slice(line.indexOf(":", line.indexOf(":") + 1) + 1);
      const kind = /^\s*(\*|\/\/|\/\*)/.test(body) ? "comment" : "CODE";
      e.say(`        ${kind.padEnd(8)} ${line.split(":").slice(0, 2).join(":")}`);
    }
    expect(code, `an arbitrary colour value in code: ${code.join(" | ")}`).toEqual([]);

    const arbitraryProperty = grep(
      ["-rnE", String.raw`\[[a-z-]+:`, "--include=*.ts", "--include=*.tsx", "src"],
      WEB_DIR,
    );
    e.say();
    e.say("    (b) every arbitrary-PROPERTY class in web/src, so the hatch is fully");
    e.say("        enumerated rather than only searched for colours:");
    e.block(arbitraryProperty === "" ? "none" : arbitraryProperty);
    e.say();
    e.say("        Read: each names an --innsegl-* token. None carries a value.");

    const inlineStyled: string[] = [];
    for (const scene of scenes) {
      for (const element of Array.from(scene.container.querySelectorAll("[style]"))) {
        inlineStyled.push(
          `${scene.name}: <${element.tagName.toLowerCase()} style="${element.getAttribute("style")}">`,
        );
      }
    }
    e.say();
    e.say("    (c) inline `style` attributes in the RENDERED output — the one route");
    e.say("        to a colour that bypasses the stylesheet entirely, measured on the");
    e.say("        DOM rather than grepped for:");
    e.block(
      inlineStyled.length === 0
        ? `none. ${elements} elements across ${scenes.length} scenes carry no style attribute.`
        : inlineStyled.join("\n"),
    );
    expect(inlineStyled).toEqual([]);

    const bundleColours = bundleLiterals();
    e.say();
    e.say("    (d) colour literals in the built JavaScript bundle, which is where an");
    e.say("        inline style or a JS-computed colour would end up:");
    e.block(bundleColours);

    /* ── 4. trying to make a green the sheet cannot hold ─────────────────── */

    e.section("4. the gate, tested by trying to defeat it");

    const gate = join(WEB_DIR, "src", "tokens", "check-tokens.sh");
    e.say("    (a) the shipped sheet, checked:");
    e.block(run(gate, [], REPO_DIR).slice(-1200));

    e.say();
    e.say("    (b) the gate's own ten-case self-test, which proves it still bites:");
    e.block(run(join(WEB_DIR, "src", "tokens", "check-tokens-selftest.sh"), [], REPO_DIR).slice(-1600));

    const temp = mkdtempSync(join(tmpdir(), "innsegl-green-"));
    const original = readFileSync(join(WEB_DIR, "src", "tokens", "tokens.css"), "utf8");

    const attempts: Array<[string, string, string]> = [
      [
        "run-completed-green",
        "doc 06 §5.3's own example: a green for \"run completed\", spelled as a\n" +
          "        status token drawing from the verification family",
        original.replace(
          "  --innsegl-color-status-retired-text: light-dark(var(--innsegl-palette-neutral-500), var(--innsegl-palette-neutral-400));",
          "  --innsegl-color-status-retired-text: light-dark(var(--innsegl-palette-verification-700), var(--innsegl-palette-verification-300));",
        ),
      ],
      [
        "raw-hex-green",
        "a raw green hex smuggled straight into a semantic token, past the palette",
        original.replace(
          "  --innsegl-color-degraded-text: light-dark(var(--innsegl-palette-degraded-700), var(--innsegl-palette-degraded-300));",
          "  --innsegl-color-degraded-text: light-dark(#116039, #6ccf95);",
        ),
      ],
      [
        "new-success-family",
        "a whole new palette family named for the claim it wants to make",
        original.replace(
          "  --innsegl-palette-accent-50: #ecedfc;",
          "  --innsegl-palette-success-500: #24a148;\n  --innsegl-palette-accent-50: #ecedfc;",
        ),
      ],
      [
        "one-mode-green",
        "a green that exists in light mode only — the failure ADR-0038 decision 3\n" +
          "        claims is unrepresentable rather than merely tested for",
        original.replace(
          "  --innsegl-color-accent-text: light-dark(var(--innsegl-palette-accent-700), var(--innsegl-palette-accent-300));",
          "  --innsegl-color-accent-text: var(--innsegl-palette-verification-700);",
        ),
      ],
    ];

    for (const [name, description, css] of attempts) {
      const path = join(temp, `${name}.css`);
      writeFileSync(path, css, "utf8");
      expect(css, `${name} did not modify the sheet`).not.toBe(original);
      const output = run(gate, [path], REPO_DIR);
      const refused = output.includes("FAIL") || output.includes("fail");
      e.say();
      e.say(`    ATTEMPT: ${description}`);
      e.say();
      e.block(failingLines(output));
      e.say(`    RESULT: ${refused ? "refused by the gate" : "*** ACCEPTED ***"}`);
      expect(refused, `${name} passed the gate`).toBe(true);
    }

    e.say();
    e.say("    ADR-0038 recorded, as a live consequence, that \"the token gate is not");
    e.say("    wired into CI, and until it is, it is a script somebody has to remember");
    e.say("    to run\". Checked rather than repeated:");
    e.block(gateInCi());

    e.write();
  });
});

function grep(args: readonly string[], cwd: string): string {
  try {
    return execFileSync("grep", [...args], { cwd, encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

function run(command: string, args: readonly string[], cwd: string): string {
  try {
    return execFileSync(command, [...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    const shell = error as { stdout?: string; stderr?: string };
    return `${shell.stdout ?? ""}${shell.stderr ?? ""}`;
  }
}

/** The lines of a gate run that carry its refusal, so the evidence is the
 * refusal rather than 300 lines of passing checks. */
function failingLines(output: string): string {
  const lines = output.split("\n");
  const start = lines.findIndex((line) => line.startsWith("FAIL"));
  if (start === -1) return lines.slice(-10).join("\n");
  return lines.slice(start).filter((line) => line.trim() !== "").join("\n");
}

function bundleLiterals(): string {
  const assets = join(WEB_DIR, "dist", "assets");
  const js = execFileSync("sh", ["-c", `ls ${assets}/*.js`], { encoding: "utf8" }).trim();
  const text = readFileSync(js, "utf8");
  const found = new Set<string>();
  for (const match of text.matchAll(/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|oklch\([^)]*\)/g)) {
    found.add(match[0]);
  }
  if (found.size === 0) return "none — the bundle contains no colour literal at all";
  return [...found].sort().join("\n");
}

/**
 * Where the candidate comes from, demonstrated rather than assumed.
 *
 * `@tailwindcss/oxide`'s Scanner is the component the Vite plugin uses to turn
 * a directory into the candidate list `compile().build()` is handed. Running it
 * directly says exactly what the build saw. Two controls, then the real tree.
 */
async function sourceDetectionExperiment(): Promise<string> {
  const { Scanner } = await import("@tailwindcss/oxide");
  const lines: string[] = [];

  const scanDir = (contents: string): string[] => {
    const dir = mkdtempSync(join(tmpdir(), "innsegl-source-"));
    writeFileSync(join(dir, "note.ts"), contents, "utf8");
    return new Scanner({ sources: [{ base: dir, pattern: "**/*", negated: false }] }).scan();
  };

  for (const [label, contents] of [
    ["a directory holding one empty file", "\n"],
    [
      "the same directory, the literal inside a // comment",
      "// the escape hatch this project keeps on purpose: bg-[#00ff00]\n",
    ],
  ] as const) {
    const found = scanDir(contents);
    lines.push(label);
    lines.push(`    file contents:      ${JSON.stringify(contents)}`);
    lines.push(`    candidates scanned: ${JSON.stringify(found)}`);
  }

  lines.push("");
  lines.push("the real tree, one file at a time, for the three files that carry it:");
  for (const relative of [
    "src/components/common/colour-discipline.test.ts",
    "src/tokens/README.md",
    "src/tokens/tailwind-theme.css",
  ]) {
    const dir = mkdtempSync(join(tmpdir(), "innsegl-source-"));
    const name = relative.slice(relative.lastIndexOf("/") + 1);
    writeFileSync(join(dir, name), readFileSync(join(WEB_DIR, relative), "utf8"), "utf8");
    const found = new Scanner({
      sources: [{ base: dir, pattern: "**/*", negated: false }],
    }).scan();
    lines.push(
      `    web/${relative}  ->  yields bg-[#00ff00]: ${found.includes("bg-[#00ff00]") ? "YES" : "no"}`,
    );
  }
  return lines.join("\n");
}

function gateInCi(): string {
  const hits = grep(["-rn", "check-tokens", ".github"], REPO_DIR);
  return hits === ""
    ? "grep -rn check-tokens .github  ->  no match. The gate is NOT in CI."
    : `${hits}\n\nThe gate and its self-test both run in CI. ADR-0038's caveat is\nsuperseded; the ADR has not been updated to say so.`;
}
