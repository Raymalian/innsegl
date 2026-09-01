// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 9 — doc 06 §8 anti-pattern 9:
 *
 *   "Celebratory or reassuring copy substituting for evidence ('You're all
 *    set!')."
 *
 * doc 06 §6.1 supplies the vocabulary this is measured against, in its own
 * words: "Factual, unvarnished, specific. Say what was checked and what
 * happened: 'Rekor inclusion proven at index 82914,' not 'Everything looks
 * good!' ... Banned vocabulary: 'successfully,' 'seamless,' 'trusted by,'
 * exclamation marks in system copy."
 *
 * Copy is measured where a reader meets it — in the rendered output of every
 * scene, through both channels, visible words and announced words — rather than
 * in the string catalogue. A catalogue entry nobody renders is not copy, and a
 * string assembled at render time from three fragments is not in the catalogue
 * at all.
 *
 * The banned list is then widened past §6.1's four items, because §8.9's
 * example ("You're all set!") is not in §6.1's list and the anti-pattern is
 * about a register rather than about four words.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery } from "../harness/gallery";
import { builtStylesheetPath, parseStylesheet } from "../harness/paint";
import { allText, visibleText } from "../harness/perceptible";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** doc 06 §6.1's own list, verbatim. */
const SPEC_BANNED: Array<[string, RegExp]> = [
  ["successfully", /\bsuccessful(ly)?\b/i],
  ["seamless", /\bseamless(ly)?\b/i],
  ["trusted by", /\btrusted by\b/i],
  ["an exclamation mark", /!/],
];

/** §8.9's register, widened. Reassurance that stands in place of evidence. */
const REGISTER_BANNED: Array<[string, RegExp]> = [
  ["you're all set", /you'?re all set/i],
  ["everything looks good", /everything (looks|is) (good|fine|ok|okay)/i],
  ["all good / all clear", /\ball (good|clear|set)\b/i],
  ["great / awesome / perfect / excellent", /\b(great|awesome|perfect|excellent|fantastic|wonderful)\b/i],
  ["congratulations / well done / nice work", /\b(congratulations|congrats|well done|nice work|good job)\b/i],
  ["celebratory emoji", /[\u{1F389}\u{1F38A}\u{2705}\u{1F44D}\u{1F680}\u{1F44F}\u{2728}]/u],
  ["don't worry / no need to worry", /\b(don'?t worry|no need to worry|nothing to worry)\b/i],
  ["everything is secure / you are protected", /\b(you are|you're) (protected|secure|safe)\b/i],
  ["healthy as a verdict word", /\bhealthy\b/i],
  ["'trust us'", /\btrust us\b/i],
  ["simply / just / easily", /\b(simply|effortless(ly)?)\b/i],
];

describe("probe 9 — celebratory or reassuring copy substituting for evidence", () => {
  it("scans every word the gallery renders, in both channels", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "09-copy.txt",
      "Probe 9 — doc 06 §8.9: celebratory or reassuring copy substituting for evidence",
    );

    e.section("what was scanned");
    let visibleChars = 0;
    let announcedChars = 0;
    const corpus: Array<{ scene: string; channel: string; text: string }> = [];
    for (const scene of scenes) {
      const seen = visibleText(sheet, scene.container);
      const heard = allText(scene.container);
      visibleChars += seen.length;
      announcedChars += heard.length;
      corpus.push({ scene: scene.name, channel: "visible", text: seen });
      corpus.push({ scene: scene.name, channel: "announced", text: heard });
    }
    e.say(`    scenes                     ${scenes.length}`);
    e.say(`    visible characters         ${visibleChars}`);
    e.say(`    announced characters       ${announcedChars}`);
    e.say("        (announced includes sr-only text, title, aria-label and alt —");
    e.say("         the channels a sighted scan would miss)");

    e.section("falsifiability: the scan on a corpus that DOES contain the copy");
    e.say("    A scan that finds nothing is worth nothing until it is shown to find");
    e.say("    something. The same patterns, over one invented sentence:");
    e.say();
    const control =
      "You're all set! Everything looks good — your commits were successfully " +
      "verified through our seamless pipeline. Trusted by thousands. 🎉 " +
      "The system is healthy, so don't worry.";
    e.block(control);
    e.say();
    let fired = 0;
    for (const [name, pattern] of [...SPEC_BANNED, ...REGISTER_BANNED]) {
      const hit = pattern.test(control);
      if (hit) fired += 1;
      e.say(`        ${hit ? "FIRES" : "silent"}  ${name}`);
    }
    e.say();
    e.say(`    ${fired} of ${SPEC_BANNED.length + REGISTER_BANNED.length} patterns fire on it.`);
    expect(fired).toBeGreaterThanOrEqual(10);

    e.section("doc 06 §6.1's banned vocabulary, verbatim");
    let specHits = 0;
    for (const [name, pattern] of SPEC_BANNED) {
      const hits = corpus.filter((entry) => pattern.test(entry.text));
      e.say(`    ${name.padEnd(22)} ${hits.length === 0 ? "not found" : `FOUND in ${hits.length} rendering(s)`}`);
      for (const hit of hits.slice(0, 6)) {
        const match = pattern.exec(hit.text);
        const at = match?.index ?? 0;
        e.say(`        ${hit.scene} (${hit.channel}): "…${hit.text.slice(Math.max(0, at - 70), at + 70)}…"`);
        specHits += 1;
      }
    }
    e.say();
    e.say(`    total occurrences: ${specHits}`);
    for (const [name, pattern] of SPEC_BANNED) {
      const hits = corpus.filter((entry) => pattern.test(entry.text));
      expect(hits.map((h) => `${h.scene}/${h.channel}`), `${name} appears in rendered copy`).toEqual([]);
    }

    e.section("the wider register doc 06 §8.9 is about");
    e.say("    §6.1's four items do not include §8.9's own example, \"You're all");
    e.say("    set!\", so the scan is widened to the register rather than the list.");
    e.say();
    const registerHits: string[] = [];
    for (const [name, pattern] of REGISTER_BANNED) {
      const hits = corpus.filter((entry) => pattern.test(entry.text));
      e.say(`    ${name.padEnd(42)} ${hits.length === 0 ? "not found" : `FOUND in ${hits.length}`}`);
      for (const hit of hits.slice(0, 4)) {
        const match = pattern.exec(hit.text);
        const at = match?.index ?? 0;
        e.say(`        ${hit.scene} (${hit.channel}): "…${hit.text.slice(Math.max(0, at - 80), at + 80)}…"`);
        registerHits.push(`${name} in ${hit.scene}`);
      }
    }
    e.say();
    e.say(`    total occurrences: ${registerHits.length}`);
    expect(registerHits).toEqual([]);

    e.section("the positive form: what the calm states actually say instead");
    e.say("    §8.9 is about reassurance SUBSTITUTING for evidence, so the test is");
    e.say("    not only that the reassurance is absent but that evidence is there in");
    e.say("    its place. The healthiest states in the product, quoted in full:");
    e.say();
    for (const name of [
      "panel/verified-live",
      "heartbeat/within-bound",
      "view/overview-calm",
      "empty/default",
    ] as const) {
      const scene = scenes.find((s) => s.name === name);
      if (scene === undefined) throw new Error(name);
      e.say(`    ${name}`);
      e.block(visibleText(sheet, scene.container).slice(0, 700));
      e.say();
    }

    e.section("the error states, which §6.1 also governs");
    e.say("    §6.1: \"Errors state what failed and what the user can do.\" Every");
    e.say("    error and unavailable state the gallery renders, quoted:");
    e.say();
    for (const name of [
      "error/default",
      "view/runs-failed",
      "view/overview-read-failed",
      "panel/cached-verified-live-errored",
      "view/public-verify-upstreams-blocked",
    ] as const) {
      const scene = scenes.find((s) => s.name === name);
      if (scene === undefined) throw new Error(name);
      e.say(`    ${name}`);
      e.block(visibleText(sheet, scene.container).slice(0, 700));
      e.say();
    }

    e.section("the catalogue, as a second pass over strings no scene reached");
    e.say("    doc 06 §6.3 externalises every string, so the catalogue is a superset");
    e.say("    of what the gallery renders. Scanned for the same vocabulary — a hit");
    e.say("    here would be copy waiting to appear rather than copy on screen:");
    e.say();
    const catalogues = execFileSync(
      "sh",
      ["-c", "ls src/app/strings.ts src/components/*/strings.ts src/views/*/strings.ts"],
      { cwd: WEB_DIR, encoding: "utf8" },
    )
      .trim()
      .split("\n");
    e.say(`    catalogue files: ${catalogues.length}`);
    for (const file of catalogues) e.say(`        web/${file}`);
    e.say();
    const catalogueHits: string[] = [];
    for (const [name, pattern] of [...SPEC_BANNED, ...REGISTER_BANNED]) {
      for (const file of catalogues) {
        const text = execFileSync("cat", [file], { cwd: WEB_DIR, encoding: "utf8" });
        // Strip block and line comments: a comment quoting the banned word in
        // order to explain the ban is not copy.
        const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
        if (!pattern.test(code)) continue;
        const match = pattern.exec(code);
        const at = match?.index ?? 0;
        catalogueHits.push(`${name} in web/${file}: "…${code.slice(Math.max(0, at - 90), at + 90).replace(/\s+/g, " ")}…"`);
      }
    }
    e.block(catalogueHits.length === 0 ? "no hit in any catalogue" : catalogueHits.join("\n\n"));
    expect(catalogueHits).toEqual([]);

    e.write();
  });
});
