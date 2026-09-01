// SPDX-License-Identifier: Apache-2.0

/*
 * Probe 5 — doc 06 §8 anti-pattern 5:
 *
 *   "Mutating controls of any kind in the UI."
 *
 * doc 06 P6 states the rule: "No mutating action exists anywhere in the UI. No
 * delete, no edit, no retry buttons that write. The only 'actions' are copy,
 * filter, export, and navigate."
 *
 * Two surfaces can carry a mutation and both are measured.
 *
 *   THE CONTROLS. Every interactive element in every scene is enumerated from
 *   the rendered DOM — button, link, form, field, and anything carrying a
 *   button role — with the words a reader would act on. Each is classified
 *   against P6's four permitted actions, and anything unclassified is printed
 *   for a human rather than waved through.
 *
 *   THE REQUESTS. A control is only half of a mutation; the other half is a
 *   method. The built JavaScript bundle is swept for every HTTP method and
 *   every fetch option it contains, and the form elements are read for their
 *   `method` and `action`.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { Evidence, WEB_DIR } from "../harness/evidence";
import { gallery } from "../harness/gallery";
import { builtStylesheetPath, parseStylesheet } from "../harness/paint";
import { allText, visibleText } from "../harness/perceptible";

const sheet = parseStylesheet(builtStylesheetPath(WEB_DIR));

/** doc 06 P6's permitted actions, as the words this product actually uses. */
const PERMITTED: Array<[RegExp, string]> = [
  [/^Copy$|Copy$|\bCopy\b/i, "copy — P6 permits it explicitly"],
  [/^Open |Open in|View |Go to/i, "navigate"],
  [/Apply|Filter|Clear|Reset|Search|Newer|Older|Next|Previous|page/i, "filter or paginate"],
  [/Retry|Re-?check|Refresh|Verify|Check again/i, "re-read — a GET, not a write"],
  [/Show|Hide|Expand|Collapse|More|Less|details|Skip to/i, "disclosure or in-page navigation"],
  [/theme|light|dark|system/i, "theme preference — local to the browser"],
];

/** Words that would name a mutation. Nothing here is expected to match. */
const MUTATING =
  /\b(delete|remove|revoke|retire|edit|update|save|create|add|submit|approve|reject|disable|enable|rotate|reset password|publish|upload|import|write|modify|archive|restore)\b/i;

describe("probe 5 — mutating controls anywhere in the UI", () => {
  it("enumerates every control and every request the build can make", async () => {
    const scenes = await gallery();
    const e = new Evidence(
      "05-mutating-controls.txt",
      "Probe 5 — doc 06 §8.5: mutating controls of any kind in the UI",
    );

    e.section("every interactive element in the gallery");
    e.say("    Enumerated from the rendered DOM: <button>, <a href>, <form>, <input>,");
    e.say("    <select>, <textarea>, [role=button], [contenteditable], [onclick].");
    e.say();

    interface Control {
      readonly scene: string;
      readonly kind: string;
      readonly words: string;
      readonly extra: string;
    }
    const controls: Control[] = [];

    for (const scene of scenes) {
      const found = scene.container.querySelectorAll(
        "button, a[href], form, input, select, textarea, [role=button], [contenteditable], [onclick]",
      );
      for (const element of Array.from(found)) {
        const tag = element.tagName.toLowerCase();
        const extras: string[] = [];
        for (const name of ["type", "href", "method", "action", "target", "formmethod", "formaction", "role", "contenteditable", "onclick", "download"]) {
          const value = element.getAttribute(name);
          if (value !== null) extras.push(`${name}="${value}"`);
        }
        controls.push({
          scene: scene.name,
          kind: tag,
          words: (allText(element) || visibleText(sheet, element) || "(no words)")
            .replace(/\s+/g, " ")
            .slice(0, 90),
          extra: extras.join(" "),
        });
      }
    }

    e.say(`    controls found: ${controls.length}`);
    e.say();

    /* Deduplicate by what a reader would see, so the list is readable. */
    const unique = new Map<string, Control & { count: number }>();
    for (const control of controls) {
      const key = `${control.kind}|${control.words}|${control.extra}`;
      const seen = unique.get(key);
      if (seen === undefined) unique.set(key, { ...control, count: 1 });
      else seen.count += 1;
    }

    const unclassified: Array<Control & { count: number }> = [];
    for (const control of [...unique.values()].sort((a, b) => a.kind.localeCompare(b.kind))) {
      const match = PERMITTED.find(([pattern]) => pattern.test(control.words));
      const classification = match === undefined ? "UNCLASSIFIED" : match[1];
      if (match === undefined && control.kind !== "form") unclassified.push(control);
      e.say(`    <${control.kind}> x${control.count}  ${control.extra}`);
      e.say(`        words: "${control.words}"`);
      e.say(`        action: ${classification}`);
    }

    e.section("anything whose words would name a mutation");
    const mutating = [...unique.values()].filter((control) => MUTATING.test(control.words));
    if (mutating.length === 0) {
      e.say("    none. No control in the gallery carries a word from the mutation");
      e.say("    vocabulary (delete, remove, revoke, retire, edit, update, save,");
      e.say("    create, add, submit, approve, reject, disable, enable, rotate,");
      e.say("    publish, upload, import, write, modify, archive, restore).");
    } else {
      for (const control of mutating) {
        e.say(`    <${control.kind}> "${control.words}" ${control.extra}`);
      }
    }
    expect(mutating.map((control) => `${control.kind}:${control.words}`)).toEqual([]);

    e.section("controls this probe could not classify");
    if (unclassified.length === 0) {
      e.say("    none.");
    } else {
      e.say("    Printed for a human rather than waved through:");
      for (const control of unclassified) {
        e.say(`    <${control.kind}> "${control.words}" ${control.extra}`);
      }
    }

    e.section("the forms, and what they would submit");
    const forms: string[] = [];
    for (const scene of scenes) {
      for (const form of Array.from(scene.container.querySelectorAll("form"))) {
        forms.push(
          `${scene.name}: <form method="${form.getAttribute("method") ?? "(none — HTML default GET)"}" ` +
            `action="${form.getAttribute("action") ?? "(none)"}">  fields: ` +
            Array.from(form.querySelectorAll("input, select, textarea"))
              .map((field) => `${field.tagName.toLowerCase()}[name=${field.getAttribute("name") ?? "-"} type=${field.getAttribute("type") ?? "-"}]`)
              .join(", "),
        );
      }
    }
    e.block(forms.length === 0 ? "no <form> in any scene" : forms.join("\n"));
    for (const form of forms) {
      expect(/method="post"/i.test(form), `a POST form: ${form}`).toBe(false);
    }

    e.section("every HTTP method the built bundle contains");
    e.say("    A control cannot mutate without a method. This reads the shipped");
    e.say("    JavaScript, not the source, so anything a dependency does is included.");
    e.say();
    const bundle = readFileSync(bundlePath(), "utf8");
    const methods = new Set<string>();
    for (const match of bundle.matchAll(/method\s*:\s*["'`]([A-Za-z]+)["'`]/g)) {
      methods.add(match[1] as string);
    }
    for (const verb of ["POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete"]) {
      if (new RegExp(`["'\`]${verb}["'\`]`).test(bundle)) methods.add(`${verb} (as a bare string)`);
    }
    e.say(
      `    method: options found in the bundle: ` +
        `${methods.size === 0 ? "none at all" : [...methods].join(", ")}`,
    );
    e.say();
    e.say("    Every fetch call site in the bundle, with the options it passes:");
    const calls = [...bundle.matchAll(/fetch\(([^;]{0,160})/g)].map((m) => m[0].slice(0, 150));
    e.block([...new Set(calls)].join("\n") || "(no fetch call found)");
    e.say();
    e.say("    A fetch with no `method` is a GET. That is the HTTP default and is");
    e.say("    what every call above relies on.");
    for (const method of methods) {
      expect(
        ["GET", "HEAD", "OPTIONS", "get", "head", "options"].includes(method),
        `a non-read HTTP method in the bundle: ${method}`,
      ).toBe(true);
    }

    e.section("the same question asked of the source");
    e.block(
      grep([
        "-rnE",
        String.raw`method\s*:\s*['"\`](POST|PUT|PATCH|DELETE)|XMLHttpRequest|navigator\.sendBeacon`,
        "--include=*.ts",
        "--include=*.tsx",
        "src",
      ]) || "no non-GET method, no XMLHttpRequest, no sendBeacon anywhere in web/src",
    );

    e.section("localStorage and other writes that leave the page");
    e.say("    P6 is about the SYSTEM's state. A preference stored in the reader's");
    e.say("    own browser writes nothing to the ledger, but it is a write, so it is");
    e.say("    named here rather than left out:");
    e.block(
      grep(["-rn", "localStorage", "--include=*.ts", "--include=*.tsx", "--include=*.html", "src", "index.html"]) ||
        "(none)",
    );

    e.write();
  });
});

function bundlePath(): string {
  const assets = join(WEB_DIR, "dist", "assets");
  return execFileSync("sh", ["-c", `ls ${assets}/*.js`], { encoding: "utf8" }).trim();
}

function grep(args: readonly string[]): string {
  try {
    return execFileSync("grep", [...args], { cwd: WEB_DIR, encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}
