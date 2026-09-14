// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-115, second half — the serif is restricted, and the restriction is a gate.
 *
 * doc 06 §5.2, amended 2026-09-14 by the operator:
 *
 *   "The serif is restricted to headings and headline figures. It never sets
 *    body copy, never sets a label, and never sets anything a reader might
 *    copy. A serif appearing anywhere else is the drift this restriction
 *    exists to catch."
 *
 * Drift is the word. A display face is pleasant, and the failure mode is not
 * one bad decision — it is twenty small ones, each defensible, ending with a
 * dashboard whose hashes are set in a book face. P4 is the load-bearing half:
 * a SPIFFE ID or a digest in a proportional serif is a value a reader cannot
 * compare by eye, which is most of what identifiers are for.
 *
 * So this is a policy table rather than a heuristic. Every place in the
 * product entitled to the serif is named below, by file and by the style
 * export that carries it. Spending it somewhere new means adding a row here,
 * in the same commit, where a reviewer reads it — which is the whole point:
 * the twenty-first small decision has to be written down.
 *
 * The scan reads code with comments stripped, exactly as the colour-discipline
 * scans do: doc 06 §5.2 is quoted verbatim in several of these files, and what
 * is governed is naming the face in CODE.
 */

/* Rooted at the project rather than at this directory: a relative glob
 * normalises `../app/App.tsx` back to `./App.tsx`, and a policy table keyed on
 * a path that changes with the scanner's own location is a table nobody can
 * read. */
const RAW = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out, code in. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

const sources = Object.entries(RAW)
  .map(([path, raw]) => ({ name: path.replace(/^\/src\//, ""), code: code(raw) }))
  .filter((file) => !file.name.includes(".test."))
  .sort((a, b) => a.name.localeCompare(b.name));

/**
 * Where the display serif may be spent, and on what.
 *
 * Every entry is a view heading or a headline figure. Nothing here is copy a
 * reader reads in sentences, and nothing here is a value a reader copies:
 * repo and agent-type set their view headings in MONO rather than appearing
 * below, because those headings are identifiers (doc 06 P4) and the face that
 * makes an identifier comparable outranks the face that makes a heading
 * handsome.
 */
const ENTITLED: Readonly<Record<string, readonly string[]>> = {
  // The wordmark. A name, set once, in the chrome — not copy, not a label.
  "app/App.tsx": ["wordmark"],
  // The view heading, the panel headings under it, and the headline figure
  // on every metric card (doc 06 §3.1).
  "views/overview/styles.ts": ["heading", "listHeading", "cardValue", "cardValueWord"],
  "views/runs/styles.ts": ["heading"],
  "views/run-detail/styles.ts": ["pageHeading"],
  // The question the page asks (doc 06 §3.6).
  "views/public-verify/styles.ts": ["pageHeading"],
  // The one word that states the verdict (doc 06 §4.1).
  "components/verification/styles.ts": ["verdictHeadline"],
};

/** The const, or the JSX-local binding, a `font-serif` occurrence sits in. */
function owners(text: string): readonly string[] {
  const declaration = /(?:export\s+)?const\s+([A-Za-z0-9_]+)\s*[:=]/g;
  const found: string[] = [];
  let current = "";
  for (const line of text.split("\n")) {
    const declared = [...line.matchAll(declaration)];
    const last = declared[declared.length - 1]?.[1];
    if (last !== undefined) current = last;
    if (line.includes("font-serif")) found.push(current);
  }
  return found;
}

describe("FE-115 the serif sets headings and headline figures, and nothing else", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = sources.map((s) => s.name);
    expect(names).toContain("views/overview/styles.ts");
    expect(names).toContain("components/verification/styles.ts");
    expect(sources.length).toBeGreaterThan(40);
  });

  it("appears in exactly the files entitled to it", () => {
    const spending = sources
      .filter((file) => /font-serif/.test(file.code))
      .map((file) => file.name)
      .sort();
    expect(spending).toEqual(Object.keys(ENTITLED).sort());
  });

  it("appears only on the style each of those files is entitled to spend it on", () => {
    for (const [name, allowed] of Object.entries(ENTITLED)) {
      const file = sources.find((source) => source.name === name);
      expect(file, name).toBeDefined();
      const spent = [...new Set(owners(file?.code ?? ""))].sort();
      expect(spent, name).toEqual([...allowed].sort());
    }
  });

  it("never sets an identifier: mono and serif are never the same class", () => {
    for (const file of sources) {
      for (const line of file.code.split("\n")) {
        if (!line.includes("font-serif")) continue;
        expect(`${file.name}: ${line.trim()}`).not.toMatch(/font-mono/);
      }
    }
  });

  it("never sets prose: the serif and a prose measure are never the same class", () => {
    for (const file of sources) {
      for (const line of file.code.split("\n")) {
        if (!line.includes("font-serif")) continue;
        expect(`${file.name}: ${line.trim()}`).not.toMatch(/leading-prose|max-w-prose/);
      }
    }
  });
});
