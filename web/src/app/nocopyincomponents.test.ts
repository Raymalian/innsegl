// SPDX-License-Identifier: Apache-2.0

// FE-020 — no component holds a user-visible string literal.
//
// doc 06 §6.3: "all strings externalized from components so translation is
// possible." That is this issue's acceptance criterion, and it is the kind of
// rule that is true on the day it is written and false three views later. So
// it is not reviewed, it is parsed: every .tsx file in the shell is read
// through the TypeScript compiler that already ships in this toolchain, and
// two things are refused —
//
//   1. JSX text with any non-whitespace in it. `<p>Fulcio unreachable</p>` is
//      copy that a translator will never find.
//   2. A string literal in an attribute a person can perceive — aria-label,
//      alt, title, placeholder and their relatives. These are the ones that
//      get missed, because they do not look like copy in a diff.
//
// The files are found by pattern rather than named in a list, so a component
// added tomorrow is scanned tomorrow without anyone remembering.
//
// Scope: every .tsx under web/src, not just this directory. It began scoped to
// src/app/ because RM-042's components were being written in parallel and were
// not this issue's to police. Both landed in the same wave, and a discipline
// that covers one directory is a discipline a component author escapes by
// putting the file somewhere else.

import ts from "typescript";
import { describe, expect, it } from "vitest";

const ATTRIBUTES_A_PERSON_CAN_PERCEIVE = new Set([
  "alt",
  "aria-description",
  "aria-label",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
  "label",
  "placeholder",
  "title",
]);

interface Finding {
  file: string;
  line: number;
  text: string;
}

export function findEmbeddedCopy(file: string, source: string): Finding[] {
  const parsed = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TSX,
  );
  const findings: Finding[] = [];

  const at = (node: ts.Node) =>
    parsed.getLineAndCharacterOfPosition(node.getStart(parsed)).line + 1;

  const literalText = (node: ts.Node | undefined): string | undefined => {
    if (node === undefined) return undefined;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return node.text;
    }
    // A template with substitutions is the hole this scanner had. RM-044 found
    // it: `Ledger segment ${segment} anchored ${minutes} min ago` in a JSX slot
    // is copy — three English words a translator needs — and it passed, because
    // only NoSubstitutionTemplateLiteral was recognised. The interpolations are
    // not the copy; the text around them is.
    if (ts.isTemplateExpression(node)) {
      const around = [
        node.head.text,
        ...node.templateSpans.map((span) => span.literal.text),
      ]
        .join(" ")
        .trim();
      // Punctuation and separators joining two interpolations are not copy.
      // `${label}: ${value}.` carries nothing a translator would change, and
      // flagging it would push authors to move a colon into a catalogue, which
      // makes the catalogue worse and teaches everyone to distrust this gate.
      // Two adjacent letters is the test: it admits "ago" and "of", and
      // rejects ":", " — ", "/" and "()".
      return /\p{L}{2}/u.test(around) ? around : undefined;
    }
    if (ts.isJsxExpression(node)) return literalText(node.expression);
    return undefined;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isJsxText(node) && node.text.trim() !== "") {
      findings.push({ file, line: at(node), text: node.text.trim() });
    }

    if (ts.isJsxAttribute(node) && ts.isIdentifier(node.name)) {
      const value = literalText(node.initializer);
      if (
        value !== undefined &&
        ATTRIBUTES_A_PERSON_CAN_PERCEIVE.has(node.name.text)
      ) {
        findings.push({ file, line: at(node), text: `${node.name.text}="${value}"` });
      }
    }

    if (
      ts.isJsxExpression(node) &&
      node.parent !== undefined &&
      (ts.isJsxElement(node.parent) || ts.isJsxFragment(node.parent))
    ) {
      const value = literalText(node);
      if (value !== undefined && value.trim() !== "") {
        findings.push({ file, line: at(node), text: value });
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(parsed);
  return findings;
}

const components = Object.entries(
  import.meta.glob("../**/*.tsx", {
    query: "?raw",
    import: "default",
    eager: true,
  }),
).filter(([path]) => !path.includes(".test."));

describe("FE-020 the shell's components hold no copy", () => {
  it("has components to scan, so a passing run is not a vacuous one", () => {
    expect(components.length).toBeGreaterThanOrEqual(3);
    const paths = components.map(([path]) => path);
    expect(paths.some((p) => p.endsWith("/App.tsx"))).toBe(true);
    // Both trees, named explicitly: a glob that silently stopped matching one
    // of them would otherwise leave this passing on the other alone.
    expect(paths.some((p) => p.includes("components/common/"))).toBe(true);
  });

  it.each(components)("%s holds none", (path, source) => {
    const findings = findEmbeddedCopy(path, source);
    expect(
      findings,
      findings
        .map((f) => `${f.file}:${f.line} — ${f.text}`)
        .join("\n"),
    ).toEqual([]);
  });
});

describe("FE-020 the scanner bites", () => {
  const planted = `
    export function Bad() {
      return (
        <div title="Everything checks out">
          Fulcio unreachable
          <img alt="verified" src={x} />
          <span>{"Rekor inclusion proven"}</span>
        </div>
      );
    }
  `;

  it("finds JSX text, a visible attribute and a literal in an expression slot", () => {
    const found = findEmbeddedCopy("planted.tsx", planted).map((f) => f.text);
    expect(found).toContain("Fulcio unreachable");
    expect(found).toContain('title="Everything checks out"');
    expect(found).toContain('alt="verified"');
    expect(found).toContain("Rekor inclusion proven");
  });

  it("does not flag an attribute nobody perceives, or copy read from the catalogue", () => {
    const good = `
      export function Good({ s }: { s: { a: string } }) {
        return <div role="status" className="text-ink" aria-label={s.a}>{s.a}</div>;
      }
    `;
    expect(findEmbeddedCopy("good.tsx", good)).toEqual([]);
  });
});
