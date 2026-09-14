// SPDX-License-Identifier: Apache-2.0

/*
 * FE-119 — the verification page asks its question in the heading.
 *
 * doc 06 §3.6 makes this page "the adoptability showcase: it must work as a
 * standalone artifact someone screenshots into an audit report", and §6.1
 * governs its voice. The approved artboard draws the consequence: the first
 * line a stranger reads is the question the page answers — "Who produced this
 * commit?" — set in the display serif, not the nav item's "Verify a commit",
 * which names a tool rather than asking anything.
 *
 * The nav item keeps its own words. They are the shell's, from the shell's
 * catalogue, and the document title is built from them: a heading and a
 * navigation label are two different jobs, and the first sentence of a
 * screenshotted artifact is the one that has to carry the question.
 *
 * The field and its control are asserted as one row because that is the thing
 * the artboard changed and the thing a reader notices: a SHA field the width
 * of the page with the control beside it, rather than a stacked form.
 */

import { render, screen, within } from "@testing-library/react";

import { PublicVerifyView } from "./PublicVerifyView";
import { strings } from "./strings";

describe("FE-119 the page asks its question in the heading", () => {
  it("heads the page with the question, not with the nav item's words", () => {
    render(<PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />);
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toEqual(strings.page.question);
    expect(heading.textContent).toMatch(/who produced this commit\?/i);
  });

  it("sets the question in the display serif (§5.2)", () => {
    render(<PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />);
    expect(screen.getByRole("heading", { level: 1 }).className).toMatch(/font-serif/);
  });

  it("keeps the commit field and its control on one row", () => {
    render(<PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />);
    const row = screen.getByTestId("verify-field-row");
    expect(within(row).getByLabelText(strings.form.commitLabel)).toBeInTheDocument();
    expect(
      within(row).getByRole("button", { name: strings.form.submit }),
    ).toBeInTheDocument();
  });

  it("sets the SHA the reader types in mono: it is material, not prose (P4)", () => {
    render(<PublicVerifyView route={{ view: "verify", commit: "", repo: "" }} />);
    expect(screen.getByLabelText(strings.form.commitLabel).className).toMatch(
      /font-mono/,
    );
  });
});
