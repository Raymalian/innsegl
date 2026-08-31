// SPDX-License-Identifier: Apache-2.0

/*
 * FE-004 — the mismatch case, with the forged-trailer fixture doc 06 §7 asks
 * for by name.
 *
 * doc 07: FE-004 | A | Mismatch case with forged-trailer fixture | Red,
 * banner-level, differing segment highlighted with non-color cue | FD P3, §6.4
 *
 * FE-004 IS ALSO TYPED (A). "Red" and "banner-level" are claims about pixels
 * and about visual dominance, and no browser runs in this repository — RM-049
 * (#57) owns that harness. What this file establishes is everything that is
 * true in the DOM: that the alarm is a banner-level alert element carrying the
 * integrity tone from the token sheet, that the two identities are side by
 * side in full, and that the cue on the differing text SURVIVES THE REMOVAL OF
 * COLOUR.
 *
 * doc 06 §6.4: "the mismatch highlight in the three-check panel also
 * underlines/marks the differing text." A wavy underline is a CSS property and
 * a stripped-down DOM cannot see one, so the panel does not rely on it alone:
 * the differing segment is a <mark> element, and the comparison states in
 * VISIBLE TEXT which of the six segments differs. Both survive here, with
 * every class, style and data-* attribute taken away.
 */

import { render, screen, within } from "@testing-library/react";
import { afterEach, cleanup, describe, expect, it } from "vitest";

import {
  FORGED_IDENTITY,
  PROVEN_IDENTITY,
  forgedTrailerProof,
  verifiedProof,
} from "./fixtures";
import { strings } from "./strings";
import { VerificationPanel } from "./VerificationPanel";

afterEach(cleanup);

function perceivable(html: string): string {
  return html
    .replace(/ (?:class|style)="[^"]*"/g, "")
    .replace(/ data-[\w-]+="[^"]*"/g, "");
}

const mismatch = () =>
  render(<VerificationPanel proof={forgedTrailerProof()} id="panel" />).container;

describe("FE-004 a forged trailer fails, loudly", () => {
  it("rolls up to failed, not to unavailable and not to verified", () => {
    const container = mismatch();
    expect(container.querySelector("[data-verdict]")?.getAttribute("data-verdict"))
      .toBe("failed");
    expect(container.innerHTML).not.toContain("proof-verified");
  });

  it("is banner-level: an alert, carrying the integrity tone (doc 06 P3, §4.5)", () => {
    mismatch();
    const alert = screen.getByRole("alert");
    expect(alert.getAttribute("class")).toContain("integrity-alert");
    expect(alert.textContent).toContain(strings.mismatch.title);
  });

  it("links the alarm to the evidence behind it (doc 06 P1)", () => {
    mismatch();
    const alert = screen.getByRole("alert");
    const link = within(alert).getByRole("link");
    expect(link.getAttribute("href")).toBe("#panel-identity");
    expect(document.getElementById("panel-identity")).not.toBeNull();
  });

  it("raises no alarm when the identities agree (P3: success is quiet)", () => {
    render(<VerificationPanel proof={verifiedProof()} id="panel" />);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("FE-004 the two identities, side by side", () => {
  it("shows both in full — truncation could hide the very segment that differs", () => {
    const container = mismatch();
    const comparison = container.querySelector("#panel-identity");
    if (comparison === null) throw new Error("the panel renders no comparison");
    const text = comparison.textContent ?? "";
    expect(text).toContain(FORGED_IDENTITY);
    expect(text).toContain(PROVEN_IDENTITY);
    expect(text).toContain(strings.identity.trailer);
    expect(text).toContain(strings.identity.certificate);
  });

  it("marks the differing segment in both of them, and only that segment", () => {
    const container = mismatch();
    const marks = Array.from(container.querySelectorAll("#panel-identity mark"));
    expect(marks.map((m) => m.textContent)).toEqual(["run-0e91bd", "run-7f3a2c"]);
  });

  it("marks nothing when the identities agree", () => {
    const container = render(
      <VerificationPanel proof={verifiedProof()} id="panel" />,
    ).container;
    expect(container.querySelectorAll("mark")).toHaveLength(0);
  });
});

describe("FE-004 the cue survives with colour taken away", () => {
  it("still marks the differing text and still names the segment", () => {
    const html = perceivable(mismatch().innerHTML);

    expect(html).not.toContain("class=");
    expect(html).not.toContain("style=");
    expect(html).not.toMatch(/data-[\w-]+=/);

    // The mark element itself: a cue in the markup, not in a stylesheet.
    expect(html).toContain("<mark>run-0e91bd</mark>");
    expect(html).toContain("<mark>run-7f3a2c</mark>");
    // And the words, which no rendering mode can take away: WHICH segment.
    expect(html).toContain(strings.identity.differs("run-id"));
  });

  it("names the differing segment in text a sighted reader sees", () => {
    mismatch();
    // Not screen-reader-only: doc 06 §6.4's cue has to reach a reader looking
    // at a greyscale printout of an audit report, and an sr-only span does
    // not.
    const named = screen.getByText(strings.identity.differs("run-id"));
    expect(named.getAttribute("class") ?? "").not.toContain("sr-only");
  });

  it("pairs the mark with the colour it is redundant with", () => {
    // Never colour alone runs both ways: the cue is not colour only, and the
    // colour is still there for the reader who can see it.
    const container = mismatch();
    const mark = container.querySelector("mark");
    expect(mark?.getAttribute("class")).toContain("mismatch");
  });
});

describe("FE-004 an identity the panel cannot parse is still compared honestly", () => {
  it("marks the whole value and says the two cannot be compared segment by segment", () => {
    const proof = forgedTrailerProof();
    const container = render(
      <VerificationPanel
        proof={{ ...proof, claim: { ...proof.claim, identity: "not-an-identity" } }}
        id="panel"
      />,
    ).container;
    const marks = Array.from(container.querySelectorAll("#panel-identity mark"));
    expect(marks[0]?.textContent).toBe("not-an-identity");
    expect(container.textContent).toContain(strings.identity.uncomparable);
  });
});
