// SPDX-License-Identifier: Apache-2.0

/*
 * FE-001 — the three-check panel in verified / failed / unavailable.
 *
 * doc 07: FE-001 | A | Visual regression: three-check panel in verified /
 * failed / unavailable | Three distinct renders (color+icon+label); snapshots
 * committed | FD P2, §4.1
 *
 * FE-001 IS TYPED (A) AND THIS FILE IS NOT A VISUAL REGRESSION TEST. There is
 * no browser and no image harness in this repository — that is RM-049 (#57) —
 * so the "snapshots committed" half of the criterion is NOT satisfied here and
 * is reported as unsatisfied. What is checkable without a browser is the half
 * that the snapshots would be evidence FOR: that the three states are three
 * renders and not one, that each carries colour AND icon AND label (doc 06
 * §6.4's "never color alone"), and that the distinction survives the removal
 * of everything a sighted reader cannot perceive.
 *
 * That last clause is the point of the stripping below. A test that compares
 * two renders with their class attributes intact proves only that two class
 * names differ, which is what a colour-only distinction looks like. So class,
 * style and every data-* attribute come out — data-* especially, because a
 * test hook left in the markup is a difference no reader can see and it makes
 * this assertion impossible to fail. What is left is the icon geometry and the
 * words.
 */

import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup } from "@testing-library/react";

import {
  LOG_INDEX,
  failedProof,
  forgedTrailerProof,
  proofWithResults,
  unavailableProof,
  verifiedProof,
} from "./fixtures";
import { strings } from "./strings";
import { VerificationPanel } from "./VerificationPanel";
import { VerificationSummary } from "./VerificationSummary";
import type { Proof } from "./types";

afterEach(cleanup);

/** Everything a reader cannot perceive, removed. */
function perceivable(html: string): string {
  return html
    .replace(/ (?:class|style)="[^"]*"/g, "")
    .replace(/ data-[\w-]+="[^"]*"/g, "");
}

function panel(proof: Proof) {
  // One id for every render, so two panels differ in what they say rather
  // than in the numbers React handed their headings.
  return render(<VerificationPanel liveness={{ source: "live" }} proof={proof} id="panel" />).container;
}

const STATES = [
  { name: "verified", proof: verifiedProof, colour: "text-proof-verified" },
  { name: "failed", proof: failedProof, colour: "text-proof-failed" },
  { name: "unavailable", proof: unavailableProof, colour: "text-proof-unavailable" },
] as const;

describe("FE-001 colour and icon and label, on all three", () => {
  it.each(STATES)("$name carries all three channels", ({ proof, colour }) => {
    const container = panel(proof());
    const badge = container.querySelector("[data-verdict]");
    if (badge === null) throw new Error("the panel renders no rollup badge");

    // Channel one: a colour with a meaning, from the token sheet.
    expect(badge.getAttribute("class")).toContain(colour);
    // Channel two: a shape.
    expect(badge.querySelector("svg")).not.toBeNull();
    // Channel three: words.
    expect((badge.textContent ?? "").trim().length).toBeGreaterThan(0);
  });

  it.each(STATES)("$name is announced by its own word", ({ name, proof }) => {
    const container = panel(proof());
    const badge = container.querySelector("[data-verdict]");
    expect(badge?.textContent).toContain(strings.verdict[name].label);
  });
});

describe("FE-001 three distinct renders, with colour taken away", () => {
  const rendered = STATES.map(({ name, proof }) => {
    const html = perceivable(panel(proof()).innerHTML);
    cleanup();
    return { name, html };
  });

  it("keeps nothing that only a stylesheet could tell apart", () => {
    for (const { name, html } of rendered) {
      expect(html, name).not.toContain("class=");
      expect(html, name).not.toContain("style=");
      expect(html, name).not.toMatch(/data-[\w-]+=/);
    }
  });

  it.each([
    [0, 1],
    [0, 2],
    [1, 2],
  ])("render %i and render %i still differ", (a, b) => {
    const first = rendered[a];
    const second = rendered[b];
    if (first === undefined || second === undefined) throw new Error("unreachable");
    expect(first.html).not.toBe(second.html);
  });

  it("differs in the words, not only in the shapes", () => {
    const words = STATES.map(({ proof }) => {
      const container = panel(proof());
      const text = container.querySelector("[data-verdict]")?.textContent ?? "";
      cleanup();
      return text.trim();
    });
    expect(new Set(words).size).toBe(3);
  });

  it("differs in the shapes, not only in the words", () => {
    const shapes = STATES.map(({ proof }) => {
      const container = panel(proof());
      const svg = container.querySelector("[data-verdict] svg");
      const geometry = Array.from(svg?.querySelectorAll("*") ?? [])
        .map((node) => `${node.tagName}:${node.getAttribute("d") ?? ""}:${node.getAttribute("points") ?? ""}`)
        .join("|");
      cleanup();
      return geometry;
    });
    expect(shapes.every((s) => s !== "")).toBe(true);
    expect(new Set(shapes).size).toBe(3);
  });
});

describe("FE-001 the three checks never collapse into one icon", () => {
  it.each(STATES)("$name names all three checks and each one's own result", ({ proof }) => {
    const container = panel(proof());
    const items = container.querySelectorAll("[data-check]");
    expect(items).toHaveLength(3);

    const p = proof();
    for (const [index, item] of items.entries()) {
      const check = p.checks[index];
      if (check === undefined) throw new Error("unreachable");
      const text = item.textContent ?? "";
      // Its own name, and its own tri-state word — not the rollup's.
      expect(text).toContain(strings.result[check.result].label);
      expect(item.querySelector("svg")).not.toBeNull();
    }
  });

  it("shows a failed check's own result even when another check passed", () => {
    const container = panel(proofWithResults(["verified", "failed", "unavailable"]));
    const words = Array.from(container.querySelectorAll("[data-check-result]")).map(
      (el) => el.getAttribute("data-check-result"),
    );
    expect(words).toEqual(["verified", "failed", "unavailable"]);
  });

  it("names the three checks in doc 06 §4.1's words", () => {
    const container = panel(verifiedProof());
    const text = container.textContent ?? "";
    expect(text).toContain(strings.checks.certificateChain);
    expect(text).toContain(strings.checks.rekorInclusion);
    expect(text).toContain(strings.checks.trailerIdentity);
  });

  it("renders a check name the panel does not recognise, rather than dropping it", () => {
    const proof = verifiedProof();
    const renamed: Proof = {
      ...proof,
      checks: [...proof.checks, { name: "Witness cosignature present", result: "unavailable" }],
    };
    const container = panel(renamed);
    expect(container.textContent).toContain("Witness cosignature present");
    expect(container.querySelectorAll("[data-check]")).toHaveLength(4);
  });
});

describe("FE-001 the Rekor check shows its log index (doc 06 §4.1)", () => {
  it("shows the index the log gave", () => {
    const container = panel(verifiedProof());
    const rekor = container.querySelector('[data-check="rekorInclusion"]');
    expect(rekor?.textContent).toContain(String(LOG_INDEX));
  });

  it("says there is no index rather than showing a zero", () => {
    const proof = verifiedProof();
    const container = panel({
      ...proof,
      entry: { log_index: 0, time_attested: false },
      checks: proof.checks.map((c) =>
        c.name === strings.checks.rekorInclusion ? { ...c, result: "unavailable" as const } : c,
      ),
    });
    const rekor = container.querySelector('[data-check="rekorInclusion"]');
    expect(rekor?.textContent).not.toContain("0");
    expect(rekor?.textContent).toContain(strings.checks.noLogIndex);
  });
});

describe("FE-003 the panel never renders a cached green", () => {
  it("renders unavailable when the live check errored and the cache says verified", () => {
    const container = render(
      <VerificationPanel
        proof={verifiedProof()}
        liveness={{ source: "cache", liveError: "dial tcp: connection refused" }}
        id="panel"
      />,
    ).container;

    expect(container.querySelector("[data-verdict]")?.getAttribute("data-verdict"))
      .toBe("unavailable");
    // The one thing that must not appear anywhere in the markup.
    expect(container.innerHTML).not.toContain("proof-verified");
    expect(container.textContent).toContain(strings.verdict.unavailable.label);
  });

  it("says why it will not repeat the cached verdict", () => {
    const container = render(
      <VerificationPanel
        proof={verifiedProof()}
        liveness={{ source: "cache", liveError: "dial tcp: connection refused" }}
        id="panel"
      />,
    ).container;
    expect(container.textContent).toContain(strings.downgrade["live-check-errored"]);
    // P1: the reader is told what went wrong, in the upstream's own words.
    expect(container.textContent).toContain("dial tcp: connection refused");
  });
});

describe("FE-037 (NEW) the panel is a described list with per-check status announced", () => {
  it("is a labelled region holding a real list of three items", () => {
    render(<VerificationPanel liveness={{ source: "live" }} proof={verifiedProof()} id="panel" />);
    const region = screen.getByRole("region", { name: strings.panel.heading });
    const list = within(region).getByRole("list");
    expect(within(list).getAllByRole("listitem")).toHaveLength(3);
  });

  it("announces each check's name and result as text, not as an icon", () => {
    render(<VerificationPanel liveness={{ source: "live" }} proof={proofWithResults(["verified", "failed", "unavailable"])} id="panel" />);
    const items = screen.getAllByRole("listitem");
    const spoken = items.map((item) => item.textContent ?? "");
    expect(spoken[0]).toContain(strings.result.verified.label);
    expect(spoken[1]).toContain(strings.result.failed.label);
    expect(spoken[2]).toContain(strings.result.unavailable.label);
    // Every icon in the panel is decoration for a label that already exists.
    for (const svg of screen.getByRole("region", { name: strings.panel.heading }).querySelectorAll("svg")) {
      expect(svg.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("describes each check with the evidence behind it (doc 06 P1)", () => {
    render(<VerificationPanel liveness={{ source: "live" }} proof={verifiedProof()} id="panel" />);
    const region = screen.getByRole("region", { name: strings.panel.heading });
    // Facts are a description list: a name and the value it stands for.
    const terms = region.querySelectorAll("dt");
    expect(terms.length).toBeGreaterThan(0);
    expect(region.textContent).toContain("checked against");
  });

  it("holds no control that writes (doc 06 P6)", () => {
    render(<VerificationPanel liveness={{ source: "live" }} proof={verifiedProof()} id="panel" />);
    const region = screen.getByRole("region", { name: strings.panel.heading });
    for (const button of region.querySelectorAll("button")) {
      // The only buttons in this product copy a value or open a disclosure.
      expect(button.getAttribute("type")).toBe("button");
    }
    expect(region.querySelectorAll("form, input, textarea, select")).toHaveLength(0);
  });
});

describe("FE-001 the summary badge always expands to the panel (§8 anti-pattern 4)", () => {
  it("shows the rollup, and the three checks are one keystroke away", () => {
    const { container } = render(
      <VerificationSummary liveness={{ source: "live" }} proof={forgedTrailerProof()} id="row" />,
    );
    const disclosure = container.querySelector("details");
    if (disclosure === null) throw new Error("the summary is not a disclosure");
    const summary = disclosure.querySelector("summary");
    expect(summary?.textContent).toContain(strings.verdict.failed.label);
    // Native disclosure semantics: operable from the keyboard without a line
    // of JavaScript, which is what doc 06 §6.4 asks of an expandable panel.
    expect(disclosure.querySelectorAll("[data-check]")).toHaveLength(3);
  });

  it("cannot be rendered without the panel behind it", () => {
    // §8 anti-pattern 4 is "a verification summary that cannot be expanded to
    // the three checks and their inputs". There is no prop that turns the
    // panel off, so a table cannot produce one by accident.
    const { container } = render(<VerificationSummary liveness={{ source: "live" }} proof={verifiedProof()} id="row" />);
    expect(container.querySelector("#row-identity")).not.toBeNull();
  });
});

describe("FE-001 a commit that claims nothing is not a failure (VER-006)", () => {
  it("renders unattributed as its own state", () => {
    const container = panel({ ...verifiedProof(), verdict: "unattributed", checks: [] });
    expect(container.querySelector("[data-verdict]")?.getAttribute("data-verdict"))
      .toBe("unattributed");
    expect(container.innerHTML).not.toContain("proof-verified");
    expect(container.innerHTML).not.toContain("proof-failed");
  });
});
