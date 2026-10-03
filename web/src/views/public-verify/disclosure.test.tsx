// SPDX-License-Identifier: Apache-2.0

/*
 * RM-332: the verify page leads with the verdict and the attribution, and the
 * six evidence sections sit behind native disclosures — keyboard-operable.
 * A section that carries a problem opens itself: doc 06 §4.5 does not let a
 * condition hide inside a closed panel.
 */

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PublicVerifyView } from "./PublicVerifyView";
import { strings } from "./strings";
import { COMMIT_SHA, REPO, bothUpstreamsBlocked, wireProof } from "./fixtures";

afterEach(cleanup);
beforeEach(() => vi.unstubAllGlobals());

async function show(body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ),
  );
  const view = render(
    <PublicVerifyView route={{ view: "verify", commit: COMMIT_SHA, repo: REPO }} />,
  );
  await waitFor(() => {
    expect(view.container.querySelector('[aria-busy="true"]')).toBeNull();
    expect(view.container.querySelector("[data-verdict]")).not.toBeNull();
  });
  return view;
}

function disclosure(heading: string): HTMLDetailsElement {
  const found = screen.getByRole("heading", { name: heading }).closest("details");
  expect(found, heading).not.toBeNull();
  return found as HTMLDetailsElement;
}

const EVIDENCE = [
  strings.liveCheck.heading,
  strings.trailer.heading,
  strings.certificate.heading,
  strings.entry.heading,
  strings.rederivation.heading,
  strings.offline.heading,
];

describe("RM-332 the evidence is collapsed behind the verdict", () => {
  it("puts the verdict before every evidence section", async () => {
    const { container } = await show(wireProof());
    const verdict = container.querySelector("[data-verdict]") as HTMLElement;
    for (const heading of EVIDENCE) {
      expect(
        verdict.compareDocumentPosition(disclosure(heading)) &
          Node.DOCUMENT_POSITION_FOLLOWING,
        heading,
      ).toBeTruthy();
    }
  });

  it("keeps the verdict out of any closed disclosure", async () => {
    const { container } = await show(wireProof());
    const verdict = container.querySelector("[data-verdict]") as HTMLElement;
    expect(verdict.closest("details:not([open])")).toBeNull();
  });

  it("closes all six sections when nothing is wrong", async () => {
    await show(wireProof());
    for (const heading of EVIDENCE) {
      expect(disclosure(heading), heading).not.toHaveAttribute("open");
    }
  });

  it("opens with a click on the heading, which sits in a native summary", async () => {
    await show(wireProof());
    const certificate = disclosure(strings.certificate.heading);
    const summary = screen.getByRole("heading", { name: strings.certificate.heading })
      .closest("summary");
    expect(summary?.parentElement).toBe(certificate);
    await userEvent.click(summary as HTMLElement);
    expect(certificate).toHaveAttribute("open");
  });

  it("opens the live checks by itself when an upstream did not answer", async () => {
    await show(bothUpstreamsBlocked());
    expect(disclosure(strings.liveCheck.heading)).toHaveAttribute("open");
  });
});
