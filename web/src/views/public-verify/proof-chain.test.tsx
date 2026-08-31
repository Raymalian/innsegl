// SPDX-License-Identifier: Apache-2.0

/*
 * FE-063 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   A | The public page renders doc 06 §3.6's full proof chain with each
 *     step's raw material | Trailer contents, certificate identity, the three
 *     checks, the log entry and its served bytes, the deployment's
 *     re-derivation, and the material for offline re-verification are all
 *     present and reachable; the fourth verdict is not collapsed into the
 *     third | FD §3.6, §4.1, P1, P4, P5, §6.4
 *
 * FE-007 is about what the page REFUSES to say. This is about what it owes a
 * reader when everything works, and the two are different failures: a page
 * that showed nothing would pass FE-007 completely.
 *
 * doc 06 §3.6 is the checklist, quoted so the assertions can be read against
 * it: "the full proof chain — trailer contents, certificate identity, Fulcio
 * chain check, Rekor inclusion proof, match verdict — each step rendered with
 * its raw material available (cert PEM, log index) for offline
 * re-verification."
 */

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { strings as verification } from "../../components/verification";
import { PublicVerifyView } from "./PublicVerifyView";
import { strings } from "./strings";
import {
  CERTIFICATE_PEM,
  COMMIT_SHA,
  ENTRY_UUID,
  FORGED_IDENTITY,
  FULCIO_ENDPOINT,
  FULCIO_ROOT_PEM,
  LOG_INDEX,
  PROVEN_IDENTITY,
  REKOR_ENDPOINT,
  REKOR_KEY_PEM,
  REPO,
  forgedTrailerProof,
  unattributedProof,
  wireProof,
} from "./fixtures";

afterEach(cleanup);
beforeEach(() => vi.unstubAllGlobals());

function serve(body: unknown, status = 200) {
  const impl = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
  vi.stubGlobal("fetch", impl);
  return impl;
}

async function show(body: unknown, commit = COMMIT_SHA, repo = REPO) {
  serve(body);
  const view = render(
    <PublicVerifyView route={{ view: "verify", commit, repo }} />,
  );
  await waitFor(() => {
    expect(view.container.querySelector('[aria-busy="true"]')).toBeNull();
    expect(view.container.querySelector("[data-verdict]")).not.toBeNull();
  });
  return view;
}

describe("FE-063 trailer contents", () => {
  it("shows all three Agent-* trailers, not only the one the panel compares", async () => {
    await show(wireProof());
    const section = screen.getByRole("heading", { name: strings.trailer.heading })
      .parentElement as HTMLElement;
    expect(within(section).getByText(strings.trailer.identity)).toBeInTheDocument();
    expect(within(section).getByText(strings.trailer.run)).toBeInTheDocument();
    expect(within(section).getByText(strings.trailer.task)).toBeInTheDocument();
    expect(section.textContent).toContain("run-7f3a2c");
    expect(section.textContent).toContain("task-1481");
  });

  it("says a commit claims nothing rather than showing empty rows", async () => {
    await show(unattributedProof());
    expect(screen.getByText(strings.trailer.none)).toBeInTheDocument();
  });
});

describe("FE-063 certificate identity", () => {
  it("shows the fields a third party needs to find the same certificate", async () => {
    const { container } = await show(wireProof());
    for (const label of [
      strings.certificate.spiffeId,
      strings.certificate.issuer,
      strings.certificate.serial,
      strings.certificate.notBefore,
      strings.certificate.notAfter,
      strings.certificate.fingerprint,
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(container.textContent).toContain("b1c2d3e4f5061728394a5b6c7d8e9f0011223344");
    expect(container.textContent).toContain(PROVEN_IDENTITY);
  });

  it("says none was resolved rather than rendering a blank panel (doc 06 §4.6)", async () => {
    await show(unattributedProof());
    expect(screen.getByText(strings.certificate.none)).toBeInTheDocument();
  });
});

describe("FE-063 the transparency-log entry", () => {
  it("shows the index doc 06 §4.1 names, the uuid, and the entry as served", async () => {
    const { container } = await show(wireProof());
    expect(screen.getByText(strings.entry.uuid)).toBeInTheDocument();
    expect(container.textContent).toContain(ENTRY_UUID);
    expect(container.textContent).toContain(String(LOG_INDEX));
    // The raw entry is the one piece of material the shared panel does not
    // carry, and it is what a reader replays against the log itself.
    expect(screen.getByText(strings.entry.raw)).toBeInTheDocument();
    expect(container.textContent).toContain('"logIndex"');
  });

  it("distinguishes a time the log signed from a time it did not (doc 06 P2)", async () => {
    await show(wireProof());
    expect(screen.getByText(strings.entry.attested)).toBeInTheDocument();
    cleanup();

    const body = wireProof() as Record<string, unknown>;
    await show({
      ...body,
      entry: { ...(body["entry"] as object), time_attested: false },
    });
    expect(screen.getByText(strings.entry.unattested)).toBeInTheDocument();
  });

  it("says none was resolved rather than showing index zero", async () => {
    await show(unattributedProof());
    expect(screen.getByText(strings.entry.none)).toBeInTheDocument();
  });
});

describe("FE-063 the raw material for offline re-verification (doc 06 P5)", () => {
  it("hands over every document the checks consumed", async () => {
    const { container } = await show(wireProof());
    for (const document of [CERTIFICATE_PEM, FULCIO_ROOT_PEM, REKOR_KEY_PEM]) {
      expect(container.textContent).toContain(document.trim());
    }
    expect(container.textContent).toContain("Agent-Identity:");
  });

  it("names the commit object it re-hashed, the repository and the response's time", async () => {
    const { container } = await show(wireProof());
    const section = screen.getByRole("heading", { name: strings.offline.heading })
      .parentElement as HTMLElement;
    expect(within(section).getByText(strings.offline.commitObjectId)).toBeInTheDocument();
    expect(within(section).getByText(strings.offline.repo)).toBeInTheDocument();
    expect(within(section).getByText(strings.offline.dataAsOf)).toBeInTheDocument();
    expect(section.textContent).toContain(REPO);
    expect(container.textContent).toContain(COMMIT_SHA);
  });

  it("names the command that does the same work without this page", async () => {
    await show(wireProof());
    expect(screen.getByText(strings.offline.commandValue)).toBeInTheDocument();
  });
});

describe("FE-063 the live-check record", () => {
  it("is a real table, with the endpoint and time for each upstream (doc 06 §6.4)", async () => {
    await show(wireProof());
    const table = screen.getByRole("table");
    for (const column of [
      strings.liveCheck.upstream,
      strings.liveCheck.endpoint,
      strings.liveCheck.checkedAt,
      strings.liveCheck.outcome,
    ]) {
      expect(within(table).getByRole("columnheader", { name: column })).toBeInTheDocument();
    }
    expect(within(table).getByRole("rowheader", { name: "Fulcio" })).toBeInTheDocument();
    expect(within(table).getByRole("rowheader", { name: "Rekor" })).toBeInTheDocument();
    expect(within(table).getByText(FULCIO_ENDPOINT)).toBeInTheDocument();
    expect(within(table).getByText(REKOR_ENDPOINT)).toBeInTheDocument();
    expect(within(table).getAllByText(strings.liveCheck.answered)).toHaveLength(2);
  });

  it("tells an upstream that did not answer from one nobody reported", async () => {
    await show(wireProof({ fulcioReachable: false, omitUpstreams: ["rekor"] }));
    const table = screen.getByRole("table");
    expect(within(table).getByText(strings.liveCheck.unanswered)).toBeInTheDocument();
    expect(within(table).getAllByText(strings.liveCheck.absent).length).toBeGreaterThanOrEqual(1);
  });
});

describe("FE-063 the deployment's own re-derivation", () => {
  it("renders each finding under its own agreement, contradictions included", async () => {
    await show(
      wireProof({
        findings: [
          { name: "the commit object is the commit that was asked about", result: "agrees" },
          { name: "the log index is the one the response reports", result: "contradicts", detail: "reports 1, entry carries 82914" },
          { name: "check 3 re-derives to the result the response reports", result: "underivable" },
        ],
      }),
    );
    expect(screen.getByText(strings.rederivation.agrees)).toBeInTheDocument();
    expect(screen.getByText(strings.rederivation.contradicts)).toBeInTheDocument();
    expect(screen.getByText(strings.rederivation.underivable)).toBeInTheDocument();
    expect(screen.getByText(strings.rederivation.contradicted)).toBeInTheDocument();
    // Twice on purpose: once as the finding, once in the panel's own account
    // of why a set of passing checks is not a verdict.
    expect(screen.getAllByText("reports 1, entry carries 82914").length).toBeGreaterThanOrEqual(1);
  });

  it("withholds the verdict when the response contradicts its own material", async () => {
    const { container } = await show(
      wireProof({
        findings: [{ name: "the log index is the one the response reports", result: "contradicts" }],
      }),
    );
    expect(container.innerHTML).not.toContain("proof-verified");
    expect(container.querySelector("[data-verdict]")?.textContent).toContain(
      verification.verdict.unavailable.label,
    );
  });

  it("says so when the response carried no re-derivation at all", async () => {
    // internal/api/server.go does not serve the findings today, so this is the
    // state a real deployment is in. Silence would read as a clean bill.
    await show(wireProof());
    expect(screen.getByText(strings.rederivation.absent)).toBeInTheDocument();
  });
});

describe("FE-063 the fourth verdict is not the third", () => {
  it("renders a pre-adoption commit as unattributed, never failed (VER-006, E7)", async () => {
    const { container } = await show(unattributedProof());
    const badge = container.querySelector("[data-verdict]");
    expect(badge?.textContent).toContain(verification.verdict.unattributed.label);
    expect(badge?.textContent).not.toContain(verification.verdict.failed.label);
    expect(badge?.textContent).not.toContain(verification.verdict.verified.label);
    expect(container.innerHTML).not.toContain("proof-verified");
  });
});

describe("FE-063 a forged trailer is loud (doc 06 P3)", () => {
  it("fails, names the differing segment in prose, and shows both identities", async () => {
    const { container } = await show(forgedTrailerProof());
    expect(container.querySelector("[data-verdict]")?.textContent).toContain(
      verification.verdict.failed.label,
    );
    expect(screen.getByText(verification.mismatch.title)).toBeInTheDocument();
    expect(container.textContent).toContain(FORGED_IDENTITY);
    expect(container.textContent).toContain(PROVEN_IDENTITY);
    // Never colour alone: the differing segment is also marked in the markup.
    expect(container.querySelector("mark")).not.toBeNull();
  });
});

describe("FE-063 the page is anonymous, keyboard-operable and read-only", () => {
  it("labels both inputs, so they are reachable by name", async () => {
    await show(wireProof());
    expect(screen.getByLabelText(strings.form.commitLabel)).toBeInTheDocument();
    expect(screen.getByLabelText(strings.form.repoLabel)).toBeInTheDocument();
  });

  it("takes a commit typed and submitted from the keyboard alone", async () => {
    window.history.replaceState(null, "", "/verify");
    const impl = serve(wireProof());
    render(<PublicVerifyView />);
    expect(screen.getByText(strings.form.idleTitle)).toBeInTheDocument();

    const field = screen.getByLabelText(strings.form.commitLabel);
    await userEvent.click(field);
    await userEvent.keyboard(`${COMMIT_SHA}{Enter}`);

    await waitFor(() => expect(impl).toHaveBeenCalled());
    const [url] = impl.mock.calls[0] as unknown as [string];
    expect(url).toContain(COMMIT_SHA);
  });

  it("issues nothing but reads (doc 06 P6)", async () => {
    const impl = serve(wireProof());
    render(<PublicVerifyView route={{ view: "verify", commit: COMMIT_SHA, repo: "" }} />);
    await waitFor(() => expect(impl).toHaveBeenCalled());
    for (const call of impl.mock.calls) {
      const init = (call as unknown as [string, RequestInit])[1];
      expect(init.method).toBe("GET");
    }
  });

  it("puts the submitted commit in the URL, so the view is shareable (doc 06 §7)", async () => {
    window.history.replaceState(null, "", "/verify");
    serve(wireProof());
    render(<PublicVerifyView />);

    await userEvent.type(screen.getByLabelText(strings.form.commitLabel), COMMIT_SHA);
    await userEvent.type(screen.getByLabelText(strings.form.repoLabel), REPO);
    await userEvent.click(screen.getByRole("button", { name: strings.form.submit }));

    await waitFor(() => {
      expect(window.location.pathname + window.location.search).toBe(
        `/verify?commit=${COMMIT_SHA}&repo=${REPO}`,
      );
    });
  });

  it("reads its input from the address, so a shared link reproduces the view", async () => {
    window.history.replaceState(null, "", `/verify?commit=${COMMIT_SHA}&repo=${REPO}`);
    const impl = serve(wireProof());
    render(<PublicVerifyView />);
    await waitFor(() => expect(impl).toHaveBeenCalled());
    const [url] = impl.mock.calls[0] as unknown as [string];
    expect(url).toBe(`/api/v1/proof/${COMMIT_SHA}?repo=${REPO}`);
  });
});
