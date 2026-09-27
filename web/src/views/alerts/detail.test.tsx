// SPDX-License-Identifier: Apache-2.0

/*
 * One alert, in full — ADR-0054, doc 06 P1, P4, §4.3.
 *
 * NEW test ID proposed for doc 07 (not added to it by this change):
 *   FE-136 | U | The alert detail view | Every field of one alert in readable
 *          |   | form: what happened, the run or segment, the full reason, when
 *          |   | it was recorded, the ledger claim, and the raw-record link;
 *          |   | long identifiers through the identifier chip; read-only | P1,
 *          |   | P4, ADR-0044, ADR-0054
 *   FE-140 | U | How to resolve an open alert | The exact resolve-alert command
 *          |   | with only the event ID filled in, copyable, two sentences of help;
 *          |   | absent on a resolved alert, which shows who, when and why | ADR-0044,
 *          |   | ADR-0054
 */

import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AlertDetail } from "./AlertDetail";
import { AlertDetailView } from "./AlertDetailView";
import { DRIFT, NOW, SEGMENT_DRIFT, UNATTRIBUTED } from "./fixtures";
import { strings } from "./strings";

function detail(alert = DRIFT) {
  return render(<AlertDetail alert={alert} apiBase="/api/v1" now={NOW} />);
}

/** The value a labelled fact carries, found through its term. */
function fact(label: string): HTMLElement {
  const term = screen.getByText(label, { selector: "dt" });
  const value = term.nextElementSibling;
  if (!(value instanceof HTMLElement)) throw new Error(`no value after ${label}`);
  return value;
}

describe("FE-136 a drift alert, in full", () => {
  it("names what happened as its heading, with the human summary under it", () => {
    detail();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      strings.alert.driftTitle,
    );
    expect(screen.getByText(strings.alert.reasons.noLogEntry)).toBeInTheDocument();
  });

  it("gives the reason in full, verbatim", () => {
    detail();
    expect(fact(strings.detail.reasonLabel)).toHaveTextContent(DRIFT.reason!);
  });

  it("says when it was recorded, absolutely and relatively", () => {
    detail();
    const when = fact(strings.detail.recordedLabel);
    expect(when).toHaveTextContent("2026-09-06 17:27:39 UTC");
    expect(when.querySelector("time")).toHaveAttribute("datetime", DRIFT.ts);
  });

  it("names the run it concerns, linked to the run's own view (P4)", () => {
    detail();
    const run = fact(strings.detail.runLabel);
    expect(within(run).getByRole("link")).toHaveAttribute("href", `/runs/${DRIFT.run_id}`);
  });

  it("carries the ledger claim id through the identifier chip", () => {
    detail();
    const claim = fact(strings.detail.claimLabel);
    expect(claim.querySelector("[data-identifier-display]")).not.toBeNull();
    expect(claim).toHaveTextContent(DRIFT.subject_event_id!);
  });

  it("links to the raw record (P1)", () => {
    detail();
    expect(
      screen.getByRole("link", { name: strings.detail.rawRecord }),
    ).toHaveAttribute("href", "/api/v1/alerts?event_type=ledger_drift_detected");
  });

  it("says plainly when an alert names no run", () => {
    detail(SEGMENT_DRIFT);
    expect(fact(strings.detail.runLabel)).toHaveTextContent(strings.detail.noRun);
  });

  it("states that it is open and that this dashboard cannot change that", () => {
    detail();
    expect(fact(strings.detail.statusLabel)).toHaveTextContent(strings.detail.openStatus);
  });

  it("offers no resolve and no dismiss control (ADR-0044)", () => {
    detail();
    for (const button of screen.queryAllByRole("button")) {
      // A copy control may carry the command text; no control may BE a resolve.
      expect(button.textContent ?? "").toMatch(/Copy$/);
    }
    expect(screen.queryByRole("form")).toBeNull();
  });
});

describe("FE-140 how an operator resolves an open alert (ADR-0054)", () => {
  const command = (id: string) =>
    `innsegl resolve-alert -event-id=${id} -resolved-by=<your name> -reason="<why it is resolved>"`;

  it("shows the exact command, with only the event ID filled in", () => {
    detail();
    const section = screen.getByRole("region", { name: strings.detail.resolveHeading });
    expect(section).toHaveTextContent(command(DRIFT.event_id));
  });

  it("offers the command through the copy control, whole", () => {
    detail();
    const section = screen.getByRole("region", { name: strings.detail.resolveHeading });
    const copy = within(section).getByRole("button");
    expect(copy).toHaveAttribute("title", command(DRIFT.event_id));
  });

  it("says what resolving records, and that segment drift clears on its own", () => {
    detail();
    const section = screen.getByRole("region", { name: strings.detail.resolveHeading });
    expect(section).toHaveTextContent(strings.detail.resolveDetail);
    expect(section).toHaveTextContent(strings.detail.autoClearDetail);
    expect(strings.detail.resolveDetail).toMatch(/never changed/);
  });

  it("is a command to copy, not a button that resolves (ADR-0044)", () => {
    detail();
    const section = screen.getByRole("region", { name: strings.detail.resolveHeading });
    expect(within(section).getAllByRole("button")).toHaveLength(1);
    expect(within(section).getByRole("button").textContent ?? "").not.toMatch(/^resolve/i);
  });

  it("is absent on a resolved alert, which shows who, when and why instead", () => {
    detail({
      ...DRIFT,
      resolved: true,
      resolved_by: "operator",
      resolved_at: "2026-09-06T18:00:00Z",
      resolved_reason: "Rekor entry re-checked by hand",
    });
    expect(screen.queryByRole("region", { name: strings.detail.resolveHeading })).toBeNull();
    const status = fact(strings.detail.statusLabel);
    expect(status).toHaveTextContent("operator");
    expect(status).toHaveTextContent("2026-09-06 18:00:00 UTC");
    expect(status).toHaveTextContent("Rekor entry re-checked by hand");
  });
});

describe("FE-136 an unattributed alert, in full", () => {
  it("names the certificate identity, the Rekor entry and its index", () => {
    detail(UNATTRIBUTED);
    expect(fact(strings.detail.identityLabel)).toHaveTextContent(
      UNATTRIBUTED.certificate_identity!,
    );
    expect(fact(strings.detail.rekorEntryLabel)).toHaveTextContent(
      UNATTRIBUTED.rekor_entry_uuid!,
    );
    expect(fact(strings.detail.rekorIndexLabel)).toHaveTextContent("2");
  });

  it("shows a resolved alert's resolution rather than calling it open", () => {
    detail({
      ...UNATTRIBUTED,
      resolved: true,
      resolved_by: "operator",
      resolved_at: "2026-09-06T18:00:00Z",
      resolved_reason: "Signed by hand during recovery",
    });
    const status = fact(strings.detail.statusLabel);
    expect(status).toHaveTextContent(/resolved/i);
    expect(status).toHaveTextContent("Signed by hand during recovery");
  });
});

/* The view: finds one alert in the feed by its event ID. */
function ok(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

afterEach(() => vi.unstubAllGlobals());

describe("FE-136 the detail view reads its alert", () => {
  it("finds the alert on a later page of the feed", async () => {
    const asked: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown) => {
        const url = String(input);
        asked.push(url);
        return Promise.resolve(
          url.includes("cursor=")
            ? ok({ alerts: [DRIFT], total: 2, limit: 1, data_as_of: "" })
            : ok({ alerts: [UNATTRIBUTED], total: 2, limit: 1, next_cursor: "32", data_as_of: "" }),
        );
      }),
    );
    render(<AlertDetailView route={{ view: "alert", eventId: DRIFT.event_id }} now={NOW} />);
    expect(
      await screen.findByRole("heading", { level: 1, name: strings.alert.driftTitle }),
    ).toBeInTheDocument();
    expect(asked.some((u) => u.includes("cursor=32"))).toBe(true);
  });

  it("says so when the feed holds no such alert, rather than guessing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(ok({ alerts: [DRIFT], total: 1, limit: 200, data_as_of: "" }))),
    );
    render(<AlertDetailView route={{ view: "alert", eventId: "nope" }} now={NOW} />);
    expect(await screen.findByText(strings.detail.notFoundDetail)).toBeInTheDocument();
  });

  it("reports a failed read as a failure, not as an absent alert (P2)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({ ok: false, status: 503, json: async () => ({}) } as unknown as Response),
      ),
    );
    render(<AlertDetailView route={{ view: "alert", eventId: DRIFT.event_id }} now={NOW} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/503/);
  });
});
