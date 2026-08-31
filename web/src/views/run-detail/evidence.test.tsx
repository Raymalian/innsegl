// SPDX-License-Identifier: Apache-2.0

/*
 * FE-084 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Run detail puts each event's own evidence next to it, and states every
 *     gap in that evidence rather than leaving it blank | Tool calls expand to
 *     their payload digest and say the ledger holds no body; commits show SHA,
 *     Rekor index and Rekor entry; canonical members are shown with an honest
 *     bound on what they are; canonical bytes that will not decode say so |
 *     FD §3.3, P1, P2, P5; doc 02 §3, §4
 *
 * The third and fourth clauses are the ones with teeth. doc 06 P1 is "evidence
 * over assertion", and the failure mode when evidence is missing is not a
 * visible error — it is a panel that renders nothing and reads as "nothing to
 * see here". doc 06 P2 forbids exactly that collapse, and doc 06 §8's ninth
 * anti-pattern is reassuring copy standing in for evidence. Silence is the
 * most reassuring copy there is.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Timeline } from "./Timeline";
import { COMMIT_SHA, NOW, healthyTimeline, ledgerEvent } from "./fixtures";
import { EVENT_TYPES } from "./types";
import type { TimelineEvent } from "./types";

function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const hidden of clone.querySelectorAll("svg, .sr-only, [hidden]")) {
    hidden.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

function renderNode(event: TimelineEvent) {
  const { container } = render(<Timeline events={[event]} now={NOW} />);
  return { container, text: visibleText(container) };
}

const DIGEST =
  "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

describe("FE-084 tool calls expand to their digests", () => {
  const toolCall = ledgerEvent(EVENT_TYPES.toolCall, 3, {
    canonical: { tool_name: "edit_file", payload_digest: DIGEST },
  });

  it("names the tool, and offers the digests behind a disclosure", async () => {
    const { text } = renderNode(toolCall);
    expect(text).toContain("edit_file");
    const digests = screen.getByText("Digests");
    await userEvent.click(digests);
    expect(screen.getByText("Payload digest")).toBeInTheDocument();
  });

  it("says the ledger holds no body, so an empty panel is not read as withholding", () => {
    // doc 02 §3: a tool call's "body only as payload_digest" — IP E4 made
    // mechanical. A reader who expects a body needs to be told there is none.
    expect(renderNode(toolCall).text).toContain(
      "The ledger stores no tool-call body, only its digest.",
    );
  });

  it("says so when a tool call recorded no digest at all", () => {
    const bare = ledgerEvent(EVENT_TYPES.toolCall, 3, {
      canonical: { tool_name: "edit_file" },
    });
    expect(renderNode(bare).text).toContain("This tool call recorded no payload digest.");
  });
});

describe("FE-084 the tool-call count", () => {
  it("counts the tool calls exactly, beside the events themselves", async () => {
    const { RunDetailView } = await import("./RunDetailView");
    const timeline = [
      ledgerEvent(EVENT_TYPES.toolCall, 1, { canonical: { tool_name: "read_file" } }),
      ledgerEvent(EVENT_TYPES.toolCall, 2, { canonical: { tool_name: "edit_file" } }),
      ledgerEvent(EVENT_TYPES.runRetired, 3),
    ];
    const { runDetail } = await import("./fixtures");
    render(
      <RunDetailView
        route={{ view: "run", runId: "run-7f3a2c" }}
        fetchRun={async () => runDetail(timeline)}
        now={NOW}
      />,
    );
    // doc 06 §6.2: counts are exact, never rounded vanity numbers.
    expect(await screen.findByText("2 tool calls")).toBeInTheDocument();
  });

  it("says one tool call rather than 1 tool calls", async () => {
    const { RunDetailView } = await import("./RunDetailView");
    const { runDetail } = await import("./fixtures");
    render(
      <RunDetailView
        route={{ view: "run", runId: "run-7f3a2c" }}
        fetchRun={async () => runDetail(healthyTimeline())}
        now={NOW}
      />,
    );
    expect(await screen.findByText("1 tool call")).toBeInTheDocument();
  });
});

describe("FE-084 a recorded commit carries its external record", () => {
  it("shows the commit SHA, the Rekor log index and the Rekor entry", () => {
    const recorded = healthyTimeline().find(
      (event) => event.event_type === EVENT_TYPES.commitRecorded,
    ) as TimelineEvent;
    const { text } = renderNode(recorded);
    expect(text).toContain(COMMIT_SHA.slice(0, 10));
    // doc 06 §4.3: a Rekor index is never abbreviated — it is a number a
    // reader types into a log query.
    expect(text).toContain("82914");
    expect(text).toContain("Rekor entry");
  });
});

describe("FE-084 canonical members, with an honest bound", () => {
  it("offers the members and states that they are not the hashed bytes", async () => {
    const recorded = healthyTimeline()[4] as TimelineEvent;
    renderNode(recorded);
    await userEvent.click(screen.getByText("Canonical members"));
    expect(
      screen.getByText(
        "These are the event's canonical members after JSON decoding. Re-deriving the event hash needs the exact response bytes, which this rendering does not preserve.",
      ),
    ).toBeInTheDocument();
  });

  it("says an undecodable canonical is undecodable, rather than rendering nothing", () => {
    const broken = ledgerEvent(EVENT_TYPES.runRetired, 6, { canonical: 42 });
    const { text } = renderNode(broken);
    expect(text).toContain("This event's canonical members could not be decoded.");
    expect(text).toContain(
      "The ledger returned something this dashboard could not read as JSON.",
    );
  });

  it("says an absent canonical is absent", () => {
    const bare = ledgerEvent(EVENT_TYPES.runRetired, 6);
    expect(renderNode(bare).text).toContain(
      "This response carried no canonical members for this event.",
    );
  });

  it("decodes a double-encoded canonical rather than discarding the evidence", () => {
    const encoded = ledgerEvent(EVENT_TYPES.toolCall, 3, {
      canonical: JSON.stringify({ tool_name: "run_tests" }),
    });
    expect(renderNode(encoded).text).toContain("run_tests");
  });
});
