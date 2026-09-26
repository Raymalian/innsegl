// SPDX-License-Identifier: Apache-2.0

/*
 * ADP-018 — the run timeline knows schema 3's adoption (ADR-0051, #298).
 *
 * MEASURED on the running deployment, 2026-09-26: the run that adopted a dead
 * run's work showed its run_adopted event as "Event type this dashboard does
 * not recognise", with a "Not a writer this event type is emitted by" warning
 * against an event the MCP is the only writer of, and none of the three facts
 * the event exists to record. The commit intent that carried the adoption out
 * showed nothing of it either.
 */

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Timeline } from "./Timeline";
import { NOW, ledgerEvent } from "./fixtures";
import { EVENT_TYPES } from "./types";

const DEAD = "run-08b1e398c684be63ee177365e7230d3b";
const CLAIM = "sha256:9b3c1f6e2a7d4b8c0e5f1a3d6c9b2e7f4a8d1c5e0b3f6a9d2c7e4b1f8a5d3c60";
const ADOPTION_ID = "01a0d51f-e225-7205-b8f3-7d25c5a8a650";

describe("ADP-018 — an adoption on the run timeline", () => {
  it("names the event and shows the dead run, its state and the claim", () => {
    const { container } = render(
      <Timeline
        events={[
          ledgerEvent(EVENT_TYPES.runAdopted, 1, {
            canonical: { adopted_run_id: DEAD, adopted_run_state: "retired", payload_digest: CLAIM },
          }),
        ]}
        now={NOW}
      />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Work adopted");
    expect(text).not.toContain("does not recognise");
    expect(text).not.toContain("Not a writer");
    expect(text).toContain("Adopted from");
    expect(text).toContain("retired");
    expect(text).toContain("Claim digest");
  });

  it("shows the adoption a commit intent carries out, and nothing on a plain one", () => {
    const { container } = render(
      <Timeline
        events={[
          ledgerEvent(EVENT_TYPES.commitIntent, 1, {
            canonical: { repo: "github.com/acme/api", adoption_event_id: ADOPTION_ID },
          }),
        ]}
        now={NOW}
      />,
    );
    expect(container.textContent ?? "").toContain("Adoption event");

    const plain = render(
      <Timeline
        events={[ledgerEvent(EVENT_TYPES.commitIntent, 1, { canonical: { repo: "github.com/acme/api" } })]}
        now={NOW}
      />,
    );
    expect(plain.container.textContent ?? "").not.toContain("Adoption event");
  });

  it("does not label a tool call's body digest as a claim", () => {
    const { container } = render(
      <Timeline
        events={[ledgerEvent(EVENT_TYPES.toolCall, 1, { canonical: { tool_name: "Write", payload_digest: CLAIM } })]}
        now={NOW}
      />,
    );
    expect(container.textContent ?? "").not.toContain("Claim digest");
  });
});
