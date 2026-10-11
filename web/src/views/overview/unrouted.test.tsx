// SPDX-License-Identifier: Apache-2.0

/*
 * FE-152 (RM-319, #579): the overview lists the sessions enrolled machines
 * reported as sending model traffic that bypassed innsegl. They are
 * `GET /api/v1/overview`'s `unrouted_sessions`; nothing renders when there
 * are none, and an older query API that sends no list renders nothing too.
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { UnroutedNotice } from "./UnroutedNotice";
import { strings } from "./strings";

afterEach(cleanup);

describe("FE-152 sessions that bypassed innsegl", () => {
  it("names each session, its machine and its last activity", () => {
    render(
      <UnroutedNotice
        sessions={[
          {
            installation_id: "11111111111111111111111111111111",
            session_id: "s-unrouted",
            first_reported_at: "2026-10-11T05:00:00Z",
            last_activity_at: "2026-10-11T05:01:00Z",
          },
        ]}
      />,
    );
    expect(screen.getByRole("region", { name: strings.unrouted.regionLabel })).toBeTruthy();
    expect(
      screen.getByText(
        strings.unrouted.line("s-unrouted", "11111111111111111111111111111111", "2026-10-11 05:01 UTC"),
      ),
    ).toBeTruthy();
  });

  it("renders nothing when there are none", () => {
    const { container } = render(<UnroutedNotice sessions={[]} />);
    expect(container.textContent).toBe("");
  });

  it("renders nothing when the query API sent no list", () => {
    const { container } = render(<UnroutedNotice sessions={undefined} />);
    expect(container.textContent).toBe("");
  });
});
