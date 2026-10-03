// SPDX-License-Identifier: Apache-2.0

/* An active run silent past the idle bound reads "Idle", in words, with
 * its meaning spoken; the ledger state on the element stays "active". */

import { render, screen } from "@testing-library/react";

import { StatusBadge } from "./StatusBadge";
import { strings } from "./strings";

describe("StatusBadge idle", () => {
  it("says Idle for an idle active run", () => {
    render(<StatusBadge status="active" idle />);
    const badge = screen.getByText(strings.idle.label).closest("[data-status]");
    expect(badge).toHaveAttribute("data-status", "active");
    expect(badge).toHaveAttribute("data-idle", "true");
    expect(badge).toHaveAttribute("title", strings.idle.meaning);
  });

  it("ignores idle on a run that is not active", () => {
    render(<StatusBadge status="retired" idle />);
    expect(screen.queryByText(strings.idle.label)).not.toBeInTheDocument();
  });
});
