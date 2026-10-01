// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { AskedTo, ReportedBack } from "./AskedReported";

const asked = {
  text: "You are implementing issue #309. Read it: `gh issue view 309`.\n\n## The problem\nThe health response names repositories.",
  available: true,
  step: 0,
};

const report = {
  text: [
    "**#309 is fixed and tested but not committed.** The signing script refused.",
    "",
    "**What read the list:** nothing in the dashboard.",
    "- `cmd/innsegl/apiintegration_test.go:392` asserts the field.",
    "- `test/deploy/readerrole_test.go:466` declares it.",
    "",
    "Both packages still pass `go vet`.",
    "",
    "The two files are still staged.",
  ].join("\n"),
  available: true,
  step: 15,
};

describe("#443 the agent's messages read as text, not markdown source", () => {
  it("renders a heading and inline code without their markers", () => {
    render(<AskedTo asked={asked} />);
    expect(screen.getByText("gh issue view 309")).toBeInTheDocument();
    expect(screen.queryByText(/##/)).toBeNull();
    expect(screen.queryByText(/`/)).toBeNull();
  });

  it("shows the start of a long report, and all of it on request", async () => {
    render(<ReportedBack reported={report} />);
    expect(screen.getByText("#309 is fixed and tested but not committed.")).toBeInTheDocument();
    expect(screen.queryByText("The two files are still staged.")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Show all \d+ lines/ }));
    expect(screen.getByText("The two files are still staged.")).toBeInTheDocument();
    expect(screen.getByRole("list")).toBeInTheDocument();
  });
});
