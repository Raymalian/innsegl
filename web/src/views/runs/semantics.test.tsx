// SPDX-License-Identifier: Apache-2.0

/*
 * FE-050 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | The runs table is a real table for a screen reader | Native table,
 *     caption, one column header per column, a row header per row; no element
 *     acquires a table role by being told it has one | FD §3.2, §6.4
 *
 * doc 06 §6.4: "Screen-reader semantics: tables are real tables." doc 06 §3.2
 * calls this view a table in as many words, and the issue calls a grid of divs
 * a defect.
 *
 * The distinction is not cosmetic. A native <table> gives a screen-reader user
 * table-navigation commands, a row and column count, and — through
 * `scope="row"` — the run id spoken again when they land on a status badge
 * four columns in. A div with `role="row"` gives the announcement and none of
 * the navigation, and gets it wrong the first time a wrapper element is added
 * between the role and its children.
 *
 * So this test asserts the ELEMENTS, not only the roles: a role assertion
 * alone would pass over exactly the defect it is meant to catch.
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { RunsTable } from "./RunsTable";
import { runPage, threeRuns } from "./fixtures";
import { strings } from "./strings";

afterEach(cleanup);

const COLUMNS = [
  strings.labels.columns.runId,
  strings.labels.columns.task,
  strings.labels.columns.repo,
  strings.labels.columns.commits,
  strings.labels.columns.status,
];

function mount() {
  const page = runPage();
  return {
    page,
    ...render(<RunsTable runs={page.runs} total={page.total} />),
  };
}

describe("FE-050 the runs table is a table", () => {
  it("is a native <table>, not a div wearing a role", () => {
    const { container } = mount();
    const table = container.querySelector("table");
    expect(table).not.toBeNull();
    expect(screen.getByRole("table").tagName).toBe("TABLE");
    // Nothing anywhere in this view claims a table role it does not have.
    expect(
      container.querySelectorAll(
        '[role="table"],[role="grid"],[role="row"],[role="cell"],[role="gridcell"],[role="columnheader"],[role="rowheader"],[role="rowgroup"]',
      ).length,
    ).toBe(0);
  });

  it("names itself with a caption carrying both exact counts", () => {
    const { container, page } = mount();
    const caption = container.querySelector("caption");
    expect(caption?.textContent).toBe(
      strings.formats.caption(page.runs.length, page.total),
    );
    // A <caption> is the table's accessible name, which is the point of it.
    expect(
      screen.getByRole("table", {
        name: strings.formats.caption(page.runs.length, page.total),
      }),
    ).toBe(container.querySelector("table"));
  });

  it("carries doc 06 §3.2's five columns, in its order, as <th scope=col>", () => {
    const { container } = mount();
    const headers = [...container.querySelectorAll("thead th")];
    expect(headers.map((th) => th.textContent)).toEqual(COLUMNS);
    for (const th of headers) {
      expect(th.tagName).toBe("TH");
      expect(th.getAttribute("scope")).toBe("col");
    }
    expect(screen.getAllByRole("columnheader")).toHaveLength(COLUMNS.length);
  });

  it("gives every row a row header naming the run it is about", () => {
    const { container } = mount();
    const rows = [...container.querySelectorAll("tbody tr")];
    expect(rows).toHaveLength(threeRuns().length);

    for (const [index, row] of rows.entries()) {
      const header = row.querySelector("th");
      expect(header?.getAttribute("scope")).toBe("row");
      expect(header?.textContent).toContain(threeRuns()[index]?.run_id ?? "");
      // Four data cells beside the header: five columns in total.
      expect(row.querySelectorAll("td")).toHaveLength(4);
    }
    expect(screen.getAllByRole("rowheader")).toHaveLength(rows.length);
    // One header row plus the data rows.
    expect(screen.getAllByRole("row")).toHaveLength(rows.length + 1);
  });

  it("renders every run the server returned, in the order it returned them", () => {
    const { container } = mount();
    const ids = [...container.querySelectorAll("tbody tr th")].map(
      (th) => th.textContent ?? "",
    );
    for (const [index, run] of threeRuns().entries()) {
      expect(ids[index]).toContain(run.run_id);
    }
  });

  it("says what an empty repository list is rather than leaving a blank cell", () => {
    mount();
    // The third fixture run touched no repository.
    expect(screen.getByText(strings.labels.table.noRepos)).toBeInTheDocument();
  });
});
