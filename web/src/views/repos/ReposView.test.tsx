// SPDX-License-Identifier: Apache-2.0

/*
 * The repositories index: each repository with its last activity, runs and
 * commits, read from GET /api/v1/repos.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ReposView } from "./ReposView";
import { strings } from "./strings";
import type { LoadRepos, RepoList } from "./query";

const LIST: RepoList = {
  repos: [
    {
      repo: "github.com/acme/api",
      runs: 12,
      commits: 31,
      last_event_at: "2026-08-30T09:15:00Z",
    },
    {
      repo: "github.com/acme/web",
      runs: 3,
      commits: 0,
      last_event_at: "2026-08-12T17:40:00Z",
    },
  ],
  data_as_of: "2026-08-31T12:00:00Z",
};

function renderList(result: RepoList | Error) {
  const load: LoadRepos = () =>
    result instanceof Error ? Promise.reject(result) : Promise.resolve(result);
  return render(<ReposView load={load} />);
}

describe("the repositories index", () => {
  it("is one table with a row per repository", async () => {
    renderList(LIST);
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    for (const label of [
      strings.labels.repository,
      strings.labels.lastActivity,
      strings.labels.runs,
      strings.labels.commits,
    ]) {
      expect(within(table).getByRole("columnheader", { name: label })).toBeInTheDocument();
    }
  });

  it("links each repository to its own page", async () => {
    renderList(LIST);
    const link = await screen.findByRole("link", { name: "github.com/acme/api" });
    expect(link).toHaveAttribute("href", "/repos/github.com%2Facme%2Fapi");
  });

  it("prints runs, commits and the last activity as an absolute time", async () => {
    renderList(LIST);
    const row = (await screen.findByRole("link", { name: "github.com/acme/api" })).closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText("12")).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText("31")).toBeInTheDocument();
    expect(
      within(row as HTMLElement).getByText("2026-08-30 09:15:00 UTC", { selector: "time" }),
    ).toBeInTheDocument();
  });

  it("keeps the server's order, most recently active first", async () => {
    renderList(LIST);
    await screen.findByRole("table");
    const names = screen.getAllByRole("link").map((l) => l.textContent);
    expect(names).toEqual(["github.com/acme/api", "github.com/acme/web"]);
  });

  it("says what it is loading", () => {
    render(<ReposView load={() => new Promise<RepoList>(() => {})} />);
    expect(screen.getByRole("status")).toHaveTextContent(strings.nouns.repos);
  });

  it("states the failure rather than drawing an empty table", async () => {
    renderList(new Error("dial tcp: connection refused"));
    expect(await screen.findByRole("alert")).toHaveTextContent("dial tcp: connection refused");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says so when no repository has been recorded", async () => {
    renderList({ repos: [], data_as_of: LIST.data_as_of });
    expect(await screen.findByText(strings.sentences.empty)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });
});
