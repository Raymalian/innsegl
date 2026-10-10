// SPDX-License-Identifier: Apache-2.0

/*
 * FE-142 (RM-307, #486): a person in several organisations sees all of them
 * at once or picks one. The choice is the innsegl_organisation cookie, which
 * the query API reads on every request (internal/api/scope.go), so every
 * view reloads its own reads under the new scope. One organisation: no
 * switcher at all.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "./AuthGate";
import { en as strings } from "./strings";

const A = { id: "a".repeat(32), name: "example-org", role: "owner", operator: true };
const B = { id: "b".repeat(32), name: "example-team", role: "member", operator: false };

function clearCookie() {
  document.cookie = "innsegl_organisation=; Path=/; Max-Age=0";
}

beforeEach(() => {
  window.history.replaceState(null, "", "/");
  clearCookie();
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearCookie();
});

function signedIn(organisations: unknown[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/auth/session")) {
        return new Response(
          JSON.stringify({ authenticated: true, display_name: "Ada", organisations }),
        );
      }
      if (url.includes("/auth/setup")) return new Response(JSON.stringify({ needed: false }));
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
}

let mounts = 0;
function Dashboard() {
  mounts += 1;
  return <div data-testid="protected">the dashboard</div>;
}

function gate() {
  return render(
    <AuthGate>
      {(account) => (
        <>
          {account}
          <Dashboard />
        </>
      )}
    </AuthGate>,
  );
}

describe("FE-142 the organisation switcher", () => {
  it("is absent for a person in one organisation", async () => {
    signedIn([A]);
    gate();
    await screen.findByTestId("protected");
    expect(
      screen.queryByRole("combobox", { name: strings.labels.header.organisation }),
    ).not.toBeInTheDocument();
  });

  it("offers every organisation and all of them, and a choice narrows every read", async () => {
    signedIn([A, B]);
    gate();
    const select = await screen.findByRole("combobox", { name: strings.labels.header.organisation });
    expect(screen.getByRole("option", { name: strings.labels.header.allOrganisations })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "example-org" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "example-team" })).toBeInTheDocument();
    expect(select).toHaveValue("");

    const before = mounts;
    await userEvent.selectOptions(select, B.id);
    expect(document.cookie).toContain(`innsegl_organisation=${B.id}`);
    await waitFor(() => expect(mounts).toBeGreaterThan(before));

    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: strings.labels.header.organisation }),
      "",
    );
    expect(document.cookie).not.toContain("innsegl_organisation=");
  });

  it("starts from the choice the cookie holds", async () => {
    document.cookie = `innsegl_organisation=${B.id}; Path=/`;
    signedIn([A, B]);
    gate();
    expect(
      await screen.findByRole("combobox", { name: strings.labels.header.organisation }),
    ).toHaveValue(B.id);
  });
});
