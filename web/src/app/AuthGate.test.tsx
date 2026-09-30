// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) — the gated shell. The server's own
 * deny-by-default gate is what actually enforces "no page without a
 * session"; this proves the CLIENT mirrors it honestly: nothing of the
 * children ever renders before a session is confirmed, a deployment with no
 * enrolled user shows the enrolment page rather than a sign-in button for a
 * user that cannot exist yet, and a signed-in render carries a sign-out
 * control.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "./AuthGate";
import { strings as authStrings } from "../views/auth/strings";

afterEach(() => {
  vi.unstubAllGlobals();
});

function respond(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

function routedFetch(
  session: { authenticated: boolean; display_name?: string },
  enrolled: boolean,
) {
  return vi.fn(async (url: string) => {
    if (url.includes("/auth/session")) return respond(session)();
    if (url.includes("/health")) {
      return respond({ database: {}, auth: { enrolled, cannot_write_ledger: {} } })();
    }
    throw new Error(`unexpected fetch ${url}`);
  });
}

describe("AuthGate", () => {
  it("renders nothing of the children while the session check is outstanding", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(authStrings.session.checking);
  });

  it("shows the enrolment page when nobody has ever signed in", async () => {
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, false));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(
      await screen.findByRole("heading", { name: /set up the first passkey/i }),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  it("shows the sign-in page when a user exists but this browser has no session", async () => {
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, true));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(await screen.findByRole("button", { name: /sign in with a passkey/i })).toBeInTheDocument();
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  it("renders the children, with a sign-out control, once a session is confirmed", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch({ authenticated: true, display_name: "Dev Operator" }, true),
    );
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    expect(await screen.findByTestId("protected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });

  it("returns to the sign-in state once the sign-out control is used", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/session")) {
          return respond({ authenticated: true, display_name: "Dev Operator" })();
        }
        if (url.includes("/health")) {
          return respond({ database: {}, auth: { enrolled: true, cannot_write_ledger: {} } })();
        }
        if (url.includes("/auth/logout")) return respond({})();
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    const signOut = await screen.findByRole("button", { name: /sign out/i });
    await userEvent.click(signOut);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /sign in with a passkey/i })).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });
});
