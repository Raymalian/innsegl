// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) and #445 — the gated shell. The server's own
 * deny-by-default gate is what actually enforces "no page without a
 * session"; this proves the CLIENT mirrors it honestly: nothing of the
 * children ever renders before a session is confirmed, a deployment with no
 * account yet shows the setup page at /setup and a no-account notice
 * everywhere else, and a signed-in render carries the account-name link and
 * sign-out control.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "./AuthGate";
import { strings as authStrings } from "../views/auth/strings";

beforeEach(() => {
  window.history.replaceState(null, "", "/");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function respond(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

function routedFetch(
  session: { authenticated: boolean; display_name?: string },
  setupNeeded: boolean,
) {
  return vi.fn(async (url: string) => {
    if (url.includes("/auth/session")) return respond(session)();
    if (url.includes("/auth/setup")) return respond({ needed: setupNeeded })();
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

  it("says there is no account yet, at the root address, when nobody has ever signed in", async () => {
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, true));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(
      await screen.findByRole("heading", { name: authStrings.signIn.noAccountHeading }),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  it("shows the setup page, reading the code off the URL, when a setup link is opened", async () => {
    window.history.replaceState(null, "", "/setup?code=the-one-time-code");
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, true));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(
      await screen.findByRole("heading", { name: authStrings.setup.heading }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(authStrings.setup.displayNameLabel)).toBeInTheDocument();
  });

  it("says a setup link is needed at /setup with no code", async () => {
    window.history.replaceState(null, "", "/setup");
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, true));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(
      await screen.findByRole("heading", { name: authStrings.setup.missingCodeHeading }),
    ).toBeInTheDocument();
  });

  it("shows the sign-in page when a user exists but this browser has no session", async () => {
    vi.stubGlobal("fetch", routedFetch({ authenticated: false }, false));
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);

    expect(await screen.findByRole("button", { name: /sign in with a passkey/i })).toBeInTheDocument();
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  it("renders the children, with the account name and a sign-out control, once a session is confirmed", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch({ authenticated: true, display_name: "Dev Operator" }, false),
    );
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    expect(await screen.findByTestId("protected")).toBeInTheDocument();
    const menuButton = screen.getByRole("button", { name: "Dev Operator" });
    expect(menuButton).toHaveAttribute("aria-haspopup", "menu");
    expect(menuButton).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  // RM-333 (#511): the account name opens a menu with Account and Sign out.
  it("opens the account menu on click, with Account linking to /account and Sign out", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch({ authenticated: true, display_name: "Dev Operator" }, false),
    );
    const user = userEvent.setup();
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    const menuButton = await screen.findByRole("button", { name: "Dev Operator" });
    await user.click(menuButton);
    expect(menuButton).toHaveAttribute("aria-expanded", "true");
    const menu = screen.getByRole("menu");
    const items = within(menu).getAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual(["Account", "Sign out"]);
    expect(items[0]).toHaveAttribute("href", "/account");

    await user.click(items[0]!);
    expect(window.location.pathname).toBe("/account");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("works the account menu from the keyboard: ArrowDown opens on the first item, arrows move, Escape returns focus", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch({ authenticated: true, display_name: "Dev Operator" }, false),
    );
    const user = userEvent.setup();
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    const menuButton = await screen.findByRole("button", { name: "Dev Operator" });
    menuButton.focus();
    await user.keyboard("{ArrowDown}");
    const items = within(screen.getByRole("menu")).getAllByRole("menuitem");
    expect(items[0]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(items[1]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(items[0]).toHaveFocus();
    await user.keyboard("{ArrowUp}");
    expect(items[1]).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(menuButton).toHaveFocus();

    await user.keyboard("{Enter}");
    expect(within(screen.getByRole("menu")).getAllByRole("menuitem")[0]).toHaveFocus();
  });

  it("closes the account menu on a click outside it", async () => {
    vi.stubGlobal(
      "fetch",
      routedFetch({ authenticated: true, display_name: "Dev Operator" }, false),
    );
    const user = userEvent.setup();
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    await user.click(await screen.findByRole("button", { name: "Dev Operator" }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.click(screen.getByTestId("protected"));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  // The account name and sign-out are one control cluster, named for a
  // screen reader, rather than two loose words in the header.
  it("groups the account name and sign-out under one named group", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/session")) {
          return respond({ authenticated: true, display_name: "Dev Operator" })();
        }
        if (url.includes("/auth/setup")) return respond({ needed: false })();
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    render(<AuthGate>{(account) => <div>{account}dashboard</div>}</AuthGate>);
    const group = await screen.findByRole("group", { name: /account/i });
    expect(within(group).getByRole("button", { name: "Dev Operator" })).toBeInTheDocument();
  });

  it("returns to the sign-in state once the sign-out control is used", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/session")) {
          return respond({ authenticated: true, display_name: "Dev Operator" })();
        }
        if (url.includes("/auth/setup")) return respond({ needed: false })();
        if (url.includes("/auth/logout")) return respond({})();
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    await userEvent.click(await screen.findByRole("button", { name: "Dev Operator" }));
    await userEvent.click(screen.getByRole("menuitem", { name: /sign out/i }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /sign in with a passkey/i })).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  it("signs in with a recovery code and lands on /account with the notice flag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes("/auth/session")) return respond({ authenticated: false })();
        if (url.includes("/auth/setup")) return respond({ needed: false })();
        if (url.includes("/auth/recover")) {
          expect(JSON.parse(String(init?.body))).toEqual({ code: "the-recovery-code" });
          return respond({ authenticated: true, display_name: "Dev Operator", remaining: 9 })();
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const user = userEvent.setup();
    render(<AuthGate>{(account) => <div data-testid="protected">{account}dashboard</div>}</AuthGate>);

    await user.click(
      await screen.findByRole("button", { name: authStrings.signIn.recoveryLink }),
    );
    await user.type(
      screen.getByLabelText(authStrings.signIn.recoveryLabel),
      "the-recovery-code",
    );
    await user.click(screen.getByRole("button", { name: authStrings.signIn.recoveryButton }));

    await waitFor(() => expect(screen.getByTestId("protected")).toBeInTheDocument());
    expect(window.location.pathname).toBe("/account");
  });
});
