// SPDX-License-Identifier: Apache-2.0

/*
 * #445 (ADR-0062's accounts amendment) — the account page: profile name
 * editable inline, every passkey with rename/remove (the last one guarded),
 * adding a passkey via the same WebAuthn ceremony enrolment uses, and
 * recovery-code generation through the save step SetupPage also uses.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AccountPage } from "./AccountPage";
import { strings } from "./strings";
import type { Account } from "./types";
import type { WebAuthnBrowser } from "./client";

function account(overrides: Partial<Account> = {}): Account {
  return {
    user_id: "user-1",
    display_name: "Dev Operator",
    created_at: "2026-09-01T00:00:00Z",
    passkeys: [
      {
        id: "pk-1",
        name: "MacBook",
        created_at: "2026-09-01T00:00:00Z",
        last_used_at: "2026-09-30T00:00:00Z",
        current: true,
      },
      {
        id: "pk-2",
        name: "Phone",
        created_at: "2026-09-10T00:00:00Z",
        last_used_at: null,
        current: false,
      },
    ],
    recovery_codes_remaining: 8,
    ...overrides,
  };
}

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function workingBrowser(): WebAuthnBrowser {
  return {
    supported: true,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: (json) => json as never,
      parseRequestOptionsFromJSON: (json) => json as never,
    },
    credentials: {
      create: async () => ({ toJSON: () => ({ id: "cred-new" }) }) as unknown as Credential,
      get: async () => ({ toJSON: () => ({ id: "cred-new" }) }) as unknown as Credential,
    },
  };
}

/** Routes every request this page can make against one in-memory account,
 * so a mutation's effect is visible on the next GET — the same "the real
 * server would do this" level of fidelity Playwright's page.route mocks
 * give, kept here so this file does not have to hand-wire call counts. */
function installAccountFetch(initial: Account) {
  let current = initial;
  const calls: Array<{ url: string; method: string; body: unknown }> = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, method, body });

      if (url.endsWith("/api/v1/account") && method === "GET") {
        return respond(current);
      }
      if (url.endsWith("/api/v1/account") && method === "PATCH") {
        current = { ...current, display_name: (body as { display_name: string }).display_name };
        return respond(current);
      }
      const renameMatch = /\/api\/v1\/account\/passkeys\/([^/]+)$/.exec(url);
      if (renameMatch && method === "PATCH") {
        const id = renameMatch[1];
        current = {
          ...current,
          passkeys: current.passkeys.map((p) =>
            p.id === id ? { ...p, name: (body as { name: string }).name } : p,
          ),
        };
        return respond(current.passkeys.find((p) => p.id === id));
      }
      if (renameMatch && method === "DELETE") {
        const id = renameMatch[1];
        if (current.passkeys.length <= 1) {
          return respond({ error: { code: "conflict", message: "the last passkey cannot be removed" } }, 409);
        }
        current = { ...current, passkeys: current.passkeys.filter((p) => p.id !== id) };
        return respond({});
      }
      if (url.endsWith("/account/passkeys/begin") && method === "POST") {
        return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } });
      }
      if (url.endsWith("/account/passkeys/finish") && method === "POST") {
        const added = {
          id: "pk-new",
          name: "Passkey 3",
          created_at: "2026-10-01T00:00:00Z",
          last_used_at: null,
          current: false,
        };
        current = { ...current, passkeys: [...current.passkeys, added] };
        return respond(added);
      }
      if (url.endsWith("/account/recovery-codes") && method === "POST") {
        current = { ...current, recovery_codes_remaining: 10 };
        return respond({ codes: Array.from({ length: 10 }, (_, i) => `new-code-${i}`) });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    }),
  );

  return { calls, current: () => current };
}

beforeEach(() => {
  window.history.replaceState(null, "", "/account");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AccountPage", () => {
  it("loads and shows the profile name, every passkey, and codes remaining", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    expect(await screen.findByText("Dev Operator")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: strings.account.passkeyNameHeader })).toBeInTheDocument();
    expect(screen.getByText("MacBook")).toBeInTheDocument();
    expect(screen.getByText("Phone")).toBeInTheDocument();
    expect(screen.getByText(strings.account.currentDevice)).toBeInTheDocument();
    expect(screen.getByText(strings.account.passkeyNeverUsed)).toBeInTheDocument();
    expect(screen.getByText(`8 ${strings.account.recoveryOf}`)).toBeInTheDocument();
  });

  it("edits and saves the display name inline", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await user.click(await screen.findByRole("button", { name: strings.account.editButton }));
    const input = screen.getByDisplayValue("Dev Operator");
    await user.clear(input);
    await user.type(input, "New Name");
    await user.click(screen.getByRole("button", { name: strings.account.saveButton }));

    await waitFor(() => expect(screen.getByText("New Name")).toBeInTheDocument());
    expect(fetches.current().display_name).toBe("New Name");
  });

  it("renames a passkey inline", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    const macRow = screen.getByText("MacBook").closest("tr");
    if (macRow === null) throw new Error("no row for MacBook");
    await user.click(within(macRow).getByRole("button", { name: strings.account.renameButton }));
    const input = within(macRow).getByDisplayValue("MacBook");
    await user.clear(input);
    await user.type(input, "Work laptop");
    await user.click(within(macRow).getByRole("button", { name: strings.account.saveButton }));

    await waitFor(() => expect(screen.getByText("Work laptop")).toBeInTheDocument());
  });

  it("removes a passkey after a confirm step, when it is not the last one", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("Phone");
    const phoneRow = screen.getByText("Phone").closest("tr");
    if (phoneRow === null) throw new Error("no row for Phone");
    await user.click(within(phoneRow).getByRole("button", { name: strings.account.removeButton }));
    expect(within(phoneRow).getByText(strings.account.removeConfirmPrompt)).toBeInTheDocument();
    await user.click(within(phoneRow).getByRole("button", { name: strings.account.removeConfirmButton }));

    await waitFor(() => expect(screen.queryByText("Phone")).not.toBeInTheDocument());
  });

  it("disables Remove, with a tooltip, on the account's last passkey", async () => {
    installAccountFetch(account({ passkeys: [account().passkeys[0]!] }));
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    const row = screen.getByText("MacBook").closest("tr");
    if (row === null) throw new Error("no row for MacBook");
    const remove = within(row).getByRole("button", { name: strings.account.removeButton });
    expect(remove).toBeDisabled();
    expect(remove).toHaveAttribute("title", strings.account.removeLastTooltip);
  });

  it("adds a passkey through the WebAuthn ceremony, defaulting its name", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    expect(screen.getByDisplayValue("Passkey 3")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.account.addButton }));

    await waitFor(() => expect(screen.getByText("Passkey 3")).toBeInTheDocument());
  });

  it("generates new recovery codes after a confirm step, then returns to the remaining count", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText(`8 ${strings.account.recoveryOf}`);
    await user.click(screen.getByRole("button", { name: strings.account.regenerateButton }));
    expect(screen.getByText(strings.account.regenerateConfirmPrompt)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.account.regenerateConfirmButton }));

    expect(
      await screen.findByRole("heading", { name: strings.recoveryCodes.heading }),
    ).toBeInTheDocument();
    expect(screen.getByText("new-code-0")).toBeInTheDocument();

    await user.click(
      screen.getByRole("checkbox", { name: strings.recoveryCodes.savedCheckbox }),
    );
    await user.click(screen.getByRole("button", { name: strings.recoveryCodes.continueButton }));

    expect(await screen.findByText(`10 ${strings.account.recoveryOf}`)).toBeInTheDocument();
  });

  it("shows the recovery-sign-in notice once, then drops the query from the address", async () => {
    window.history.replaceState(null, "", "/account?notice=recovery-signin");
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    expect(
      await screen.findByText(new RegExp(strings.account.recoverySignInNotice)),
    ).toBeInTheDocument();
    await waitFor(() => expect(window.location.search).toBe(""));
  });

  it("shows a load failure as an alert", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond({ error: { code: "unauthorized", message: "no session" } }, 401)),
    );
    render(<AccountPage browser={workingBrowser()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("no session");
  });
});
