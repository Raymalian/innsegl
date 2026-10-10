// SPDX-License-Identifier: Apache-2.0

/*
 * FE-147 (#480, #481, E28): the members section of the account page. Each
 * organisation's members and roles; for an owner or admin, changing a role
 * and removing a member (each after a passkey), and creating an invitation
 * link (shown once, after a passkey) or withdrawing a pending one. A member
 * sees the list only.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MembersSection } from "./AccountMembers";
import { strings } from "./strings";
import type { AccountOrganisation } from "./types";
import type { WebAuthnBrowser } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

const ORG: AccountOrganisation = { id: "org-1", name: "example-org", role: "owner", operator: true, privileges: [] };
const LINK = "http://localhost:8082/invite#iv_" + "a".repeat(64);

function browser(): WebAuthnBrowser {
  return {
    supported: true,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: (json) => json as never,
      parseRequestOptionsFromJSON: (json) => json as never,
    },
    credentials: {
      create: async () => ({ toJSON: () => ({ id: "cred-1" }) }) as unknown as Credential,
      get: async () => ({ toJSON: () => ({ id: "cred-1" }) }) as unknown as Credential,
    },
  };
}

function install(canManage: boolean) {
  const calls: Array<{ url: string; body: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, body });
      const ok = (b: unknown) => new Response(JSON.stringify(b));
      if (url.includes("/account/members?organisation_id=org-1")) {
        return ok({
          can_manage: canManage,
          members: [
            { user_id: "u-1", display_name: "Ada", role: "owner", since: "2026-09-01T00:00:00Z", you: true },
            { user_id: "u-2", display_name: "Grace", role: "member", since: "2026-09-02T00:00:00Z", you: false },
          ],
          invitations: canManage
            ? [
                { id: 7, role: "admin", state: "pending", created_by: "u-1", accepted_by: "", expires_at: "2026-10-13T00:00:00Z" },
                { id: 6, role: "member", state: "accepted", created_by: "u-1", accepted_by: "u-2", expires_at: "2026-10-12T00:00:00Z" },
              ]
            : [],
        });
      }
      if (url.endsWith("/begin")) return ok({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } });
      if (url.endsWith("/invitations/finish")) {
        return ok({ link: LINK, organisation_id: "org-1", role: "member", expires_at: "2026-10-13T00:00:00Z" });
      }
      if (url.endsWith("/finish") || url.endsWith("/withdraw")) return ok({});
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return calls;
}

describe("FE-147 the members section", () => {
  it("lists members and roles, and offers a member nothing to change", async () => {
    install(false);
    render(<MembersSection organisations={[{ ...ORG, role: "member" }]} browser={browser()} />);
    const region = await screen.findByRole("region", { name: strings.account.membersHeading });
    expect(await within(region).findByText("Grace")).toBeInTheDocument();
    expect(within(region).getByText("Ada")).toBeInTheDocument();
    expect(within(region).queryByRole("button")).toBeNull();
    expect(within(region).queryByRole("combobox")).toBeNull();
  });

  it("changes a role and removes a member, each after a passkey", async () => {
    const calls = install(true);
    const user = userEvent.setup();
    render(<MembersSection organisations={[ORG]} browser={browser()} />);
    const region = await screen.findByRole("region", { name: strings.account.membersHeading });
    await within(region).findByText("Grace");

    await user.selectOptions(within(region).getByLabelText(strings.account.memberRoleLabel("Grace")), "admin");
    await user.click(within(region).getByRole("button", { name: strings.account.memberRoleButton }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/members/role/finish"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/members/role/begin"))?.body).toEqual({
      organisation_id: "org-1", user_id: "u-2", role: "admin",
    });

    await user.click(within(region).getByRole("button", { name: strings.account.memberRemoveButton }));
    await user.click(within(region).getByRole("button", { name: strings.account.memberRemoveConfirmButton }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/members/remove/finish"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/members/remove/begin"))?.body).toEqual({
      organisation_id: "org-1", user_id: "u-2",
    });
    // Nobody is offered a change to their own membership here.
    expect(within(region).getAllByRole("button", { name: strings.account.memberRemoveButton })).toHaveLength(1);
  });

  it("creates an invitation link shown once, and withdraws a pending one", async () => {
    const calls = install(true);
    const user = userEvent.setup();
    render(<MembersSection organisations={[ORG]} browser={browser()} />);
    const region = await screen.findByRole("region", { name: strings.account.membersHeading });
    await within(region).findByText("Grace");

    await user.selectOptions(within(region).getByLabelText(strings.account.inviteRoleLabel), "member");
    await user.click(within(region).getByRole("button", { name: strings.account.inviteButton }));
    expect(await within(region).findByText(LINK)).toBeInTheDocument();
    expect(calls.find((c) => c.url.endsWith("/invitations/begin"))?.body).toEqual({
      organisation_id: "org-1", role: "member",
    });

    expect(within(region).getAllByRole("button", { name: strings.account.inviteWithdrawButton })).toHaveLength(1);
    await user.click(within(region).getByRole("button", { name: strings.account.inviteWithdrawButton }));
    await waitFor(() =>
      expect(calls.find((c) => c.url.endsWith("/invitations/withdraw"))?.body).toEqual({
        organisation_id: "org-1", invitation_id: 7,
      }),
    );
  });

  it("no longer says members are managed elsewhere", () => {
    expect(strings.account.privilegeNotes.manage_members).not.toMatch(/not on the dashboard/i);
  });
});
