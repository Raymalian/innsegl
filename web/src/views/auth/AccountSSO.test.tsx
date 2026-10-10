// SPDX-License-Identifier: Apache-2.0

/*
 * FE-150 (#485, E30): the account page's organisation sign-in section. An
 * owner sets the organisation's sign-in (saved after a passkey; the secret
 * is never shown back, only whether one is saved) and removes it. Every
 * member connects it to their own account, which sends the browser to the
 * provider; connected sign-ins are listed and can be disconnected.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OrganisationSignInSection } from "./AccountSSO";
import { strings } from "./strings";
import type { AccountOrganisation, AccountSignIn } from "./types";
import type { WebAuthnBrowser } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

const a = strings.account;
const ORG: AccountOrganisation = { id: "org-1", name: "example-org", role: "owner", operator: true, privileges: [] };
const REDIRECT = "http://localhost:8082/api/v1/auth/sso/callback";

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

function install(view: Record<string, unknown>) {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, method: init?.method ?? "GET", body });
      const ok = (b: unknown) => new Response(JSON.stringify(b));
      if (url.includes("/account/sso?organisation_id=org-1")) return ok({ organisation_id: "org-1", ...view });
      if (url.endsWith("/begin")) return ok({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } });
      if (url.endsWith("/configure/finish")) return ok({ organisation_id: "org-1", configured: true, can_manage: true });
      if (url.endsWith("/finish")) return ok({ sessions_revoked: 2 });
      if (url.endsWith("/account/sso/link")) return ok({ redirect_url: "https://idp.example.test/authorize?state=s" });
      if (url.includes("/account/sign-ins/")) return ok({});
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return calls;
}

describe("FE-150 the organisation sign-in section", () => {
  it("lets the owner save the sign-in after a passkey, showing the redirect URI and never the secret", async () => {
    const calls = install({
      configured: true, sign_in_name: "example-org", issuer: "https://idp.example.test", client_id: "dash",
      has_client_secret: true, redirect_uri: REDIRECT, can_manage: true,
    });
    render(<OrganisationSignInSection organisations={[ORG]} signIns={[]} browser={browser()} reload={() => {}} goTo={() => {}} />);
    const region = await screen.findByRole("region", { name: a.ssoHeading });
    expect(await within(region).findByText(REDIRECT)).toBeInTheDocument();
    expect(within(region).getByLabelText(a.ssoIssuerLabel)).toHaveValue("https://idp.example.test");
    const secret = within(region).getByLabelText(a.ssoSecretLabel);
    expect(secret).toHaveValue("");
    expect(within(region).getByText(a.ssoSecretKeepHint)).toBeInTheDocument();

    await userEvent.clear(within(region).getByLabelText(a.ssoClientLabel));
    await userEvent.type(within(region).getByLabelText(a.ssoClientLabel), "dash-2");
    await userEvent.click(within(region).getByRole("button", { name: a.ssoSaveButton }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/account/sso/configure/finish"))).toBe(true));
    const begin = calls.find((c) => c.url.endsWith("/account/sso/configure/begin"));
    expect(begin?.body).toEqual({
      organisation_id: "org-1", sign_in_name: "example-org", issuer: "https://idp.example.test",
      client_id: "dash-2", client_secret: "", keep_secret: true,
    });
    expect(await within(region).findByText(a.ssoSaved)).toBeInTheDocument();
  });

  it("asks before removing, then removes after a passkey", async () => {
    const calls = install({
      configured: true, sign_in_name: "example-org", issuer: "https://idp.example.test", client_id: "dash",
      has_client_secret: false, redirect_uri: REDIRECT, can_manage: true,
    });
    render(<OrganisationSignInSection organisations={[ORG]} signIns={[]} browser={browser()} reload={() => {}} goTo={() => {}} />);
    const region = await screen.findByRole("region", { name: a.ssoHeading });
    await userEvent.click(await within(region).findByRole("button", { name: a.ssoRemoveButton }));
    expect(within(region).getByText(a.ssoRemovePrompt)).toBeInTheDocument();
    await userEvent.click(within(region).getByRole("button", { name: a.ssoRemoveConfirmButton }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/account/sso/remove/finish"))).toBe(true));
  });

  it("shows a member the sign-in's name and a connect button that goes to the provider; no settings", async () => {
    const calls = install({ configured: true, sign_in_name: "example-org", has_client_secret: false, can_manage: false });
    const go = vi.fn();
    render(
      <OrganisationSignInSection
        organisations={[{ ...ORG, role: "member" }]}
        signIns={[]}
        browser={browser()}
        reload={() => {}}
        goTo={go}
      />,
    );
    const region = await screen.findByRole("region", { name: a.ssoHeading });
    expect(await within(region).findByText(a.ssoSignInName("example-org"))).toBeInTheDocument();
    expect(within(region).queryByLabelText(a.ssoIssuerLabel)).not.toBeInTheDocument();
    await userEvent.click(within(region).getByRole("button", { name: a.ssoConnectButton }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("https://idp.example.test/authorize?state=s"));
    expect(calls.find((c) => c.url.endsWith("/account/sso/link"))?.body).toEqual({ organisation_id: "org-1" });
  });

  it("lists connected sign-ins and disconnects one", async () => {
    const calls = install({ configured: true, sign_in_name: "example-org", has_client_secret: false, can_manage: false });
    const linked: AccountSignIn[] = [
      { id: 7, organisation: "example-org", sign_in_name: "example-org", linked_at: "2026-10-01T00:00:00Z", last_used_at: null },
    ];
    const reload = vi.fn();
    render(
      <OrganisationSignInSection
        organisations={[{ ...ORG, role: "member" }]}
        signIns={linked}
        browser={browser()}
        reload={reload}
        goTo={() => {}}
      />,
    );
    const region = await screen.findByRole("region", { name: a.ssoHeading });
    expect(within(region).getByText(a.ssoLinkedItem("example-org", "example-org"))).toBeInTheDocument();
    expect(await within(region).findByText(a.ssoConnected)).toBeInTheDocument();
    expect(within(region).queryByRole("button", { name: a.ssoConnectButton })).not.toBeInTheDocument();
    await userEvent.click(within(region).getByRole("button", { name: a.ssoDisconnectButton }));
    await waitFor(() => expect(reload).toHaveBeenCalled());
    expect(calls.find((c) => c.url.includes("/account/sign-ins/7"))?.method).toBe("DELETE");
  });

  it("says plainly when no organisation sign-in is set up", async () => {
    install({ configured: false, has_client_secret: false, can_manage: false });
    render(
      <OrganisationSignInSection
        organisations={[{ ...ORG, role: "member" }]}
        signIns={[]}
        browser={browser()}
        reload={() => {}}
        goTo={() => {}}
      />,
    );
    const region = await screen.findByRole("region", { name: a.ssoHeading });
    expect(await within(region).findByText(a.ssoNotConfigured)).toBeInTheDocument();
  });
});
