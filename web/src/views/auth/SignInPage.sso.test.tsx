// SPDX-License-Identifier: Apache-2.0

/*
 * FE-149 (#485, E30): "Sign in with your organisation" on the sign-in page.
 * A third view beside the passkey and the recovery code: the organisation's
 * sign-in name, then the browser goes to the provider the server named. A
 * sign-in the server sent back with ?sso=<reason> says why, in one sentence.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SignInPage } from "./SignInPage";
import { strings } from "./strings";

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

const PROVIDER = "https://idp.example.test/authorize?state=abc";

describe("FE-149 signing in with your organisation", () => {
  it("asks for the sign-in name and sends the browser to the organisation's provider", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url, body: init?.body === undefined ? undefined : JSON.parse(String(init.body)) });
        return new Response(JSON.stringify({ redirect_url: PROVIDER }));
      }),
    );
    const go = vi.fn();
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} goTo={go} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.ssoLink }));
    expect(screen.getByRole("heading", { name: strings.signIn.ssoHeading })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: strings.signIn.button })).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText(strings.signIn.ssoLabel), " example-org ");
    await userEvent.click(screen.getByRole("button", { name: strings.signIn.ssoButton }));

    await waitFor(() => expect(go).toHaveBeenCalledWith(PROVIDER));
    expect(calls).toEqual([{ url: "/api/v1/auth/sso/begin", body: { sign_in_name: "example-org" } }]);
  });

  it("says so when no organisation sign-in has that name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ error: { code: "not_found", message: "no organisation sign-in is set up under that name" } }), {
          status: 404,
        }),
      ),
    );
    const go = vi.fn();
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} goTo={go} />);
    await userEvent.click(screen.getByRole("button", { name: strings.signIn.ssoLink }));
    await userEvent.type(screen.getByLabelText(strings.signIn.ssoLabel), "nobody");
    await userEvent.click(screen.getByRole("button", { name: strings.signIn.ssoButton }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no organisation sign-in is set up under that name");
    expect(go).not.toHaveBeenCalled();
  });

  it("says why a sign-in came back refused, once, and keeps the passkey button", () => {
    window.history.replaceState(null, "", "/?sso=removed");
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent(strings.ssoReasons["removed"] ?? "");
    expect(screen.getByRole("button", { name: strings.signIn.button })).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });

  it("words an unknown reason as the generic one, never echoing the URL", () => {
    window.history.replaceState(null, "", "/?sso=%3Cscript%3E");
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent(strings.ssoReasons["internal"] ?? "");
    expect(screen.getByRole("alert")).not.toHaveTextContent("script");
  });
});
