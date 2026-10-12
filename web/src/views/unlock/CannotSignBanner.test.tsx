// SPDX-License-Identifier: Apache-2.0

/*
 * FE-158, component half (E34 follow-up to #616): the "CA cannot sign"
 * banner the app shell mounts once, above every page. Only an owner or admin
 * of the operator's organisation sees it; it links to /account?unlock; it
 * keeps out of the way while the unlock page is open. The Playwright half
 * (web/tests/auth/step-up.pw.ts) shows it on two pages of the real app.
 */

import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CannotSignBanner, custodyChangedEvent } from "./CannotSignBanner";
import { strings } from "./strings";

const LOCKED = { enabled: true, initialized: true, sealed: true, can_sign: false, reason: "the store is sealed" };
const SIGNING = { enabled: true, initialized: true, sealed: false, can_sign: true };

function install(role: string, operator: boolean, custody: () => unknown) {
  const urls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      urls.push(url);
      if (url.endsWith("/auth/session")) {
        return new Response(
          JSON.stringify({
            authenticated: true,
            display_name: "Dev Operator",
            organisations: [{ id: "org-1", name: "example-org", role, operator }],
          }),
        );
      }
      if (url.endsWith("/account/ca-custody")) return new Response(JSON.stringify(custody()));
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return urls;
}

beforeEach(() => {
  window.history.replaceState(null, "", "/runs");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FE-158 the cannot-sign banner on every page", () => {
  it.each([["owner"], ["admin"]])("shows an operator %s the banner, linking to the unlock page", async (role) => {
    install(role, true, () => LOCKED);
    render(<CannotSignBanner />);
    expect(await screen.findByText(strings.banner.title)).toBeInTheDocument();
    expect(screen.getByText(strings.banner.reason("the store is sealed"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: strings.banner.action })).toHaveAttribute("href", "/account?unlock");
  });

  it.each([
    ["a member of the operator's organisation", "member", true],
    ["an owner of another organisation", "owner", false],
  ])("shows %s nothing, and never asks for the custodian's status", async (_who, role, operator) => {
    const urls = install(role, operator, () => LOCKED);
    render(<CannotSignBanner />);
    await waitFor(() => expect(urls.some((u) => u.endsWith("/auth/session"))).toBe(true));
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText(strings.banner.title)).toBeNull();
    expect(urls.some((u) => u.endsWith("/account/ca-custody"))).toBe(false);
  });

  it("shows nothing while the CA can sign, or with custody off", async () => {
    let custody: unknown = SIGNING;
    const urls = install("owner", true, () => custody);
    const { rerender } = render(<CannotSignBanner />);
    await waitFor(() => expect(urls.some((u) => u.endsWith("/account/ca-custody"))).toBe(true));
    expect(screen.queryByText(strings.banner.title)).toBeNull();
    custody = { ...LOCKED, enabled: false };
    rerender(<CannotSignBanner />);
    expect(screen.queryByText(strings.banner.title)).toBeNull();
  });

  it("keeps out of the way on the unlock page, and goes when an unlock is reported", async () => {
    let custody: unknown = LOCKED;
    install("owner", true, () => custody);
    window.history.replaceState(null, "", "/account?unlock");
    render(<CannotSignBanner />);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText(strings.banner.title)).toBeNull();

    act(() => {
      window.history.pushState(null, "", "/runs");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    expect(await screen.findByText(strings.banner.title)).toBeInTheDocument();

    custody = SIGNING;
    act(() => {
      window.dispatchEvent(new Event(custodyChangedEvent));
    });
    await waitFor(() => expect(screen.queryByText(strings.banner.title)).toBeNull());
  });
});
