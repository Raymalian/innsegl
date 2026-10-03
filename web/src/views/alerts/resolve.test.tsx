// SPDX-License-Identifier: Apache-2.0

/*
 * RM-330 (#506), ADR-0044's 2026-10-03 amendment — resolving from the
 * dashboard.
 *
 * The form takes a reason, then asks for a passkey: begin names the alerts
 * and the reason, the browser signs the challenge, finish writes. Nothing is
 * resolved without the passkey, and a refusal is shown in the server's own
 * words rather than as a generic failure.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WebAuthnBrowser } from "../auth/client";
import { ResolveForm } from "./ResolveForm";
import { strings } from "./strings";

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function browser(overrides: Partial<WebAuthnBrowser> = {}): WebAuthnBrowser {
  return {
    supported: true,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: (json) => json as never,
      parseRequestOptionsFromJSON: (json) => json as never,
    },
    credentials: {
      create: async () => null,
      get: async () => ({ toJSON: () => ({ id: "cred-1" }) }) as unknown as Credential,
    },
    ...overrides,
  };
}

function installFetch(finish: () => Response = () =>
  respond({
    resolutions: [
      { event_id: "a", resolved_by: "Operator", resolved_at: "2026-10-03T10:00:00Z", reason: "why" },
      { event_id: "b", resolved_by: "Operator", resolved_at: "2026-10-03T10:00:00Z", reason: "why" },
    ],
  }),
) {
  const calls: Array<{ url: string; body: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, body });
      if (url.endsWith("/alert-resolutions/begin")) {
        return respond({ ceremony_id: "cer-9", publicKey: { challenge: "c" } });
      }
      if (url.endsWith("/alert-resolutions/finish")) return finish();
      throw new Error(`unexpected fetch ${url}`);
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

async function fillAndConfirm(reason = "telemetry was restarted") {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText(strings.resolve.reasonLabel), reason);
  await user.click(screen.getByRole("button", { name: strings.resolve.confirmLabel }));
  return user;
}

describe("RM-330 the resolve form", () => {
  it("sends the alerts and the reason, confirms with a passkey, and reports what it wrote", async () => {
    const calls = installFetch();
    const onResolved = vi.fn();
    render(<ResolveForm eventIds={["a", "b"]} browser={browser()} onResolved={onResolved} />);

    await fillAndConfirm();

    expect(await screen.findByRole("status")).toHaveTextContent(strings.resolve.doneDetail(2));
    expect(calls[0]?.body).toEqual({ event_ids: ["a", "b"], reason: "telemetry was restarted" });
    expect(calls[1]?.body).toEqual({ ceremony_id: "cer-9", credential: { id: "cred-1" } });
    expect(onResolved).toHaveBeenCalledTimes(1);
  });

  it("asks for a reason before anything is sent", async () => {
    const calls = installFetch();
    render(<ResolveForm eventIds={["a"]} browser={browser()} onResolved={vi.fn()} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: strings.resolve.confirmLabel }));
    expect(screen.getByRole("alert")).toHaveTextContent(strings.resolve.needReasonDetail);
    expect(calls).toHaveLength(0);
  });

  it("shows the server's own words when the alert was already resolved", async () => {
    installFetch(() =>
      respond({ error: { code: "conflict", message: "ledger: that alert already has a resolution: a" } }, 409),
    );
    const onResolved = vi.fn();
    render(<ResolveForm eventIds={["a"]} browser={browser()} onResolved={onResolved} />);
    await fillAndConfirm();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      strings.resolve.failedWith("ledger: that alert already has a resolution: a"),
    );
    expect(onResolved).not.toHaveBeenCalled();
  });

  it("says nothing was resolved when the passkey prompt is closed", async () => {
    const calls = installFetch();
    const closed = browser({
      credentials: {
        create: async () => null,
        get: async () => {
          throw new DOMException("closed", "NotAllowedError");
        },
      },
    });
    render(<ResolveForm eventIds={["a"]} browser={closed} onResolved={vi.fn()} />);
    await fillAndConfirm();
    expect(await screen.findByRole("alert")).toHaveTextContent(strings.resolve.cancelledDetail);
    expect(calls.some((c) => c.url.endsWith("/finish"))).toBe(false);
  });

  it("says a browser with no passkey support cannot confirm", async () => {
    installFetch();
    render(<ResolveForm eventIds={["a"]} browser={browser({ supported: false })} onResolved={vi.fn()} />);
    await fillAndConfirm();
    expect(await screen.findByRole("alert")).toHaveTextContent(strings.resolve.unsupportedDetail);
  });

  it("is a labelled form, operable from the keyboard alone", async () => {
    installFetch();
    render(<ResolveForm eventIds={["a"]} browser={browser()} onResolved={vi.fn()} />);
    expect(screen.getByRole("form", { name: strings.resolve.heading })).toBeInTheDocument();
    const user = userEvent.setup();
    await user.tab();
    expect(screen.getByLabelText(strings.resolve.reasonLabel)).toHaveFocus();
    await user.keyboard("restarted");
    await user.tab();
    expect(screen.getByRole("button", { name: strings.resolve.confirmLabel })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("status")).toHaveTextContent(strings.resolve.doneDetail(2));
  });

  it("names a group's form by its count", () => {
    installFetch();
    render(<ResolveForm eventIds={["a", "b", "c"]} browser={browser()} onResolved={vi.fn()} />);
    expect(screen.getByRole("form", { name: strings.resolve.groupHeading(3) })).toBeInTheDocument();
  });
});
