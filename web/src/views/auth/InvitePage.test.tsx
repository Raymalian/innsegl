// SPDX-License-Identifier: Apache-2.0

/*
 * FE-143 (#481, #486): the page an invitation link opens. The code rides in
 * the URL's fragment, which a browser never sends to a server; the page
 * reads it, says what it invites to, and either creates the person's account
 * with a new passkey or joins the signed-in person with the account they
 * have.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvitePage } from "./InvitePage";
import { strings } from "./strings";
import type { WebAuthnBrowser } from "./client";
import { AuthGate } from "../../app/AuthGate";

const CODE = "iv_" + "a".repeat(64);
const PREVIEW = {
  organisation_id: "b".repeat(32),
  organisation: "example-team",
  role: "member",
  expires_at: "2026-10-13T12:00:00Z",
};

beforeEach(() => {
  window.history.replaceState(null, "", "/invite#" + CODE);
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

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
      create: async () => ({ toJSON: () => ({ id: "cred-1" }) }) as unknown as Credential,
      get: async () => ({ toJSON: () => ({ id: "cred-1" }) }) as unknown as Credential,
    },
  };
}

describe("FE-143 the invitation page", () => {
  it("says the link carries no invitation when the fragment is empty", () => {
    window.history.replaceState(null, "", "/invite");
    render(<InvitePage signedIn={false} onJoined={() => {}} browser={workingBrowser()} />);
    expect(screen.getByRole("heading", { name: strings.invite.missingHeading })).toBeInTheDocument();
  });

  it("says an unusable link is unusable, and nothing more", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        respond({ error: { code: "not_found", message: "that invitation link is not usable" } }, 404),
      ),
    );
    render(<InvitePage signedIn={false} onJoined={() => {}} browser={workingBrowser()} />);
    expect(
      await screen.findByRole("heading", { name: strings.invite.unusableHeading }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("creates a new person's account with a passkey, shows the recovery codes, then joins", async () => {
    const sent: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        if (url.endsWith("/auth/invitation")) {
          sent.preview = body;
          return respond(PREVIEW);
        }
        if (url.endsWith("/auth/invitation/begin")) {
          sent.begin = body;
          return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } });
        }
        if (url.endsWith("/auth/invitation/finish")) {
          sent.finish = body;
          return respond({
            authenticated: true,
            display_name: "Ada",
            recovery_codes: ["code-1", "code-2"],
            organisation: { id: PREVIEW.organisation_id, name: "example-team", role: "member" },
          });
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const onJoined = vi.fn();
    render(<InvitePage signedIn={false} onJoined={onJoined} browser={workingBrowser()} />);

    expect(await screen.findByText(/example-team/)).toBeInTheDocument();
    expect(screen.getByText(/as a member/)).toBeInTheDocument();
    expect(sent.preview).toEqual({ code: CODE });

    await userEvent.type(screen.getByLabelText(strings.invite.displayNameLabel), "Ada");
    await userEvent.click(screen.getByRole("button", { name: strings.invite.createButton }));

    expect(await screen.findByText("code-1")).toBeInTheDocument();
    expect(sent.begin).toEqual({ code: CODE, display_name: "Ada" });
    expect(sent.finish).toEqual({ ceremony_id: "cer-1", credential: { id: "cred-1" }, code: CODE });
    expect(onJoined).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: strings.recoveryCodes.continueButton }));
    expect(onJoined).toHaveBeenCalledWith("Ada");
  });

  it("joins a signed-in person with the account they have", async () => {
    let accepted: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith("/auth/invitation")) return respond(PREVIEW);
        if (url.endsWith("/account/invitations/accept")) {
          accepted = JSON.parse(String(init?.body));
          return respond({ id: PREVIEW.organisation_id, name: "example-team", role: "member" });
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const onJoined = vi.fn();
    render(<InvitePage signedIn onJoined={onJoined} browser={workingBrowser()} />);

    await userEvent.click(await screen.findByRole("button", { name: strings.invite.joinButton }));
    await waitFor(() => expect(onJoined).toHaveBeenCalled());
    expect(accepted).toEqual({ code: CODE });
    expect(screen.queryByLabelText(strings.invite.displayNameLabel)).not.toBeInTheDocument();
  });

  it("is what the gate shows at /invite to a person who is not signed in", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/session")) return respond({ authenticated: false });
        if (url.includes("/auth/setup")) return respond({ needed: false });
        if (url.endsWith("/auth/invitation")) return respond(PREVIEW);
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);
    expect(await screen.findByRole("heading", { name: strings.invite.heading })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: strings.signIn.heading })).not.toBeInTheDocument();
    expect(screen.queryByTestId("protected")).not.toBeInTheDocument();
  });

  // Measured on the dev stack: the gate re-read the session on join, which
  // remounted this page, which asked about the now-spent code and said the
  // link was unusable. The joined page must stay.
  it("says a signed-in person has joined, through the gate", async () => {
    let spent = false;
    let sessionReads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/session")) {
          sessionReads += 1;
          return respond({ authenticated: true, display_name: "Ada" });
        }
        if (url.includes("/auth/setup")) return respond({ needed: false });
        if (url.endsWith("/auth/invitation")) {
          return spent
            ? respond({ error: { code: "not_found", message: "not usable" } }, 404)
            : respond(PREVIEW);
        }
        if (url.endsWith("/account/invitations/accept")) {
          spent = true;
          return respond({ id: PREVIEW.organisation_id, name: "example-team", role: "member" });
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    render(<AuthGate>{() => <div data-testid="protected">the dashboard</div>}</AuthGate>);
    await userEvent.click(await screen.findByRole("button", { name: strings.invite.joinButton }));
    expect(await screen.findByRole("heading", { name: strings.invite.joinedHeading })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 300));
    expect(screen.getByRole("heading", { name: strings.invite.joinedHeading })).toBeInTheDocument();
    // Re-reading the session would remount the page onto the spent code.
    expect(sessionReads).toBe(1);
  });
});
