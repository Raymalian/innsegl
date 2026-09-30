// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) — the sign-in page: one passkey button, no
 * username field, and the three ways a ceremony does not end in a session
 * (the server refuses, the browser has no passkey support, the operator
 * cancels the platform prompt) rendered as distinct, factual copy rather
 * than one generic failure (doc 06 §6.1, P2's "honest states" read applied
 * to this page's one control).
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SignInPage } from "./SignInPage";
import { strings } from "./strings";
import type { WebAuthnBrowser } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

function respond(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

/** A browser that completes the ceremony with a fixed, fake credential —
 * enough shape for client.ts's own credentialJSON() to read a toJSON(). */
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

function unsupportedBrowser(): WebAuthnBrowser {
  return {
    supported: false,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: () => {
        throw new Error("unreachable");
      },
      parseRequestOptionsFromJSON: () => {
        throw new Error("unreachable");
      },
    },
    credentials: {
      create: async () => null,
      get: async () => null,
    },
  };
}

describe("SignInPage", () => {
  it("renders the one passkey button and no form field", () => {
    render(<SignInPage onSignedIn={() => {}} browser={workingBrowser()} />);
    expect(screen.getByRole("heading", { name: strings.signIn.heading })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: strings.signIn.button }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("completes the ceremony and reports the signed-in display name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/auth/login/begin")) {
          return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } })();
        }
        if (url.includes("/auth/login/finish")) {
          return respond({ authenticated: true, display_name: "Dev Operator" })();
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const onSignedIn = vi.fn();
    render(<SignInPage onSignedIn={onSignedIn} browser={workingBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));

    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith("Dev Operator"));
  });

  it("shows the server's own refusal verbatim", async () => {
    vi.stubGlobal(
      "fetch",
      respond({ error: { code: "unauthorized", message: "sign-in failed: no such credential" } }, 401),
    );
    render(<SignInPage onSignedIn={() => {}} browser={workingBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "sign-in failed: no such credential",
    );
  });

  it("names the browser's own lack of passkey support, distinctly", async () => {
    vi.stubGlobal("fetch", respond({ ceremony_id: "cer-1", publicKey: {} }));
    render(<SignInPage onSignedIn={() => {}} browser={unsupportedBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));

    expect(await screen.findByRole("alert")).toHaveTextContent(strings.signIn.unsupported);
  });

  it("disables the button while the ceremony is in flight", async () => {
    let resolveBegin: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            resolveBegin = resolve;
          }),
      ),
    );
    render(<SignInPage onSignedIn={() => {}} browser={workingBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));
    expect(screen.getByRole("button", { name: strings.signIn.working })).toBeDisabled();
    resolveBegin?.(new Response(JSON.stringify({ ceremony_id: "c", publicKey: {} })));
  });
});
