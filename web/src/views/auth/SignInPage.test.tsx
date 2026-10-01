// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) and #445 — the sign-in page: one passkey button,
 * no username field, a toggle to a recovery-code form, and a no-account
 * notice when SetupStatus.needed. Three ways a passkey ceremony does not
 * end in a session (the server refuses, the browser has no passkey support,
 * the operator cancels the platform prompt) are rendered as distinct,
 * factual copy rather than one generic failure (doc 06 §6.1).
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
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={workingBrowser()} />);
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
    render(
      <SignInPage onSignedIn={onSignedIn} onRecovered={() => {}} browser={workingBrowser()} />,
    );

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));

    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith("Dev Operator"));
  });

  it("shows the server's own refusal verbatim", async () => {
    vi.stubGlobal(
      "fetch",
      respond({ error: { code: "unauthorized", message: "sign-in failed: no such credential" } }, 401),
    );
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={workingBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "sign-in failed: no such credential",
    );
  });

  it("names the browser's own lack of passkey support, distinctly", async () => {
    vi.stubGlobal("fetch", respond({ ceremony_id: "cer-1", publicKey: {} }));
    render(
      <SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={unsupportedBrowser()} />,
    );

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
    render(<SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={workingBrowser()} />);

    await userEvent.click(screen.getByRole("button", { name: strings.signIn.button }));
    expect(screen.getByRole("button", { name: strings.signIn.working })).toBeDisabled();
    resolveBegin?.(new Response(JSON.stringify({ ceremony_id: "c", publicKey: {} })));
  });

  it("says there is no account yet, with no passkey button, when setup is still needed", () => {
    render(
      <SignInPage
        setupNeeded
        onSignedIn={() => {}}
        onRecovered={() => {}}
        browser={workingBrowser()}
      />,
    );
    expect(
      screen.getByRole("heading", { name: strings.signIn.noAccountHeading }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: strings.signIn.button })).not.toBeInTheDocument();
  });

  describe("the recovery-code form", () => {
    it("is hidden until 'Use a recovery code' is clicked", async () => {
      render(
        <SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={workingBrowser()} />,
      );
      expect(screen.queryByLabelText(strings.signIn.recoveryLabel)).not.toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: strings.signIn.recoveryLink }));
      expect(screen.getByLabelText(strings.signIn.recoveryLabel)).toBeInTheDocument();

      await userEvent.click(
        screen.getByRole("button", { name: strings.signIn.recoveryHideLink }),
      );
      expect(screen.queryByLabelText(strings.signIn.recoveryLabel)).not.toBeInTheDocument();
    });

    it("signs in with a code and reports the display name and codes remaining", async () => {
      let sentBody: unknown;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string, init?: RequestInit) => {
          if (url.includes("/auth/recover")) {
            sentBody = JSON.parse(String(init?.body));
            return respond({ authenticated: true, display_name: "Dev Operator", remaining: 7 })();
          }
          throw new Error(`unexpected fetch ${url}`);
        }),
      );
      const onRecovered = vi.fn();
      const user = userEvent.setup();
      render(
        <SignInPage onSignedIn={() => {}} onRecovered={onRecovered} browser={workingBrowser()} />,
      );

      await user.click(screen.getByRole("button", { name: strings.signIn.recoveryLink }));
      await user.type(screen.getByLabelText(strings.signIn.recoveryLabel), "the-recovery-code");
      await user.click(screen.getByRole("button", { name: strings.signIn.recoveryButton }));

      await waitFor(() => expect(onRecovered).toHaveBeenCalledWith("Dev Operator", 7));
      expect(sentBody).toEqual({ code: "the-recovery-code" });
    });

    it("shows a wrong recovery code's refusal verbatim", async () => {
      vi.stubGlobal(
        "fetch",
        respond({ error: { code: "unauthorized", message: "that recovery code is not usable" } }, 401),
      );
      const user = userEvent.setup();
      render(
        <SignInPage onSignedIn={() => {}} onRecovered={() => {}} browser={workingBrowser()} />,
      );

      await user.click(screen.getByRole("button", { name: strings.signIn.recoveryLink }));
      await user.type(screen.getByLabelText(strings.signIn.recoveryLabel), "wrong-code");
      await user.click(screen.getByRole("button", { name: strings.signIn.recoveryButton }));

      expect(await screen.findByRole("alert")).toHaveTextContent(
        "that recovery code is not usable",
      );
    });
  });
});
