// SPDX-License-Identifier: Apache-2.0

/*
 * #445 — the setup-link page that replaces the old typed-code EnrolPage: a
 * name and a passkey ceremony, driven only by the code already in the URL,
 * then the account's first ten recovery codes shown once before the caller
 * is told the account exists.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SetupPage } from "./SetupPage";
import { strings } from "./strings";
import type { WebAuthnBrowser } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

function respond(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
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

describe("SetupPage", () => {
  it("says there is no setup link when the URL carried no code", () => {
    render(
      <SetupPage setupNeeded browser={workingBrowser()} code="" onEnrolled={() => {}} />,
    );
    expect(
      screen.getByRole("heading", { name: strings.setup.missingCodeHeading }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("says the account already exists when setup is no longer needed", () => {
    render(
      <SetupPage
        setupNeeded={false}
        code="the-code"
        browser={workingBrowser()}
        onEnrolled={() => {}}
      />,
    );
    expect(
      screen.getByRole("heading", { name: strings.setup.alreadyDoneHeading }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: strings.setup.signInLink })).toHaveAttribute(
      "href",
      "/",
    );
  });

  it("renders the name field and the create-passkey button when a code is present", () => {
    render(
      <SetupPage setupNeeded code="the-code" browser={workingBrowser()} onEnrolled={() => {}} />,
    );
    expect(screen.getByRole("heading", { name: strings.setup.heading })).toBeInTheDocument();
    expect(screen.getByLabelText(strings.setup.displayNameLabel)).toBeInTheDocument();
    expect(screen.queryByLabelText(/code/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: strings.setup.button })).toBeInTheDocument();
  });

  it("submits the name with the URL's own code, then shows the recovery codes before calling onEnrolled", async () => {
    let sentBeginBody: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes("/auth/enrol/begin")) {
          sentBeginBody = JSON.parse(String(init?.body));
          return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } })();
        }
        if (url.includes("/auth/enrol/finish")) {
          return respond({
            authenticated: true,
            display_name: "Dev Operator",
            recovery_codes: ["code-1", "code-2"],
          })();
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const onEnrolled = vi.fn();
    const user = userEvent.setup();
    render(
      <SetupPage
        setupNeeded
        code="the-one-time-code"
        browser={workingBrowser()}
        onEnrolled={onEnrolled}
      />,
    );

    await user.type(screen.getByLabelText(strings.setup.displayNameLabel), "Dev Operator");
    await user.click(screen.getByRole("button", { name: strings.setup.button }));

    expect(
      await screen.findByRole("heading", { name: strings.recoveryCodes.heading }),
    ).toBeInTheDocument();
    expect(screen.getByText("code-1")).toBeInTheDocument();
    expect(screen.getByText("code-2")).toBeInTheDocument();
    expect(sentBeginBody).toEqual({ display_name: "Dev Operator", code: "the-one-time-code" });
    expect(onEnrolled).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("checkbox", { name: strings.recoveryCodes.savedCheckbox }),
    );
    await user.click(screen.getByRole("button", { name: strings.recoveryCodes.continueButton }));

    await waitFor(() => expect(onEnrolled).toHaveBeenCalledWith("Dev Operator"));
  });

  it("shows a refused code verbatim, not a generic failure", async () => {
    vi.stubGlobal(
      "fetch",
      respond(
        {
          error: {
            code: "forbidden",
            message:
              "that one-time code is not usable: it may be wrong, already used, or expired",
          },
        },
        403,
      ),
    );
    render(
      <SetupPage setupNeeded code="some-code" browser={workingBrowser()} onEnrolled={() => {}} />,
    );

    await userEvent.type(screen.getByLabelText(strings.setup.displayNameLabel), "Dev Operator");
    await userEvent.click(screen.getByRole("button", { name: strings.setup.button }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "that one-time code is not usable: it may be wrong, already used, or expired",
    );
  });
});
