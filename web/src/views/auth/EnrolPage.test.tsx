// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) — the first-enrolment page: display name + the
 * one-time code, then a passkey ceremony. The socket-denial refusal
 * (internal/api/socketdenial.go) is just another AuthRequestError from the
 * server's point of view, and this page is required to show it verbatim
 * (doc 06 §6.1) rather than translate it into something vaguer.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EnrolPage } from "./EnrolPage";
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

describe("EnrolPage", () => {
  it("renders the display-name and code fields, and the create-passkey button", () => {
    render(<EnrolPage onEnrolled={() => {}} browser={workingBrowser()} />);
    expect(screen.getByRole("heading", { name: strings.enrol.heading })).toBeInTheDocument();
    expect(screen.getByLabelText(strings.enrol.displayNameLabel)).toBeInTheDocument();
    expect(screen.getByLabelText(strings.enrol.codeLabel)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: strings.enrol.button })).toBeInTheDocument();
  });

  it("submits the display name and code, completes the ceremony, and reports success", async () => {
    let sentBeginBody: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes("/auth/enrol/begin")) {
          sentBeginBody = JSON.parse(String(init?.body));
          return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } })();
        }
        if (url.includes("/auth/enrol/finish")) {
          return respond({ authenticated: true, display_name: "Dev Operator" })();
        }
        throw new Error(`unexpected fetch ${url}`);
      }),
    );
    const onEnrolled = vi.fn();
    render(<EnrolPage onEnrolled={onEnrolled} browser={workingBrowser()} />);

    await userEvent.type(screen.getByLabelText(strings.enrol.displayNameLabel), "Dev Operator");
    await userEvent.type(screen.getByLabelText(strings.enrol.codeLabel), "the-one-time-code");
    await userEvent.click(screen.getByRole("button", { name: strings.enrol.button }));

    await waitFor(() => expect(onEnrolled).toHaveBeenCalledWith("Dev Operator"));
    expect(sentBeginBody).toEqual({
      display_name: "Dev Operator",
      code: "the-one-time-code",
    });
  });

  it("shows the socket-denial refusal verbatim, not a generic failure", async () => {
    vi.stubGlobal(
      "fetch",
      respond(
        {
          error: {
            code: "forbidden",
            message: "no managed settings file at /etc/claude-code/managed-settings.json",
          },
        },
        403,
      ),
    );
    render(<EnrolPage onEnrolled={() => {}} browser={workingBrowser()} />);

    await userEvent.type(screen.getByLabelText(strings.enrol.displayNameLabel), "Dev Operator");
    await userEvent.type(screen.getByLabelText(strings.enrol.codeLabel), "some-code");
    await userEvent.click(screen.getByRole("button", { name: strings.enrol.button }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "no managed settings file at /etc/claude-code/managed-settings.json",
    );
  });

  it("requires both fields before the browser will submit the form", () => {
    render(<EnrolPage onEnrolled={() => {}} browser={workingBrowser()} />);
    expect(screen.getByLabelText(strings.enrol.displayNameLabel)).toBeRequired();
    expect(screen.getByLabelText(strings.enrol.codeLabel)).toBeRequired();
  });
});
