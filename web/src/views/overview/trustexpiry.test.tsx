// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0073: the dashboard warns a year and 90 days before any CA in use
 * expires. The dates come from GET /api/v1/health's `trust_expiries`, which
 * the query API reads from the deployment's trust history.
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TrustExpiryNotice, fetchTrustExpiries, fetchTrustState } from "./TrustExpiryNotice";
import { strings } from "./strings";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("the CA expiry warning", () => {
  it("reads the expiries from the health response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            database: {},
            trust_expiries: [
              { name: "Fulcio root CA", kind: "fulcio_root", key_id: "aa", not_after: "2036-09-13T00:00:00Z" },
              { name: "gateway CA", kind: "gateway_ca", key_id: "bb", not_after: "2026-12-01T00:00:00Z", warning: "expires within 90 days" },
              { name: 7 },
            ],
          }),
        ),
      ),
    );
    const got = await fetchTrustExpiries("/api/v1", new AbortController().signal);
    expect(got).toHaveLength(2);
    expect(got[1]).toMatchObject({ name: "gateway CA", warning: "expires within 90 days" });
  });

  it("is empty when the health response carries none", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ database: {} }))));
    expect(await fetchTrustExpiries("/api/v1", new AbortController().signal)).toEqual([]);
  });

  it("warns only about the CAs that are near expiry", () => {
    render(
      <TrustExpiryNotice
        expiries={[
          { name: "Fulcio root CA", notAfter: "2036-09-13T00:00:00Z", warning: "" },
          { name: "gateway CA", notAfter: "2026-12-01T00:00:00Z", warning: "expires within 90 days" },
        ]}
      />,
    );
    expect(screen.getByText(strings.trustExpiry.line("gateway CA", "expires within 90 days", "2026-12-01"))).toBeTruthy();
    expect(screen.queryByText(/Fulcio root CA/)).toBeNull();
  });

  it("renders nothing when nothing is near expiry", () => {
    const { container } = render(
      <TrustExpiryNotice expiries={[{ name: "Fulcio root CA", notAfter: "2036-09-13T00:00:00Z", warning: "" }]} />,
    );
    expect(container.textContent).toBe("");
  });
});

describe("the trust watch's problems", () => {
  it("reads them from the health response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            trust_problems: [
              { text: "sentinel 6e55aa in github.com/o/r should verify as verified: it verified as failed", since: "2026-10-06T09:00:00Z" },
              { text: 3 },
            ],
          }),
        ),
      ),
    );
    const got = await fetchTrustState("/api/v1", new AbortController().signal);
    expect(got.problems).toHaveLength(1);
    expect(got.expiries).toEqual([]);
  });

  it("shows each problem with when it was first seen", () => {
    render(
      <TrustExpiryNotice
        expiries={[]}
        problems={[{ text: "sentinel 6e55aa failed", since: "2026-10-06T09:00:00Z" }]}
      />,
    );
    expect(screen.getByText(strings.trustExpiry.problem("sentinel 6e55aa failed", "2026-10-06"))).toBeTruthy();
  });
});
