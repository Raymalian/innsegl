// SPDX-License-Identifier: Apache-2.0

/*
 * FE-159, unit half (#602): 30 minutes without input signs the dashboard
 * out, input moves the clock, and a session the server already ended for
 * idle is noticed on the next activity check. The Playwright half
 * (web/tests/auth/step-up.pw.ts) drives the real app on Playwright's clock.
 */

import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { IDLE_SIGN_OUT_MS, SESSION_CHECK_MS, useIdleSignOut } from "./idle";

function Probe({ onEnded }: { readonly onEnded: (idle: boolean) => void }) {
  useIdleSignOut(true, onEnded);
  return null;
}

let posts: string[];
let sessionBody: unknown;

beforeEach(() => {
  vi.useFakeTimers();
  posts = [];
  sessionBody = { authenticated: true, display_name: "Dev Operator" };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") posts.push(url);
      if (url.endsWith("/auth/session")) return new Response(JSON.stringify(sessionBody));
      return new Response("{}");
    }),
  );
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("FE-159 the dashboard signs itself out when idle", () => {
  it("signs out after 30 minutes without input, and says it was idle", async () => {
    const onEnded = vi.fn();
    render(<Probe onEnded={onEnded} />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(IDLE_SIGN_OUT_MS - 1000);
    });
    expect(onEnded).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(posts).toEqual(["/api/v1/auth/logout"]);
    expect(onEnded).toHaveBeenCalledWith(true);
  });

  it("input restarts the 30 minutes", async () => {
    const onEnded = vi.fn();
    render(<Probe onEnded={onEnded} />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(IDLE_SIGN_OUT_MS - 1000);
      window.dispatchEvent(new Event("keydown"));
      await vi.advanceTimersByTimeAsync(IDLE_SIGN_OUT_MS - 1000);
    });
    expect(onEnded).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(onEnded).toHaveBeenCalledWith(true);
  });

  it("an active person's check notices a session the server ended for idle", async () => {
    const onEnded = vi.fn();
    render(<Probe onEnded={onEnded} />);
    sessionBody = { authenticated: false, ended: "idle" };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SESSION_CHECK_MS);
      window.dispatchEvent(new Event("pointerdown"));
      await vi.advanceTimersByTimeAsync(10);
    });
    expect(onEnded).toHaveBeenCalledWith(true);
    expect(posts).toEqual([]);
  });
});
