// SPDX-License-Identifier: Apache-2.0

/*
 * #602: a dashboard nobody is using signs itself out after 30 minutes.
 *
 * The server ends a session that has made no request for 30 minutes
 * (internal/api sessionIdleTimeout). An open tab still makes requests on its
 * own (the alerts menu polls), so the tab also keeps its own clock: 30
 * minutes with no pointer, key, wheel or touch input, and it signs out —
 * the server revokes the session — and the sign-in page says why.
 *
 * While the person IS using it, the tab reads GET /api/v1/auth/session at
 * most every 5 minutes. That moves the server's clock for a person reading
 * one page for a long time, and it notices a session the server already
 * ended (idle elsewhere, or signed out from another browser).
 *
 * Timers and Date.now only: Playwright's clock drives both (FE-159).
 */

import { useEffect, useRef } from "react";

import { fetchSessionStatus, signOut } from "./client";

/** The dashboard's idle bound; the server's is the same. */
export const IDLE_SIGN_OUT_MS = 30 * 60 * 1000;

/** How often, at most, activity re-reads the session. */
export const SESSION_CHECK_MS = 5 * 60 * 1000;

const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"] as const;

/**
 * While `active`, signs out after IDLE_SIGN_OUT_MS without input and calls
 * `onEnded(true)`; calls `onEnded(idle)` when a check finds the server
 * already ended the session.
 */
export function useIdleSignOut(active: boolean, onEnded: (idle: boolean) => void, base?: string): void {
  const ended = useRef(onEnded);
  ended.current = onEnded;

  useEffect(() => {
    if (!active) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let lastCheck = Date.now();
    let done = false;

    const finish = (idle: boolean) => {
      if (done) return;
      done = true;
      ended.current(idle);
    };
    const expire = () => {
      void signOut(base)
        .catch(() => undefined)
        .finally(() => finish(true));
    };
    const arm = () => {
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(expire, IDLE_SIGN_OUT_MS);
    };
    const check = () => {
      lastCheck = Date.now();
      void fetchSessionStatus(base)
        .then((status) => {
          if (!status.authenticated) finish(status.ended === "idle");
        })
        .catch(() => undefined);
    };
    const onActivity = () => {
      if (done) return;
      arm();
      if (Date.now() - lastCheck >= SESSION_CHECK_MS) check();
    };

    arm();
    for (const name of ACTIVITY_EVENTS) window.addEventListener(name, onActivity, { passive: true });
    return () => {
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      for (const name of ACTIVITY_EVENTS) window.removeEventListener(name, onActivity);
    };
  }, [active, base]);
}
