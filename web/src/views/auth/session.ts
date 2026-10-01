// SPDX-License-Identifier: Apache-2.0

/*
 * What the gated shell needs to know before it can render anything at all
 * (ADR-0062): am I signed in, and if not, does an account even exist yet?
 *
 * Two reads, run together, because neither alone is enough to choose a
 * screen: "not signed in" could mean "show the sign-in button" or "show the
 * setup page", and only GET /api/v1/auth/setup (#445, allow-listed, no
 * session needed) tells the two apart.
 */

import { useCallback, useEffect, useState } from "react";

import { fetchSessionStatus, fetchSetupStatus } from "./client";

export type SessionState =
  | { readonly status: "checking" }
  | { readonly status: "unauthenticated"; readonly setupNeeded: boolean }
  | { readonly status: "authenticated"; readonly displayName: string };

export interface SessionResource {
  readonly state: SessionState;
  /** Called once a ceremony's own POST already proved the session exists —
   * no second round trip to learn what the server just told us directly. */
  readonly markAuthenticated: (displayName: string) => void;
  readonly markSignedOut: () => void;
  readonly reload: () => void;
}

export function useSessionState(base?: string): SessionResource {
  const [state, setState] = useState<SessionState>({ status: "checking" });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setState({ status: "checking" });

    void (async () => {
      const [session, setup] = await Promise.all([
        fetchSessionStatus(base),
        fetchSetupStatus(base),
      ]);
      if (!live) return;
      setState(
        session.authenticated
          ? { status: "authenticated", displayName: session.displayName }
          : { status: "unauthenticated", setupNeeded: setup.needed },
      );
    })();

    return () => {
      live = false;
    };
  }, [base, nonce]);

  const markAuthenticated = useCallback((displayName: string) => {
    setState({ status: "authenticated", displayName });
  }, []);

  const markSignedOut = useCallback(() => {
    setState({ status: "unauthenticated", setupNeeded: false });
  }, []);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { state, markAuthenticated, markSignedOut, reload };
}
