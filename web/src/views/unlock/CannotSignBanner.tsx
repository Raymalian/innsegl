// SPDX-License-Identifier: Apache-2.0

/*
 * #616's "the CA cannot sign" banner, on every page (E34 follow-up). The
 * app shell mounts it once (App.tsx), above every view.
 *
 * Only an owner or admin of the operator's organisation sees it: that is
 * who can unlock (ADR-0082). Anyone else reads nothing past the session
 * (GET /api/v1/auth/session, which names their memberships); the server
 * refuses them GET /api/v1/account/ca-custody anyway. The status is read
 * again on every navigation, and when the unlock page reports an unlock
 * (custodyChangedEvent). The banner links to /account?unlock, and stays out
 * of the way while that page is open.
 */

import { useEffect, useState } from "react";

import { noticeTitle } from "../../components/common/styles";
import { Link, usePath } from "../../app/router";
import { fetchSessionStatus } from "../auth/client";
import { degraded, noticeBase, noticeBody, secondaryButton, focusRing } from "../auth/styles";
import { fetchCustodyStatus, type CustodyStatus } from "./api";
import { strings } from "./strings";

/** Dispatched on window when an unlock changed what the custodian reports. */
export const custodyChangedEvent = "innsegl:custody-changed";

/** Where the banner sends the reader: the unlock page. */
export const unlockPath = "/account?unlock";

function unlockPageOpen(path: string): boolean {
  const url = new URL(path, "http://dashboard.invalid");
  return url.pathname === "/account" && url.searchParams.has("unlock");
}

export function CannotSignBanner() {
  const path = usePath();
  const [mayUnlock, setMayUnlock] = useState(false);
  const [status, setStatus] = useState<CustodyStatus | null>(null);
  const [changed, setChanged] = useState(0);

  useEffect(() => {
    let live = true;
    void fetchSessionStatus()
      .then((session) => {
        if (!live) return;
        setMayUnlock(
          session.organisations.some((o) => o.operator && (o.role === "owner" || o.role === "admin")),
        );
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    const onChanged = () => setChanged((n) => n + 1);
    window.addEventListener(custodyChangedEvent, onChanged);
    return () => window.removeEventListener(custodyChangedEvent, onChanged);
  }, []);

  useEffect(() => {
    if (!mayUnlock) return;
    let live = true;
    void fetchCustodyStatus()
      .then((s) => {
        if (live) setStatus(s);
      })
      .catch(() => {
        if (live) setStatus(null);
      });
    return () => {
      live = false;
    };
  }, [mayUnlock, path, changed]);

  if (!mayUnlock || status === null || !status.enabled || status.can_sign || unlockPageOpen(path)) {
    return null;
  }
  return (
    <div role="alert" className={`${noticeBase} ${degraded} mx-auto mt-4 w-[calc(100%-2rem)] max-w-content`}>
      <div className={noticeBody}>
        <p className={noticeTitle}>{strings.banner.title}</p>
        <p>{strings.banner.body}</p>
        {status.reason !== undefined && status.reason !== "" && (
          <p className="text-micro">{strings.banner.reason(status.reason)}</p>
        )}
        <Link to={unlockPath} className={`${secondaryButton} ${focusRing} mt-1 inline-block no-underline`}>
          {strings.banner.action}
        </Link>
      </div>
    </div>
  );
}
