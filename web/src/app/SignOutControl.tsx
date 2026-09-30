// SPDX-License-Identifier: Apache-2.0

// The header's sign-out control (ADR-0062). Chrome, not a page-level
// decision — ThemeToggle's own sibling in the header — so it reads its copy
// from the SHELL catalogue (useStrings) rather than from views/auth's own,
// the same split public-verify's directory and the shell's each already
// hold.

import { useState } from "react";

import { useStrings } from "./i18n";
import { signOut } from "../views/auth/client";
import { chromeButton, focusRing } from "../views/auth/styles";

export interface SignOutControlProps {
  readonly onSignedOut: () => void;
}

export function SignOutControl({ onSignedOut }: SignOutControlProps) {
  const strings = useStrings();
  const [working, setWorking] = useState(false);

  const click = async () => {
    setWorking(true);
    try {
      await signOut();
    } finally {
      // A sign-out that could not reach the server is still a sign-out the
      // reader asked for: the cookie this browser holds is no more useful
      // than before, and there is no session-scoped content to protect by
      // insisting the request round-tripped first.
      onSignedOut();
    }
  };

  return (
    <button
      type="button"
      onClick={() => void click()}
      disabled={working}
      className={`${chromeButton} ${focusRing}`}
    >
      {working ? strings.labels.header.signOutWorking : strings.labels.header.signOut}
    </button>
  );
}
