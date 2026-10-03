// SPDX-License-Identifier: Apache-2.0

// The header's account menu (ADR-0062; RM-333, #511). The account name is a
// menu button; its two items are the account page and sign-out. Chrome, not
// a page-level decision — ThemeToggle's own sibling in the header — so it
// reads its copy from the SHELL catalogue (useStrings) rather than from
// views/auth's own, the same split public-verify's directory and the shell's
// each already hold.
//
// Keyboard (doc 06 §6.4), the notification menu's own pattern: the name is a
// real button, so Enter and Space open the menu, and ArrowDown opens it too;
// opening puts focus on the first item. Inside, the arrow keys move and
// wrap, Home and End jump, Escape closes and returns focus to the button,
// and Tab out or a click anywhere else closes it.

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FocusEvent,
  type KeyboardEvent,
} from "react";

import { useStrings } from "./i18n";
import { Link } from "./router";
import { signOut } from "../views/auth/client";
import { chromeButton, focusRing } from "../views/auth/styles";
import { hairline } from "../components/common/styles";

export interface AccountMenuProps {
  readonly displayName: string;
  readonly onSignedOut: () => void;
}

const ITEM = '[role="menuitem"]';

const menuPanel = `${hairline} absolute right-0 z-10 mt-1 flex min-w-[10rem] flex-col gap-0.5 rounded-md border-line bg-raised p-1 shadow-popover`;
const menuItem = `block w-full rounded-sm px-3 py-1.5 text-left text-body text-ink hover:bg-hover focus:bg-hover ${focusRing}`;

export function AccountMenu({ displayName, onSignedOut }: AccountMenuProps) {
  const strings = useStrings();
  const [open, setOpen] = useState(false);
  const [working, setWorking] = useState(false);
  const shell = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const items = useCallback(
    (): HTMLElement[] => Array.from(menu.current?.querySelectorAll<HTMLElement>(ITEM) ?? []),
    [],
  );

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  }, []);

  useEffect(() => {
    if (open) items()[0]?.focus();
  }, [open, items]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!shell.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    return () => document.removeEventListener("mousedown", onPointer);
  }, [open]);

  const onButtonKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" && !open) {
      event.preventDefault();
      setOpen(true);
    }
  };

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const all = items();
    const here = all.indexOf(document.activeElement as HTMLElement);
    const move = (to: number) => {
      event.preventDefault();
      all[(to + all.length) % all.length]?.focus();
    };
    switch (event.key) {
      case "ArrowDown":
        return move(here + 1);
      case "ArrowUp":
        return move(here - 1);
      case "Home":
        return move(0);
      case "End":
        return move(all.length - 1);
      case "Escape":
        event.preventDefault();
        return close(true);
    }
  };

  const onBlur = (event: FocusEvent<HTMLDivElement>) => {
    const next = event.relatedTarget as Node | null;
    if (next !== null && !shell.current?.contains(next)) setOpen(false);
  };

  const doSignOut = async () => {
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
    <div ref={shell} className="relative" onBlur={onBlur}>
      <button
        ref={button}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        title={displayName}
        onClick={() => setOpen((was) => !was)}
        onKeyDown={onButtonKey}
        className={`${chromeButton} ${focusRing} inline-flex max-w-[6rem] items-center gap-1 font-medium text-ink md:max-w-[11rem]`}
      >
        <span className="truncate">{displayName}</span>
        <svg
          aria-hidden="true"
          viewBox="0 0 16 16"
          className="h-3 w-3 shrink-0"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <path d="M4 6l4 4 4-4" />
        </svg>
      </button>
      {open ? (
        <div
          ref={menu}
          id={menuId}
          role="menu"
          aria-label={strings.labels.header.accountMenu}
          onKeyDown={onMenuKey}
          className={menuPanel}
        >
          <Link role="menuitem" to="/account" className={menuItem} onClick={() => close(false)}>
            {strings.labels.header.accountPage}
          </Link>
          <button
            type="button"
            role="menuitem"
            disabled={working}
            onClick={() => void doSignOut()}
            className={menuItem}
          >
            {working ? strings.labels.header.signOutWorking : strings.labels.header.signOut}
          </button>
        </div>
      ) : null}
    </div>
  );
}
