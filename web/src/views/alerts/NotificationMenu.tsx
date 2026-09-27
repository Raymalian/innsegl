// SPDX-License-Identifier: Apache-2.0

/*
 * The header's notification menu — ADR-0054, doc 06 P1, P2, P3, §6.4.
 *
 * Open alerts used to be banners stacked at the top of the overview. They are
 * now a bell in the persistent header, on every view, with a count badge that
 * is filled red whenever an alert is open and absent when none is. P3 still
 * holds — the alarm is the loudest thing in the chrome and is on every page
 * rather than one — but it no longer pushes the page it sits on below a fold.
 *
 * Presentational: it takes what the reads returned and renders it.
 * `HeaderAlerts` does the reading.
 *
 * What it deliberately does NOT have:
 *
 *   - no dismiss, no "mark as read", no resolve. ADR-0044: the dashboard
 *     renders no mutating action. An alert leaves this list when an operator
 *     resolves it at the command line and the ledger records that, never
 *     because a reader looked at it.
 *   - no raw hash and no field name in the list. Those are on the detail view,
 *     in identifier chips that copy the whole value (doc 06 §4.3).
 *
 * Keyboard (doc 06 §6.4): the bell is a real button, so Enter and Space open
 * it; ArrowDown opens it too. Inside, the arrow keys move between items and
 * wrap, Home and End jump, Tab moves on as it would anywhere, and Escape
 * closes the menu and puts focus back on the bell.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FocusEvent,
  type KeyboardEvent,
} from "react";

import { Link } from "../../app/router";
import { Icon } from "../../components/common/Icon";
import { srOnly } from "../../components/common/styles";
import { elapsedSince, formatAbsoluteUtc } from "../../components/common/time";
import type { AlertRecord } from "../overview/types";
import { strings } from "./strings";
import {
  alarmIcon,
  badgeOpen,
  badgeUnknown,
  bellButton,
  menuHeader,
  menuHeading,
  menuItem,
  menuItemHead,
  menuItemSummary,
  menuItemTime,
  menuItemTitle,
  menuNote,
  menuPanel,
  menuShell,
  mutedText,
} from "./styles";
import { alertSummary, alertTitle, openNewestFirst } from "./summary";

export interface NotificationMenuProps {
  /** Null when the alerts list did not answer (or has not yet). */
  readonly alerts: readonly AlertRecord[] | null;
  /** The overview's `open_alerts`; null when that did not answer. */
  readonly openCount: number | null;
  /** True before the first answer. Neither calm nor an alarm. */
  readonly loading?: boolean;
  readonly apiBase: string;
  readonly now?: Date;
}

const ITEM = '[role="menuitem"]';

export function NotificationMenu({
  alerts,
  openCount,
  loading = false,
  apiBase,
  now,
}: NotificationMenuProps) {
  const [open, setOpen] = useState(false);
  const shell = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();
  const at = now ?? new Date();

  const listed = alerts === null ? null : openNewestFirst(alerts);
  /* The aggregate is the whole ledger's count; the list is one page of the
   * feed. The larger of the two is the one that is not an undercount. */
  const count =
    listed === null ? openCount : Math.max(listed.length, openCount ?? 0);
  const unknown = count === null && !loading;

  const label = loading && count === null
    ? strings.menu.buttonReadingLabel
    : count === null
      ? strings.menu.buttonUnknownLabel
      : strings.menu.buttonLabel(count);

  const announcement = useAnnouncement(listed);

  const items = useCallback(
    (): HTMLElement[] =>
      Array.from(menu.current?.querySelectorAll<HTMLElement>(ITEM) ?? []),
    [],
  );

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  }, []);

  /* Opening moves focus to the first item, which is what makes the arrows
   * work straight away for a keyboard reader. */
  useEffect(() => {
    if (open) items()[0]?.focus();
  }, [open, items]);

  /* A click anywhere else closes it, as a menu does everywhere else. */
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

  /* Tab past the last item, or a click on another control, takes focus out:
   * the menu closes behind it rather than hanging open over the page. */
  const onBlur = (event: FocusEvent<HTMLDivElement>) => {
    const next = event.relatedTarget as Node | null;
    if (next !== null && !shell.current?.contains(next)) setOpen(false);
  };

  const remaining =
    listed === null || count === null ? 0 : Math.max(0, count - listed.length);

  return (
    <div ref={shell} className={menuShell} onBlur={onBlur}>
      <button
        ref={button}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={label}
        className={bellButton}
        onClick={() => setOpen((was) => !was)}
        onKeyDown={onButtonKey}
      >
        <Icon name="bell" className="shrink-0" />
        {count !== null && count > 0 ? (
          <span data-alert-badge aria-hidden="true" className={badgeOpen}>
            {count}
          </span>
        ) : unknown ? (
          <span data-alert-badge aria-hidden="true" className={badgeUnknown}>
            {strings.menu.unknownBadge}
          </span>
        ) : null}
      </button>

      <span aria-live="polite" className={srOnly}>
        {announcement}
      </span>

      {open ? (
        <div className={menuPanel}>
          <p className={menuHeader}>
            <span className={menuHeading}>{strings.menu.heading}</span>
            <span className={`text-micro ${mutedText}`}>{strings.menu.order}</span>
          </p>
          <div
            ref={menu}
            id={menuId}
            role="menu"
            aria-label={strings.menu.menuLabel}
            onKeyDown={onMenuKey}
          >
            <MenuBody
              listed={listed}
              count={count}
              loading={loading}
              apiBase={apiBase}
              now={at}
              onFollow={() => close(false)}
            />
            {/* The rest are an item too, pointing at the paged feed that
              * holds them (P1), so the list never ends in a claim that goes
              * nowhere. */}
            {remaining > 0 ? (
              <a role="menuitem" href={`${apiBase}/alerts`} className={menuItem}>
                <span className={menuItemSummary}>{strings.menu.moreDetail(remaining)}</span>
              </a>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function MenuBody({
  listed,
  count,
  loading,
  apiBase,
  now,
  onFollow,
}: {
  readonly listed: readonly AlertRecord[] | null;
  readonly count: number | null;
  readonly loading: boolean;
  readonly apiBase: string;
  readonly now: Date;
  readonly onFollow: () => void;
}) {
  if (listed === null) {
    /* P2: the list did not answer. Say what is known — the count — and link
     * to the response it came from; never an empty box that reads as calm. */
    if (count !== null && count > 0) {
      return (
        <a role="menuitem" href={`${apiBase}/overview`} className={menuItem}>
          <span className={menuItemSummary}>{strings.menu.countOnlyDetail(count)}</span>
        </a>
      );
    }
    return (
      <Note
        text={
          loading
            ? strings.menu.readingDetail
            : count === 0
              ? strings.menu.emptyDetail
              : strings.menu.unreadDetail
        }
      />
    );
  }
  if (listed.length === 0) return <Note text={strings.menu.emptyDetail} />;

  return (
    <>
      {listed.map((alert) => {
        const ts = new Date(alert.ts);
        return (
          <Link
            key={alert.event_id}
            role="menuitem"
            to={{ view: "alert", eventId: alert.event_id }}
            className={menuItem}
            onClick={onFollow}
          >
            <span className={menuItemHead}>
              <span className={menuItemTitle}>
                <Icon name="integrity-alert" className={alarmIcon} />
                {alertTitle(alert)}
              </span>
              <time
                dateTime={alert.ts}
                title={formatAbsoluteUtc(ts)}
                className={menuItemTime}
              >
                {strings.menu.ago(elapsedSince(ts, now))}
              </time>
            </span>
            <span className={menuItemSummary}>{alertSummary(alert)}</span>
          </Link>
        );
      })}
    </>
  );
}

/** A line inside the menu that is not a destination. A disabled item rather
 * than bare text, because a menu holds items and nothing else. */
function Note({ text }: { readonly text: string }) {
  return (
    <div role="menuitem" aria-disabled="true" tabIndex={-1} className={menuNote}>
      {text}
    </div>
  );
}

/**
 * What the polite live region says. On the first list, how many are open;
 * after that, how many are new since the last read — which is the case the
 * region exists for, an alert arriving on a page somebody already has open.
 * Silence when nothing changed, so a poll is not a recital.
 */
function useAnnouncement(listed: readonly AlertRecord[] | null): string {
  const seen = useRef<Set<string> | null>(null);
  const [message, setMessage] = useState("");
  const key = listed === null ? null : listed.map((a) => a.event_id).join(" ");

  useEffect(() => {
    if (key === null) return;
    const ids = key === "" ? [] : key.split(" ");
    const before = seen.current;
    seen.current = new Set(ids);
    if (before === null) {
      if (ids.length > 0) setMessage(strings.menu.announceOpen(ids.length));
      return;
    }
    const fresh = ids.filter((id) => !before.has(id)).length;
    if (fresh > 0) setMessage(strings.menu.announceNew(fresh));
  }, [key]);

  return message;
}
