// SPDX-License-Identifier: Apache-2.0

/*
 * A tab control that means what the role says — doc 06 §6.4.
 *
 * "Real semantics, not divs pretending" is this project's rule for the
 * timeline (see styles.ts) and it is the rule here. `role="tab"` is a promise
 * to a screen-reader user: it makes the browser announce "tab, 1 of 2" and it
 * makes that reader press Left and Right, because that is what a tablist does
 * everywhere else. A row of buttons that swaps a div announces the promise and
 * then does not keep it, which is worse than plain buttons would have been.
 *
 * So the whole WAI-ARIA tab pattern is here and none of it is optional:
 *
 *   tablist/tab/tabpanel      the structure a screen reader navigates
 *   aria-selected             which one is open, said rather than shown
 *   aria-controls / -labelledby   which panel belongs to which tab, both ways
 *   roving tabindex           ONE tab in the page's tab order, so Tab moves
 *                             past the control rather than through it
 *   Left / Right / Home / End  movement inside it, wrapping at both ends
 *
 * SELECTION FOLLOWS FOCUS. The APG allows either, and picks automatic
 * activation when showing a panel is cheap. It is cheap here: both panels are
 * already mounted (see below), so an arrow key costs a `hidden` flip and
 * nothing else. Manual activation would mean a reader arrowing across the
 * strip hears tab names and sees nothing change until they press Enter, which
 * is the worse of the two for a control with two tabs.
 *
 * BOTH PANELS ARE RENDERED, THE UNSELECTED ONE `hidden`. Not conditional
 * rendering, for two reasons. `aria-controls` on the unselected tab has to
 * name an element that exists, or it is a dangling reference an audit tool
 * reports and a screen reader cannot follow. And the panels here own their own
 * reads — unmounting one would re-issue its request every time the reader
 * changed tabs. `hidden` keeps the element, takes it out of the accessibility
 * tree, and takes its focusable content out of the tab order, which is exactly
 * the three things wanted. Nothing sets a `display` utility on the panel: one
 * would beat `[hidden]` in the cascade and the panel would stay on screen.
 */

import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { tabCount, tabIdle, tabSelected, tabStrip } from "./styles";

export interface TabSpec {
  /** Stable across renders — it becomes part of the tab's and the panel's id. */
  readonly id: string;
  readonly label: string;
  /** What is behind this tab, for a reader who is looking at the other one. */
  readonly count: string;
  readonly panel: ReactNode;
}

export interface TabsProps {
  /** The accessible name of the tablist. doc 06 §6.4: a landmark a reader can
   * move to is a landmark that has to be named. */
  readonly label: string;
  readonly tabs: readonly TabSpec[];
}

export function Tabs({ label, tabs }: TabsProps) {
  /* One generated prefix for the whole control, so a page with two of them
   * cannot produce two tabs with the same id — which would make every
   * aria-controls on the page point at whichever panel parsed first. */
  const base = useId();
  const [selected, setSelected] = useState(0);
  const buttons = useRef(new Map<number, HTMLButtonElement>());

  if (tabs.length === 0) return null;

  const tabId = (id: string) => `${base}-tab-${id}`;
  const panelId = (id: string) => `${base}-panel-${id}`;

  /** Move the selection AND the focus. The two travel together under
   * automatic activation; moving one without the other is how a control ends
   * up announcing a tab the reader is not on. */
  const go = (index: number) => {
    setSelected(index);
    buttons.current.get(index)?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const last = tabs.length - 1;
    let next: number;
    switch (event.key) {
      // Wrapping at both ends rather than stopping dead: the APG's own
      // behaviour, and with two tabs a control that stopped dead would be a
      // control where Left does nothing half the time.
      case "ArrowRight":
        next = selected === last ? 0 : selected + 1;
        break;
      case "ArrowLeft":
        next = selected === 0 ? last : selected - 1;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = last;
        break;
      default:
        return;
    }
    // Only for the keys actually handled: End and Home scroll a page, and
    // taking those away from a reader who was not in the strip would be a
    // worse bug than the one this prevents.
    event.preventDefault();
    go(next);
  };

  return (
    <>
      <div role="tablist" aria-label={label} className={tabStrip}>
        {tabs.map((tab, index) => (
          <button
            key={tab.id}
            ref={(node) => {
              if (node === null) buttons.current.delete(index);
              else buttons.current.set(index, node);
            }}
            type="button"
            role="tab"
            id={tabId(tab.id)}
            aria-selected={index === selected}
            aria-controls={panelId(tab.id)}
            tabIndex={index === selected ? 0 : -1}
            onClick={() => {
              setSelected(index);
            }}
            onKeyDown={onKeyDown}
            className={index === selected ? tabSelected : tabIdle}
          >
            <span>{tab.label}</span>
            <span className={tabCount}>{tab.count}</span>
          </button>
        ))}
      </div>
      {tabs.map((tab, index) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={panelId(tab.id)}
          aria-labelledby={tabId(tab.id)}
          hidden={index !== selected}
        >
          {tab.panel}
        </div>
      ))}
    </>
  );
}
