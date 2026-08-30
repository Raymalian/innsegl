// SPDX-License-Identifier: Apache-2.0

/*
 * Identifier chip — doc 06 §4.3, P4, §6.4. Driven by FE-008.
 *
 *   §4.3: "One component for SPIFFE IDs, SHAs, run IDs, Rekor indices:
 *   monospace, middle-truncation preserving trust domain and final segment,
 *   copy-on-click with confirmation, full value on hover/focus and in an
 *   accessible tooltip."
 *
 * The load-bearing idea is that the truncation is a rendering, never the
 * value. Three separate paths carry the FULL identifier and none of them can
 * be satisfied by what is on screen:
 *
 *   - the accessible name of the control, so a screen-reader user hears the
 *     whole thing (§6.4: "Truncated identifiers expose their full value to
 *     assistive tech");
 *   - the clipboard, so a copied SPIFFE ID pastes into `innsegl verify`
 *     rather than into an ellipsis;
 *   - the tooltip and the native title, on hover AND on keyboard focus.
 *
 * The truncated glyphs are `aria-hidden`, which is the point: assistive
 * technology never receives the abbreviated form at all, so there is no path
 * by which the ellipsis reaches a reader who cannot see it is an ellipsis.
 *
 * P6 (read-only): the only actions here are copy and navigate.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Icon } from "./Icon";
import type { IdentifierKind } from "./identifier";
import { DEFAULT_MAX_LENGTH, truncateIdentifier } from "./identifier";
import { strings } from "./strings";
import {
  focusRing,
  identifierText,
  link,
  popover,
  srOnly,
  stateTransition,
} from "./styles";

/** How long the "Copied" confirmation stays up before the region falls silent. */
const CONFIRMATION_MS = 2_400;

export interface IdentifierChipProps {
  /** The full, unabbreviated identifier. This is what gets copied. */
  readonly value: string;
  readonly kind?: IdentifierKind;
  readonly maxLength?: number;
  /** P4: "link to their canonical view". Omitted where there is no such view. */
  readonly href?: string;
}

export function IdentifierChip({
  value,
  kind = "generic",
  maxLength = DEFAULT_MAX_LENGTH,
  href,
}: IdentifierChipProps) {
  const tooltipId = useId();
  const [revealed, setRevealed] = useState(false);
  const [feedback, setFeedback] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) clearTimeout(timer.current);
    },
    [],
  );

  const announce = useCallback((message: string) => {
    setFeedback(message);
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => setFeedback(""), CONFIRMATION_MS);
  }, []);

  const copy = useCallback(async () => {
    try {
      const clipboard = navigator.clipboard;
      if (clipboard === undefined) throw new Error("no clipboard");
      await clipboard.writeText(value);
      announce(strings.identifier.copied);
    } catch {
      // P2: an unverified claim is worse than an admitted failure.
      announce(strings.identifier.copyFailed);
    }
  }, [announce, value]);

  const kindLabel = strings.identifier.kind[kind];
  const display = truncateIdentifier(value, { kind, maxLength });
  const truncated = display !== value;

  return (
    <span className="relative inline-flex items-center gap-1">
      <button
        type="button"
        title={value}
        aria-describedby={revealed ? tooltipId : undefined}
        onClick={() => void copy()}
        onFocus={() => setRevealed(truncated)}
        onBlur={() => setRevealed(false)}
        onMouseEnter={() => setRevealed(truncated)}
        onMouseLeave={() => setRevealed(false)}
        className={`inline-flex max-w-full items-center gap-1 rounded-sm px-1 py-0 text-left hover:bg-hover ${focusRing} ${stateTransition}`}
      >
        <span data-identifier-display aria-hidden="true" className={identifierText}>
          {display}
        </span>
        {/* The whole value, for assistive technology, plus what clicking does. */}
        <span className={srOnly}>{`${kindLabel}: ${value}. ${strings.identifier.copy}`}</span>
        <Icon name="copy" className="shrink-0 text-ink-muted" />
      </button>

      {revealed ? (
        <span
          role="tooltip"
          id={tooltipId}
          className={`${popover} ${identifierText} top-full left-0 break-all text-ink`}
        >
          {value}
        </span>
      ) : null}

      {/* doc 06 §6.4 asks for live-region announcements; a copy that silently
       * did or did not happen is not a confirmation. */}
      <span role="status" aria-live="polite" className={srOnly}>
        {feedback}
      </span>

      {href === undefined ? null : (
        <a href={href} className={`${link} shrink-0`}>
          <span className={srOnly}>{`${strings.identifier.open} ${kindLabel} ${value}`}</span>
          <Icon name="open" />
        </a>
      )}
    </span>
  );
}
