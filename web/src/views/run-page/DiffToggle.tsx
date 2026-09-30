// SPDX-License-Identifier: Apache-2.0

/*
 * The Timeline heading's Unified / Side by side toggle — Main.dc.html. Two
 * real buttons (not a <select>), `aria-pressed` carrying the state to
 * assistive technology, and the choice itself lives in the URL (doc 06 §7),
 * set by RunPage rather than here: this component is a pure function of
 * `mode` and an `onChange`, the same shape `Tabs.tsx` uses.
 */

import type { DiffMode } from "./Diff";
import { strings } from "./strings";
import { toggleButton, toggleButtonIdle, toggleButtonSelected, toggleGroup } from "./styles";

export interface DiffToggleProps {
  readonly mode: DiffMode;
  readonly onChange: (mode: DiffMode) => void;
}

export function DiffToggle({ mode, onChange }: DiffToggleProps) {
  return (
    <div role="group" aria-label={strings.timeline.toggleLabel} className={toggleGroup}>
      <button
        type="button"
        aria-pressed={mode === "unified"}
        onClick={() => onChange("unified")}
        className={`${toggleButton} ${mode === "unified" ? toggleButtonSelected : toggleButtonIdle}`}
      >
        {strings.timeline.unified}
      </button>
      <button
        type="button"
        aria-pressed={mode === "side"}
        onClick={() => onChange("side")}
        className={`${toggleButton} ${mode === "side" ? toggleButtonSelected : toggleButtonIdle}`}
      >
        {strings.timeline.sideBySide}
      </button>
    </div>
  );
}
