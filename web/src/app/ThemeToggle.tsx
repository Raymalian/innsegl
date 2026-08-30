// SPDX-License-Identifier: Apache-2.0

// The manual override doc 06 §5.1 asks for, as three radios.
//
// Radios rather than a two-state switch, because there are three states and
// the third one matters: "follow the system" is not the same as "light", and a
// toggle that collapses them silently stops honouring prefers-color-scheme the
// first time anybody touches it. Radios also arrive keyboard-operable and
// grouped for a screen reader without the shell implementing either
// (doc 06 §6.4).

import { useEffect, useState } from "react";

import { useStrings } from "./i18n";
import {
  THEME_PREFERENCES,
  applyPreference,
  readPreference,
  storePreference,
  type ThemePreference,
} from "./theme";

const RADIO_GROUP = "innsegl-theme";

export function ThemeToggle() {
  const strings = useStrings();
  const [preference, setPreference] = useState<ThemePreference>(readPreference);

  // The pre-paint bootstrap in index.html has normally done this already; this
  // is what keeps the control honest if it did not run, and it costs one
  // attribute write.
  useEffect(() => {
    applyPreference(preference);
  }, [preference]);

  const choose = (next: ThemePreference) => {
    setPreference(next);
    storePreference(next);
  };

  return (
    <fieldset className="flex items-center gap-2 border-0 p-0 text-micro">
      <legend className="float-left mr-2 p-0 text-ink-secondary">
        {strings.labels.theme.region}
      </legend>
      {THEME_PREFERENCES.map((option) => (
        <label
          key={option}
          className="flex items-center gap-1 text-ink-secondary"
        >
          <input
            type="radio"
            name={RADIO_GROUP}
            value={option}
            checked={preference === option}
            onChange={() => {
              choose(option);
            }}
            className="accent-accent-emphasis"
          />
          {strings.labels.theme[option]}
        </label>
      ))}
    </fieldset>
  );
}
