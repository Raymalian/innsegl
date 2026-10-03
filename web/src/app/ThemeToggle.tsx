// SPDX-License-Identifier: Apache-2.0

// The manual override doc 06 §5.1 asks for, as three radios.
//
// Radios rather than a two-state switch, because there are three states and
// the third one matters: "follow the system" is not the same as "light", and a
// toggle that collapses them silently stops honouring prefers-color-scheme the
// first time anybody touches it. Radios also arrive keyboard-operable and
// grouped for a screen reader without the shell implementing either
// (doc 06 §6.4).
//
// Drawn as one compact segmented control: each radio is an icon, its name
// kept for a screen reader and as a tooltip. The native radio stays in the
// label, visually hidden, so arrow keys and the group's name work as before.

import { useEffect, useState, type ReactNode } from "react";

import { focusRing, hairline } from "../components/common/styles";
import { useStrings } from "./i18n";
import {
  THEME_PREFERENCES,
  applyPreference,
  readPreference,
  storePreference,
  type ThemePreference,
} from "./theme";

const RADIO_GROUP = "innsegl-theme";

const ICON_PROPS = {
  width: 14,
  height: 14,
  viewBox: "0 0 16 16",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
  focusable: false,
} as const;

const ICONS: Record<ThemePreference, ReactNode> = {
  // A screen: follow what the system says.
  system: (
    <svg {...ICON_PROPS}>
      <rect x="2" y="3" width="12" height="8" rx="1" />
      <path d="M6 14h4M8 11v3" />
    </svg>
  ),
  light: (
    <svg {...ICON_PROPS}>
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1" />
    </svg>
  ),
  dark: (
    <svg {...ICON_PROPS}>
      <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z" />
    </svg>
  ),
};

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
    <fieldset
      className={`${hairline} flex items-center gap-0.5 rounded-sm border-line bg-surface p-0.5`}
    >
      <legend className="sr-only">{strings.labels.theme.region}</legend>
      {THEME_PREFERENCES.map((option) => (
        <label
          key={option}
          title={strings.labels.theme[option]}
          className={`flex cursor-pointer items-center rounded-sm p-1 text-ink-secondary hover:bg-hover has-[:checked]:bg-accent-surface has-[:checked]:text-accent has-[:focus-visible]:outline-focus has-[:focus-visible]:outline-[length:var(--innsegl-focus-ring-width)] has-[:focus-visible]:outline-offset-[var(--innsegl-focus-ring-offset)]`}
        >
          <input
            type="radio"
            name={RADIO_GROUP}
            value={option}
            checked={preference === option}
            onChange={() => {
              choose(option);
            }}
            className={`sr-only ${focusRing}`}
          />
          {ICONS[option]}
          <span className="sr-only">{strings.labels.theme[option]}</span>
        </label>
      ))}
    </fieldset>
  );
}
