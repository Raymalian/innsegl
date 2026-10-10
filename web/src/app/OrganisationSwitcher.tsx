// SPDX-License-Identifier: Apache-2.0

// The header's organisation switcher (RM-307, #486). A person in several
// organisations sees all of their runs at once, or one organisation's. The
// choice is a cookie the query API reads on every request
// (internal/api/scope.go), so the server narrows every read and no view
// filters anything itself. It only ever narrows: the server ignores a choice
// that names an organisation the person is not in.
//
// Chrome, like the account menu beside it, so its copy is the shell's.

import { useId, useState } from "react";

import { useStrings } from "./i18n";
import { focusRing } from "../views/auth/styles";
import type { SessionOrganisation } from "../views/auth/client";

/** internal/api's OrganisationCookie. */
export const ORGANISATION_COOKIE = "innsegl_organisation";

/** The organisation the cookie names, "" for all of them. */
export function chosenOrganisation(cookie: string = document.cookie): string {
  for (const part of cookie.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === ORGANISATION_COOKIE) return decodeURIComponent(value.join("="));
  }
  return "";
}

function choose(id: string) {
  document.cookie =
    id === ""
      ? `${ORGANISATION_COOKIE}=; Path=/; Max-Age=0; SameSite=Strict`
      : `${ORGANISATION_COOKIE}=${encodeURIComponent(id)}; Path=/; SameSite=Strict`;
}

export interface OrganisationSwitcherProps {
  readonly organisations: readonly SessionOrganisation[];
  /** Called after the choice changed, so every view reads again. */
  readonly onChange: () => void;
}

const selectClass = `rounded-sm border border-line bg-surface px-2 py-1 text-micro text-ink ${focusRing} max-w-[10rem] md:max-w-[14rem]`;

export function OrganisationSwitcher({ organisations, onChange }: OrganisationSwitcherProps) {
  const strings = useStrings();
  const id = useId();
  const [value, setValue] = useState(() => {
    const chosen = chosenOrganisation();
    return organisations.some((o) => o.id === chosen) ? chosen : "";
  });
  if (organisations.length < 2) return null;
  return (
    <div className="flex items-center gap-1">
      <label htmlFor={id} className="sr-only">
        {strings.labels.header.organisation}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          setValue(event.target.value);
          choose(event.target.value);
          onChange();
        }}
        className={selectClass}
      >
        <option value="">{strings.labels.header.allOrganisations}</option>
        {organisations.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </select>
    </div>
  );
}
