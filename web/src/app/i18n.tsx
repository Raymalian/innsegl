// SPDX-License-Identifier: Apache-2.0

// The seam that makes doc 06 §6.3's "translation is possible" true rather than
// asserted. A component asks for the active catalogue and never for a
// particular language's words; swapping the catalogue swaps the interface.
//
// There is one catalogue today, and English is the default, because §6.3 says
// "English-first". What matters is that no component can reach `en` directly
// — they reach `useStrings()` — so adding a locale is a provider and a file,
// not an edit to every view.

import { createContext, useContext, type ReactNode } from "react";

import { en, type Strings } from "./strings";

const StringsContext = createContext<Strings>(en);

export function StringsProvider({
  strings = en,
  children,
}: {
  strings?: Strings;
  children: ReactNode;
}) {
  return (
    <StringsContext.Provider value={strings}>{children}</StringsContext.Provider>
  );
}

/** The active string catalogue. The only way a component obtains copy. */
export function useStrings(): Strings {
  return useContext(StringsContext);
}
