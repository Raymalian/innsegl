// SPDX-License-Identifier: Apache-2.0

// Schema 5's repository and branch pseudonyms, as the dashboard shows them
// (ADR-0080 decision 4).
//
// The query API resolves every pseudonym it can through the alias table, so a
// value that still reads `pn:<key-id>:<32 hex>` is one whose name was erased.
// It is shown as erased, with the first eight hex digits so a person can
// match one erased repository across pages, and never as a blank.

import { en } from "./strings";

const PSEUDONYM = /^pn:[a-z0-9][a-z0-9-]{0,62}:([0-9a-f]{32})$/;

export function isPseudonym(value: string): boolean {
  return PSEUDONYM.test(value);
}

export function displayName(value: string): string {
  const hex = PSEUDONYM.exec(value)?.[1];
  if (hex === undefined) return value;
  return `${en.labels.names.erased} · ${hex.slice(0, 8)}`;
}
