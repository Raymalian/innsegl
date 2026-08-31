// SPDX-License-Identifier: Apache-2.0

/*
 * Test support: what a sighted reader can actually perceive in rendered HTML.
 *
 * This exists because of a defect this project has already shipped once. An
 * agent proved that two states rendered differently by comparing their markup
 * with `class` and `style` stripped — and left the `data-state` attribute in.
 * The comparison then differed no matter what the pixels did, so the assertion
 * could not fail, and a review found it only by mutating the component.
 *
 * So the rule is inverted here. Strip everything a sighted reader CANNOT
 * perceive — the hooks a test grabs by, the ids React generates, the machine
 * timestamps, the accessibility names — and keep everything they can: text,
 * `class` (which is the colour), inline `style`, and `title`, which a hover
 * reveals. Two states that compare equal after this are two states a reader
 * cannot tell apart.
 *
 * It is not in a `.test.ts` file because two test files use it and importing
 * one test file from another runs its suite twice.
 */

/** Attributes that carry nothing to the eye. */
const INVISIBLE =
  /\s(?:data-[a-z-]+|aria-[a-z-]+|role|id|for|headers|datetime|href|tabindex|type|name|value)="[^"]*"/g;

/** Rendered HTML reduced to what a sighted reader can perceive. */
export function perceptible(html: string): string {
  return html.replace(INVISIBLE, "").replace(/\s+/g, " ").trim();
}
