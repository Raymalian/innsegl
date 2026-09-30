// SPDX-License-Identifier: Apache-2.0

/*
 * Load a fixture JSON file at test time, without a static `import … from
 * "*.json"` — the project's tsconfig does not set `resolveJsonModule` (not a
 * setting this issue's file ownership covers), and `JSON.parse()`'s `any`
 * return would defeat the point of a typed import anyway. Tests read fixtures
 * through this instead; `validate.ts`'s runtime shape check is what actually
 * proves a fixture matches the contract.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

export function loadFixture(name: string): unknown {
  const text = readFileSync(join(import.meta.dirname, name), "utf-8");
  return JSON.parse(text) as unknown;
}
