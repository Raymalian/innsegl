// SPDX-License-Identifier: Apache-2.0

// Vite's `?raw` suffix, typed.
//
// Several of this shell's tests assert against source text rather than against
// behaviour — that index.html carries the theme bootstrap verbatim, that no
// component holds a user-visible string literal, that theme.ts contains no
// colour. Reading those files needs node:fs, and @types/node is deliberately
// not in the shared toolchain, so the files are imported through Vite instead.
// One declaration here is the whole cost of that, and it keeps the toolchain
// untouched.

declare module "*?raw" {
  const content: string;
  export default content;
}

// `import.meta.glob(..., { query: "?raw" })`, typed. FE-020 scans every
// component file the shell has, found by pattern rather than by a list, so a
// file added tomorrow is scanned tomorrow.
interface ImportMeta {
  glob(
    pattern: string,
    options: { query: "?raw"; import: "default"; eager: true },
  ): Record<string, string>;
}
