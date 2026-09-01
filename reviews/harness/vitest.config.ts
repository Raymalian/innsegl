// SPDX-License-Identifier: Apache-2.0

/*
 * The measurement harness for the doc 06 §8 anti-pattern review (RM-050, #58).
 *
 * A SEPARATE vitest project from the dashboard's own, deliberately. The probes
 * under reviews/probes/ are the instruments of a one-off review: they print as
 * much as they assert, and folding them into `web`'s default include glob would
 * change that suite's count and make the product's build depend on this review.
 * `web/vite.config.ts` is not this issue's file to edit either.
 *
 * Root is `web/`, so every bare import inside web/src resolves against
 * web/node_modules exactly as it does under the real suite. The probes live
 * outside that root, so the handful of bare specifiers THEY use are aliased
 * below. No product module is aliased: a probe imports one by path or not at
 * all.
 *
 * Two plugins the dashboard's own config carries are absent here, and their
 * absence changes nothing this review measures:
 *
 *   @vitejs/plugin-react — supplies Fast Refresh, which no test uses. Vite's
 *   own esbuild transform compiles the probes' TSX through the automatic JSX
 *   runtime that web/tsconfig.json already selects.
 *
 *   @tailwindcss/vite — compiles `@import "tailwindcss"` at build time. No
 *   probe imports a stylesheet: colour is read out of web/dist/assets/*.css,
 *   which `npm run build` produced with that plugin, and out of the Tailwind
 *   compiler API called directly. Both are the real compiler; neither needs
 *   the plugin in this process.
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, "../../web");
const modules = resolve(web, "node_modules");

export default {
  root: web,
  // web/tsconfig.json selects the automatic JSX runtime, but it `include`s only
  // `src`, so the probes — which sit outside it — would otherwise be compiled
  // with the classic transform and fail for want of a React import.
  esbuild: { jsx: "automatic" as const },
  // The probes and their harness sit above `root`. Vite refuses to serve a
  // file outside the root unless it is allowed explicitly.
  server: { fs: { allow: [resolve(here, "../..")] } },
  resolve: {
    alias: [
      // Probes live outside web/, so node resolution cannot walk up to
      // web/node_modules on its own. These are the only bare specifiers the
      // probes import; every product module is imported by path.
      { find: /^react$/, replacement: resolve(modules, "react") },
      { find: /^react\/(.*)$/, replacement: resolve(modules, "react/$1") },
      { find: /^react-dom$/, replacement: resolve(modules, "react-dom") },
      { find: /^react-dom\/(.*)$/, replacement: resolve(modules, "react-dom/$1") },
      {
        find: /^@testing-library\/react$/,
        replacement: resolve(modules, "@testing-library/react"),
      },
      {
        find: /^@testing-library\/dom$/,
        replacement: resolve(modules, "@testing-library/dom"),
      },
      {
        find: /^@tailwindcss\/node$/,
        replacement: resolve(modules, "@tailwindcss/node"),
      },
      {
        find: /^@tailwindcss\/oxide$/,
        replacement: resolve(modules, "@tailwindcss/oxide"),
      },
    ],
  },
  test: {
    globals: true,
    environment: "jsdom",
    css: true,
    include: [resolve(here, "../probes/**/*.probe.tsx")],
    // Probes write evidence files into one directory; serial is quieter and
    // the whole run is a few seconds either way.
    fileParallelism: false,
    testTimeout: 30_000,
  },
};
