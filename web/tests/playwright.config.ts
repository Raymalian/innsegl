// SPDX-License-Identifier: Apache-2.0

/*
 * The browser harness RM-049 (#57) builds — a real Chromium, not jsdom.
 *
 * Every agent before this one verified rendered DOM and compiled CSS and
 * explicitly declined to claim a visual check, because no browser harness
 * existed. This is that harness: it drives the actual six views and a set of
 * component scenarios through a real `vite` dev server, in a real Chromium,
 * so a test can read `getComputedStyle` off actual elements — which is the
 * only thing that resolves `light-dark()` and inheritance (issue #104) and
 * the only thing that proves what doc 06 §6.4 asks for rather than what the
 * source code merely claims.
 *
 * `web/tests/` is this issue's exclusively owned path (doc 07, RM-049's
 * epic). Nothing here imports from web/vite.config.ts or changes it — the
 * dev server it starts is the same one `npm run dev` starts, unmodified.
 */

import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, "..");

/** Fixed rather than ephemeral, so a failure trace's baseURL is reproducible
 * and two local runs never race for a port. */
const PORT = 4317;

export default defineConfig({
  testDir: here,
  // Deliberately NOT the `*.spec.ts` / `*.test.ts` Playwright defaults to:
  // `web/vite.config.ts`'s Vitest config (unmodified — outside this issue's
  // paths) uses the same conventional default for ITS OWN test discovery,
  // and its `include` is not scoped away from `web/tests/`. A file named
  // `foo.spec.ts` under this directory is therefore collected by BOTH
  // runners — Vitest fails it immediately (`test.describe` outside a
  // Playwright run), which briefly happened while this suite was written.
  // `*.pw.ts` is unambiguous and collides with neither tool's default.
  testMatch: /.*\.pw\.ts$/,
  fullyParallel: true,
  forbidOnly: !!process.env["CI"],
  // One retry in CI: a flake in a real browser (a timing race in a
  // Playwright-side wait) is real, but it should not be indistinguishable
  // from an accessibility or contrast regression on first read of a report.
  retries: process.env["CI"] ? 1 : 0,
  workers: process.env["CI"] ? 2 : undefined,
  reporter: process.env["CI"]
    ? [["list"], ["html", { open: "never", outputFolder: path.join(here, "playwright-report") }]]
    : "list",
  outputDir: path.join(here, "test-results"),
  timeout: 30_000,
  expect: {
    timeout: 5_000,
    // Screenshot comparison is pixel-exact by default (maxDiffPixelRatio 0);
    // this project's snapshots are static, deterministic component renders —
    // no animation, no network image, no real clock — so exactness is the
    // correct bar and a nonzero tolerance would quietly widen it.
    toHaveScreenshot: { maxDiffPixels: 0 },
  },
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
    colorScheme: "light",
  },
  webServer: {
    // `--host 127.0.0.1` explicitly: Vite's bare `--port` binds the hostname
    // `localhost`, which on some resolvers prefers `::1` — Playwright then
    // polls `127.0.0.1` (this config's own `baseURL`) forever and times out
    // even though the server is actually up. Binding the same address this
    // config polls removes the race.
    command: `npx vite --port ${PORT} --strictPort --host 127.0.0.1`,
    cwd: webRoot,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: !process.env["CI"],
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
