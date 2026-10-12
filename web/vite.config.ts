// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

import { defineConfig, type Plugin } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

import { THEME_BOOTSTRAP } from "./src/app/theme";

/**
 * #612 (FE-155): the built page carries no inline script, so the dashboard's
 * Content-Security-Policy (internal/api/ui.go, dashboardCSP) can say
 * `script-src 'self'` and nothing more.
 *
 * index.html keeps the theme bootstrap inline in source — FE-018 asserts the
 * exact text and the blocking `<script>` tag there, and the dev server sends
 * no policy. At build this moves it, byte for byte, to a hashed file under
 * /assets/ and loads it with a classic `<script src>` in the same place: still
 * parser-blocking in the head, so it still runs before the first paint.
 *
 * The build fails, rather than shipping a page the policy breaks, when the
 * bootstrap is not found or any other inline script remains. `innsegl api`
 * refuses such a page at start as well.
 */
function externaliseThemeBootstrap(): Plugin {
  const source = THEME_BOOTSTRAP + "\n";
  const hash = createHash("sha256").update(source).digest("hex").slice(0, 10);
  const fileName = `assets/theme-${hash}.js`;
  return {
    name: "innsegl:externalise-theme-bootstrap",
    apply: "build",
    transformIndexHtml: {
      order: "post",
      handler(html) {
        const inline = /<script>\s*([\s\S]*?)\s*<\/script>/g;
        let moved = 0;
        const out = html.replace(inline, (whole, body: string) => {
          if (body !== THEME_BOOTSTRAP) return whole;
          moved++;
          return `<script src="/${fileName}"></script>`;
        });
        if (moved !== 1) {
          throw new Error(`index.html: expected the theme bootstrap inline once, found it ${moved} times`);
        }
        for (const [tag, attrs = "", body = ""] of out.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
          if (!/\bsrc\s*=/i.test(attrs) || body.trim() !== "") {
            throw new Error(`index.html: an inline script the dashboard's CSP would block: ${tag}`);
          }
        }
        return out;
      },
    },
    generateBundle() {
      this.emitFile({ type: "asset", fileName, source });
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), externaliseThemeBootstrap()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    css: true,
  },
});
