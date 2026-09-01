// SPDX-License-Identifier: Apache-2.0

// The harness's entry point. Mirrors web/src/app/main.tsx's shape — mount and
// nothing else — but loads no theme bootstrap: the harness's light/dark mode
// is driven by Playwright's `colorScheme` context option (real
// `prefers-color-scheme`, the mechanism doc 06 §5.1 and ADR-0038 decision 3
// actually specify), not by the manual override.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "../../src/app/index.css";
import { Harness } from "./Harness";

const container = document.getElementById("root");
if (container === null) {
  throw new Error("innsegl test harness: the document has no #root to mount into");
}

createRoot(container).render(
  <StrictMode>
    <Harness />
  </StrictMode>,
);
