// SPDX-License-Identifier: Apache-2.0

// The browser entry point. It does three things and nothing else: load the
// stylesheet, reconcile the theme attribute with what was stored, and mount
// the shell.
//
// The theme call is not the primary mechanism — index.html applies the
// override before the first paint, which is the only place it can be applied
// without a flash. This is what keeps the two in step if that script was
// blocked, and it is one attribute write.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { StringsProvider } from "./i18n";
import "./index.css";
import { applyPreference, readPreference } from "./theme";

applyPreference(readPreference());

const container = document.getElementById("root");
if (container === null) {
  throw new Error("innsegl: the document has no #root to mount into");
}

createRoot(container).render(
  <StrictMode>
    <StringsProvider>
      <App />
    </StringsProvider>
  </StrictMode>,
);
