// SPDX-License-Identifier: Apache-2.0

/*
 * Attempting a violation, and recording what stops it.
 *
 * Several of ADR-0038's and the components' claims are STRUCTURAL — "this is
 * unrepresentable", not "this is absent today". doc 06 §9 asks for measurement
 * rather than assertion, and the measurement for a structural claim is not a
 * render: it is writing the offending code and showing the toolchain refuse
 * it. A claim nobody tried to break is a claim.
 *
 * The source of each attempt is written into the evidence file verbatim, so a
 * reader sees exactly what was tried rather than a description of it. The
 * attempts are never committed as files, because a tracked file that must fail
 * to typecheck is a trap for whoever next runs a whole-repo check.
 *
 * The scratch directory lives inside web/node_modules, which is gitignored,
 * and relative imports from there reach web/src the way any module in the
 * project does.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { WEB_DIR } from "./evidence";

const SCRATCH = join(WEB_DIR, "node_modules", ".innsegl-review");

export interface Attempt {
  /** The source that was written, exactly as the compiler saw it. */
  readonly source: string;
  /** The compiler's own words, or "" when it accepted the code. */
  readonly refusal: string;
  readonly accepted: boolean;
}

/**
 * Typecheck one TSX file against the dashboard's own compiler settings.
 *
 * The flags are web/tsconfig.json's, restated rather than inherited: that file
 * includes only `src`, so a file outside it is not in the project and `-p`
 * would silently check nothing.
 */
export function typecheck(name: string, source: string): Attempt {
  mkdirSync(SCRATCH, { recursive: true });
  const file = join(SCRATCH, `${name}.tsx`);
  writeFileSync(file, source, "utf8");
  try {
    execFileSync(
      "npx",
      [
        "tsc",
        "--noEmit",
        "--strict",
        "--noUncheckedIndexedAccess",
        "--jsx",
        "react-jsx",
        "--target",
        "ES2022",
        "--module",
        "ESNext",
        "--moduleResolution",
        "bundler",
        "--lib",
        "ES2022,DOM,DOM.Iterable",
        "--skipLibCheck",
        "--types",
        "react",
        file,
      ],
      { cwd: WEB_DIR, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    return { source, refusal: "", accepted: true };
  } catch (error) {
    const shell = error as { stdout?: string; stderr?: string };
    const refusal = `${shell.stdout ?? ""}${shell.stderr ?? ""}`
      .split("\n")
      .map((line) => line.replace(/^.*\.innsegl-review\//, ""))
      .filter((line) => line.trim() !== "")
      .join("\n");
    return { source, refusal, accepted: false };
  } finally {
    rmSync(file, { force: true });
  }
}
