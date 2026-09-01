// SPDX-License-Identifier: Apache-2.0

/*
 * Evidence files.
 *
 * Every probe writes what it measured to reviews/evidence/, and those files are
 * committed. The review document quotes them; it does not paraphrase them. A
 * reviewer who does not believe a verdict re-runs the probe and diffs.
 *
 * Each file carries the commit it was produced at and the built stylesheet it
 * read, because a measurement with no provenance is a claim.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const REVIEWS_DIR = resolve(here, "..");
export const REPO_DIR = resolve(REVIEWS_DIR, "..");
export const WEB_DIR = join(REPO_DIR, "web");
export const EVIDENCE_DIR = join(REVIEWS_DIR, "evidence");

function head(): string {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: REPO_DIR,
      encoding: "utf8",
    }).trim();
  } catch {
    return "unknown";
  }
}

export class Evidence {
  private readonly lines: string[] = [];

  constructor(
    private readonly file: string,
    private readonly title: string,
  ) {}

  say(line = ""): this {
    this.lines.push(line);
    return this;
  }

  section(title: string): this {
    this.say();
    this.say(`── ${title} ${"─".repeat(Math.max(0, 74 - title.length))}`);
    this.say();
    return this;
  }

  block(text: string): this {
    for (const line of text.split("\n")) this.say(`    ${line}`);
    return this;
  }

  write(): string {
    mkdirSync(EVIDENCE_DIR, { recursive: true });
    const path = join(EVIDENCE_DIR, this.file);
    const header = [
      this.title,
      "",
      `Produced by reviews/probes/, RM-050 (#58). Working tree at ${head()}.`,
      `Node ${process.version}. Rendered in jsdom via @testing-library/react.`,
      "",
      "=".repeat(78),
    ];
    writeFileSync(path, `${[...header, ...this.lines].join("\n")}\n`, "utf8");
    return path;
  }
}
