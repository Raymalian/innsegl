// SPDX-License-Identifier: Apache-2.0

/**
 * Innsegl — non-repudiable identity and attribution for AI agents.
 *
 * This package holds the name `innsegl` on npm for the Innsegl project. It is
 * a name reservation, not the implementation: Innsegl is written in Go and
 * lives at the module path below.
 *
 * Holding the name is a security control, not housekeeping. Innsegl's product
 * is that an artifact's origin can be verified without trusting whoever serves
 * it; a package published under Innsegl's own name by someone else would be
 * exactly the attack Innsegl exists to make detectable (doc 04, asset A6,
 * abuse case AB-09). So this package is deliberately not an empty shell — it
 * tells whoever installs it where the real implementation is, and what a
 * package that is *not* ours looks like.
 */

export const version = "0.0.2";

export const canonical = Object.freeze({
  source: "https://github.com/Raymalian/innsegl",
  home: "https://innsegl.dev",
  goModule: "innsegl.dev/innsegl",
  npmScope: "@innsegl",
  pypiProject: "innsegl",
  license: "Apache-2.0",
});

export function main() {
  const lines = [
    "Innsegl — non-repudiable identity and attribution for AI agents.",
    "",
    "This npm package holds the name `innsegl` for the project. It is a name",
    "reservation, not the implementation: Innsegl is written in Go.",
    "",
    `  Source     ${canonical.source}`,
    `  Home       ${canonical.home}`,
    `  Go module  ${canonical.goModule}`,
    `  Licence    ${canonical.license}`,
    "",
    `The ${canonical.npmScope} npm scope and the PyPI project \`${canonical.pypiProject}\` are held by`,
    "the same project. A package claiming to be Innsegl that is not linked from",
    "the repository above is not ours — please report it:",
    `  ${canonical.source}/security`,
  ];
  for (const line of lines) console.log(line);
}
