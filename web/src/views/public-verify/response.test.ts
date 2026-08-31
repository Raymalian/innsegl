// SPDX-License-Identifier: Apache-2.0

/*
 * FE-061 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   U | The public page refuses a response it cannot read, field by field | A
 *     body missing or mistyping any field the proof chain renders yields no
 *     Proof and names the field; a valid body yields one | FD §3.6, §4.6, P2
 *
 * doc 07's FE-007 covers the malformed case from the outside: the page shows
 * an error and no verdict. This is the same rule from the inside, at the one
 * function through which a response becomes a Proof, and it is a separate ID
 * because it is where the rule can be made exhaustive. FE-007 can afford one
 * malformed body; this can afford one per field, and a field added later with
 * no check is a row missing from the table below rather than a case nobody
 * thought to render.
 *
 * The `verdict` case is the one worth reading twice. `verdict` is validated
 * and then never rendered — components/verification rolls the badge up from
 * the checks (doc 06 P1). It is validated anyway because `unattributed` is not
 * derivable from checks (a commit that claims nothing has none), so the field
 * is load-bearing for exactly one of the four states, and a value outside the
 * four would reach `VERDICT_TONE[verdict]` as an undefined class string.
 */

import { describe, expect, it } from "vitest";

import { readProofResponse } from "./response";
import { COMMIT_SHA, wireProof } from "./fixtures";

/** The fixture with one field replaced, at any depth. */
function mangled(path: string, value: unknown): unknown {
  const body = structuredClone(wireProof()) as Record<string, unknown>;
  const parts = path.split(".");
  let node: Record<string, unknown> = body;
  for (const part of parts.slice(0, -1)) {
    node = node[part] as Record<string, unknown>;
  }
  const last = parts[parts.length - 1] as string;
  if (value === undefined) delete node[last];
  else node[last] = value;
  return body;
}

describe("FE-061 a body that is a proof", () => {
  it("is read, and carries the commit it names", () => {
    const reading = readProofResponse(wireProof());
    expect(reading.ok).toBe(true);
    if (!reading.ok) return;
    expect(reading.proof.commit_sha).toBe(COMMIT_SHA);
    expect(reading.proof.checks).toHaveLength(3);
    expect(reading.findings).toEqual([]);
  });

  it("keeps the findings the deployment re-derived, when it sends any", () => {
    const reading = readProofResponse(
      wireProof({
        findings: [
          { name: "the log index is the one the response reports", result: "contradicts", detail: "82914 vs 1" },
          { name: "the verdict is the rollup of the reported checks", result: "underivable" },
        ],
      }),
    );
    expect(reading.ok).toBe(true);
    if (!reading.ok) return;
    expect(reading.findings.map((f) => f.result)).toEqual([
      "contradicts",
      "underivable",
    ]);
  });

  it("tolerates a field this build does not know about", () => {
    const body = { ...(wireProof() as Record<string, unknown>), future_field: 7 };
    expect(readProofResponse(body).ok).toBe(true);
  });
});

/*
 * One row per way a body fails to be a proof. The expected value is the field
 * path the refusal names, because "not a proof" without the field is exactly
 * the copy doc 06 §6.1 forbids — and it is the only thing that lets the
 * deployment's operator fix it.
 */
const REFUSED: ReadonlyArray<readonly [string, unknown, string]> = [
  ["the body is not an object", 42, "(the body is not a JSON object)"],
  ["the body is null", null, "(the body is not a JSON object)"],
  ["the body is an array", [], "(the body is not a JSON object)"],
  ["commit_sha is absent", mangled("commit_sha", undefined), "commit_sha"],
  ["commit_sha is empty", mangled("commit_sha", ""), "commit_sha"],
  ["commit_sha is a number", mangled("commit_sha", 1), "commit_sha"],
  ["repo is absent", mangled("repo", undefined), "repo"],
  ["data_as_of is absent", mangled("data_as_of", undefined), "data_as_of"],
  ["verdict is absent", mangled("verdict", undefined), "verdict"],
  ["verdict is not one of the four", mangled("verdict", "probably", ), "verdict"],
  ["checks is absent", mangled("checks", undefined), "checks"],
  ["checks is not an array", mangled("checks", {}), "checks"],
  ["a check is not an object", mangled("checks", ["ok"]), "checks[0]"],
  ["a check has no name", mangled("checks", [{ result: "verified" }]), "checks[0].name"],
  [
    "a check result is not one of the three",
    mangled("checks", [{ name: "Fulcio certificate chain valid", result: "probably" }]),
    "checks[0].result",
  ],
  ["upstreams is absent", mangled("upstreams", undefined), "upstreams"],
  ["upstreams is not an array", mangled("upstreams", "fulcio"), "upstreams"],
  ["an upstream has no name", mangled("upstreams", [{ url: "u", reachable: true }]), "upstreams[0].name"],
  [
    "an upstream does not say whether it answered",
    mangled("upstreams", [{ name: "fulcio", url: "u" }]),
    "upstreams[0].reachable",
  ],
  [
    "an upstream says it answered with a string",
    mangled("upstreams", [{ name: "fulcio", url: "u", reachable: "true" }]),
    "upstreams[0].reachable",
  ],
  ["claim is absent", mangled("claim", undefined), "claim"],
  ["certificate is absent", mangled("certificate", undefined), "certificate"],
  ["entry is absent", mangled("entry", undefined), "entry"],
  ["material is absent", mangled("material", undefined), "material"],
  ["entry.log_index is a string", mangled("entry.log_index", "82914"), "entry.log_index"],
  ["entry.time_attested is absent", mangled("entry.time_attested", undefined), "entry.time_attested"],
  ["findings is not an array", mangled("findings", { a: 1 }), "findings"],
  ["a finding has no name", mangled("findings", [{ result: "agrees" }]), "findings[0].name"],
  [
    "a finding's result is not one of the three",
    mangled("findings", [{ name: "x", result: "probably" }]),
    "findings[0].result",
  ],
];

describe("FE-061 a body that is not a proof", () => {
  it.each(REFUSED)("%s", (_name, body, field) => {
    const reading = readProofResponse(body);
    expect(reading.ok).toBe(false);
    if (reading.ok) return;
    expect(reading.reason).toBe(field);
  });

  it("covers every field the parser checks, so a new one cannot be forgotten", () => {
    // A crude but honest completeness signal: the table has to grow when the
    // parser does. If a field is added to firstFault and not here, this drops.
    expect(REFUSED.length).toBeGreaterThanOrEqual(29);
  });
});

/*
 * `upstreams[n].reachable` is singled out because it is the field that decides
 * whether this page may show a verdict at all (I5). A parser that coerced it
 * would turn "the deployment said nothing about whether it reached Fulcio"
 * into "it reached Fulcio", which is the database-only verdict arriving
 * through the type system instead of through the UI.
 */
describe("FE-061 reachable is a boolean or the body is not a proof", () => {
  it.each([["a truthy string", "yes"], ["a one", 1], ["null", null], ["absent", undefined]] as const)(
    "refuses %s",
    (_name, value) => {
      const body = mangled("upstreams", [
        { name: "fulcio", url: "u", checked_at: "t", ...(value === undefined ? {} : { reachable: value }) },
      ]);
      const reading = readProofResponse(body);
      expect(reading.ok).toBe(false);
    },
  );
});
