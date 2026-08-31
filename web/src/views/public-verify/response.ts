// SPDX-License-Identifier: Apache-2.0

/*
 * Reading a proof response, on a page that has been given no reason to believe
 * one.
 *
 * Every other view in this dashboard consumes an API run by the people who
 * built the view. This one is pointed at a deployment by a stranger whose
 * entire reason for being here is doc 06 §1's third audience: someone who
 * "trusts nothing about this deployment". So the first thing this page does
 * with a response is decline to assume it is a proof.
 *
 * ── WHY A PARSER AND NOT A CAST ────────────────────────────────────────────
 *
 * `response.json() as Proof` is the ordinary thing to write and it is wrong
 * here in a way that matters. TypeScript erases at the boundary: a cast makes
 * `proof.checks.map` a compile-time promise about a value that arrived over a
 * network. A malformed body would then reach the three-check panel, and the
 * panel would render whatever it could of it — which is a verdict assembled
 * out of a document nobody established was a verdict.
 *
 * doc 06 §4.6 has the rule: "No blank panels ... loading states time out into
 * an explicit error." A half-rendered panel is worse than a blank one. So a
 * body that is not a proof produces no proof, the view renders an error, and
 * `readProofResponse` is the only way this view obtains a Proof — there is no
 * second path and no cast anywhere in the directory.
 *
 * ── WHAT IS AND IS NOT CHECKED ─────────────────────────────────────────────
 *
 * SHAPE is checked: the fields doc 06 §4.1 and §3.6 need in order to render
 * anything, and the two closed vocabularies (four verdicts, three check
 * results) that a renderer would otherwise index into with a string from the
 * wire.
 *
 * TRUTH is not, and cannot be, checked here. Whether the certificate chains,
 * whether the entry is included, whether the trailer matches — those are
 * `internal/verify`'s and they are the reason the upstreams exist. What this
 * file establishes is only that a document CAN be read, so that the honest
 * refusals below are told apart from an unreadable answer.
 *
 * ── THE VERDICT FIELD IS PARSED AND THEN IGNORED ───────────────────────────
 *
 * `verdict` has to be one of four for the response to be readable, and then
 * nothing renders it: `verdictOf` in components/verification rolls the badge
 * up from the checks in front of the reader (doc 06 P1). The field is kept
 * because `unattributed` is not derivable from checks — a commit that claims
 * nothing has none — and dropping it would collapse VER-006's fourth state
 * into `unavailable`, which doc 06 §8's anti-pattern 2 forbids.
 *
 * ── A GAP IN THE BFF, REPORTED RATHER THAN PAPERED OVER ────────────────────
 *
 * `internal/api/rederive.go` produces the agrees/contradicts/underivable
 * findings that convict a lying server, and `internal/api/server.go`'s
 * handleProof does not put them in the response — `Rederive` has no
 * non-test caller in the repository. So `findings` is read here, and is
 * almost always absent in practice.
 *
 * This file deliberately does NOT re-derive them in TypeScript. A second
 * re-derivation, written in a second language against the same bytes, is a
 * second thing to keep in agreement with `internal/verify`, and the first time
 * the two disagreed the page would be accusing an honest deployment. The
 * absence is reported to the reader instead (strings.rederivation.absent), and
 * to the humans, as the one change to internal/api this page wants.
 */

import type { Finding, Proof } from "../../components/verification";

/** A response body, read or refused. There is no third outcome and no cast. */
export type ProofReading =
  | { readonly ok: true; readonly proof: Proof; readonly findings: readonly Finding[] }
  | { readonly ok: false; readonly reason: string };

const VERDICTS: readonly string[] = ["verified", "failed", "unavailable", "unattributed"];
const CHECK_RESULTS: readonly string[] = ["verified", "failed", "unavailable"];
const AGREEMENTS: readonly string[] = ["agrees", "contradicts", "underivable"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The field path of the first thing that is not what it must be, or null. */
function firstFault(body: unknown): string | null {
  if (!isObject(body)) return "(the body is not a JSON object)";

  if (typeof body["commit_sha"] !== "string" || body["commit_sha"] === "") {
    return "commit_sha";
  }
  if (typeof body["repo"] !== "string") return "repo";
  if (typeof body["data_as_of"] !== "string") return "data_as_of";
  if (typeof body["verdict"] !== "string" || !VERDICTS.includes(body["verdict"])) {
    return "verdict";
  }

  const checks = body["checks"];
  if (!Array.isArray(checks)) return "checks";
  for (const [index, check] of checks.entries()) {
    if (!isObject(check)) return `checks[${index}]`;
    if (typeof check["name"] !== "string" || check["name"] === "") {
      return `checks[${index}].name`;
    }
    if (typeof check["result"] !== "string" || !CHECK_RESULTS.includes(check["result"])) {
      return `checks[${index}].result`;
    }
  }

  const upstreams = body["upstreams"];
  if (!Array.isArray(upstreams)) return "upstreams";
  for (const [index, upstream] of upstreams.entries()) {
    if (!isObject(upstream)) return `upstreams[${index}]`;
    if (typeof upstream["name"] !== "string" || upstream["name"] === "") {
      return `upstreams[${index}].name`;
    }
    if (typeof upstream["url"] !== "string") return `upstreams[${index}].url`;
    // The one field a renderer must not coerce: an upstream that did not
    // answer and an upstream that said nothing about answering are the same
    // thing, and neither is `true`.
    if (typeof upstream["reachable"] !== "boolean") {
      return `upstreams[${index}].reachable`;
    }
  }

  for (const name of ["claim", "certificate", "entry", "material"]) {
    if (!isObject(body[name])) return name;
  }
  const entry = body["entry"] as Record<string, unknown>;
  if (typeof entry["log_index"] !== "number") return "entry.log_index";
  if (typeof entry["time_attested"] !== "boolean") return "entry.time_attested";

  const findings = body["findings"];
  if (findings !== undefined) {
    if (!Array.isArray(findings)) return "findings";
    for (const [index, finding] of findings.entries()) {
      if (!isObject(finding)) return `findings[${index}]`;
      if (typeof finding["name"] !== "string") return `findings[${index}].name`;
      if (
        typeof finding["result"] !== "string" ||
        !AGREEMENTS.includes(finding["result"])
      ) {
        return `findings[${index}].result`;
      }
    }
  }

  return null;
}

/**
 * Read a response body as a proof, or refuse it and say which field decided.
 *
 * The field path is deliberately technical and is rendered verbatim beside the
 * refusal: doc 06 §6.1 asks copy to "say what was checked and what happened",
 * and "the answer was not a proof" without naming the field is the opposite of
 * that. It is also the one piece of information that lets a deployment's
 * operator fix it.
 */
export function readProofResponse(body: unknown): ProofReading {
  const fault = firstFault(body);
  if (fault !== null) return { ok: false, reason: fault };

  const proof = body as unknown as Proof;
  const findings = ((body as Record<string, unknown>)["findings"] ?? []) as readonly Finding[];
  return { ok: true, proof, findings };
}
