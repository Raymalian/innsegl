// SPDX-License-Identifier: Apache-2.0

/*
 * Which segment of a SPIFFE ID differs — the machinery behind doc 06 §4.1's
 * "on mismatch, the differing segment is highlighted".
 *
 * This mirrors `verify.DiffIdentity` in internal/verify/trailers.go: the same
 * grammar, the same six segment names, the same first-difference rule, and the
 * same refusal to compare two identities that do not both parse. It is a
 * mirror rather than a second opinion — the verdict is the backend's, and
 * nothing here can change one. What it computes is where to put the mark.
 *
 * Doing it in the client at all is a deliberate choice with one reason. The
 * backend already names the differing segment, in prose, in check 3's
 * "differing segment" fact:
 *
 *     run-id: the trailer says "run-0e91bd", the certificate says "run-7f3a2c"
 *
 * A sentence is not a highlight. To mark the differing text inside a rendered
 * identity the panel has to know which characters they are, and parsing that
 * sentence back into an offset would be worse than splitting the identity on
 * the grammar both sides already agree about.
 *
 * The six names are a PROTECTED SURFACE (VERSIONING.md surface 3): they are
 * what a reader sees when a comparison fails, and "the identities differ" is
 * not a finding anybody can act on. FE-004 asserts them character for
 * character against internal/verify's own list.
 */

/**
 * The grammar of IP §1 and doc 02 §5:
 *
 *     spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}
 */
export const SPIFFE_SEGMENT_NAMES = [
  "scheme",
  "trust-domain",
  "agent",
  "agent-type",
  "task-id",
  "run-id",
] as const;

export type SegmentName = (typeof SPIFFE_SEGMENT_NAMES)[number];

/** What separates a segment from the one before it. Part of the grammar, so
 * it lives here rather than as a literal in a component: the panel renders
 * `separator + value` and never has to know how a SPIFFE ID is punctuated. */
const SEPARATORS: readonly string[] = ["", "://", "/", "/", "/", "/"];

/** One rendered piece of an identity. */
export interface Segment {
  /** The grammar position, or `identity` for a value that does not parse. */
  readonly name: SegmentName | "identity";
  readonly value: string;
  readonly separator: string;
  /** Whether this is the piece the comparison found differing. */
  readonly differs: boolean;
}

export type IdentityDiff =
  | { readonly kind: "same" }
  | {
      readonly kind: "segment";
      readonly index: number;
      readonly name: SegmentName;
      readonly trailer: string;
      readonly certificate: string;
    }
  /** One of them does not parse, or they differ outside the six named
   * segments. Either way the two cannot be compared segment by segment, and
   * saying so is more use than pointing at a segment that is not the answer. */
  | { readonly kind: "uncomparable" };

/** Breaks an identity into its six segments, or null if it does not parse. */
export function splitSPIFFEID(id: string): readonly string[] | null {
  const at = id.indexOf("://");
  if (at <= 0) return null;
  const scheme = id.slice(0, at);
  const parts = id.slice(at + 3).split("/");
  if (parts.length !== SPIFFE_SEGMENT_NAMES.length - 1) return null;
  if (parts.some((part) => part === "")) return null;
  return [scheme, ...parts];
}

/** Names the first segment in which two SPIFFE IDs differ. */
export function diffIdentity(trailer: string, certificate: string): IdentityDiff {
  if (trailer === certificate) return { kind: "same" };
  const claimed = splitSPIFFEID(trailer);
  const proven = splitSPIFFEID(certificate);
  if (claimed === null || proven === null) return { kind: "uncomparable" };
  for (let i = 0; i < SPIFFE_SEGMENT_NAMES.length; i += 1) {
    const a = claimed[i];
    const b = proven[i];
    const name = SPIFFE_SEGMENT_NAMES[i];
    if (a === undefined || b === undefined || name === undefined) break;
    if (a !== b) {
      return { kind: "segment", index: i, name, trailer: a, certificate: b };
    }
  }
  // Six equal segments and two unequal strings: only the punctuation between
  // them can differ, which the split above does not preserve.
  return { kind: "uncomparable" };
}

/**
 * The pieces to render for one identity, with the differing one marked.
 *
 * An identity that does not parse is returned whole, as a single piece, marked
 * if the comparison found any difference at all. Truncating or guessing at the
 * structure of a malformed identity would be inventing a reading of the very
 * value under suspicion.
 */
export function segmentsOf(id: string, diff: IdentityDiff): readonly Segment[] {
  const parts = splitSPIFFEID(id);
  if (parts === null) {
    return [
      { name: "identity", value: id, separator: "", differs: diff.kind !== "same" },
    ];
  }
  return parts.map((value, index) => ({
    name: SPIFFE_SEGMENT_NAMES[index] ?? "identity",
    value,
    separator: SEPARATORS[index] ?? "/",
    differs: diff.kind === "segment" && diff.index === index,
  }));
}
