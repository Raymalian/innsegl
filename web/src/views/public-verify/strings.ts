// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the public verification page can render.
 *
 * doc 06 §6.3 keeps copy out of components so a translator moves one file, and
 * `web/src/app/nocopyincomponents.test.ts` parses every .tsx under web/src to
 * prove none escaped. The catalogue lives in this directory rather than in the
 * shell's, for the same reason the two component directories each keep their
 * own: this view is separately owned, and folding the three together later is
 * a mechanical edit.
 *
 * doc 06 §6.1 governs the wording and this page is where it matters most,
 * because this page is read by someone who has been given no reason to believe
 * it:
 *
 *   "Factual, unvarnished, specific. Say what was checked and what happened...
 *    Errors state what failed and what the user can do: 'Fulcio unreachable —
 *    verification can't run. Retry, or verify offline with the material
 *    below.' Banned vocabulary: 'successfully', 'seamless', 'trusted by',
 *    exclamation marks in system copy."
 *
 * `blocked.title` below is that sentence, with the upstream name filled in.
 * It is quoted rather than paraphrased on purpose: doc 06 wrote the model
 * error copy for this exact situation on this exact page.
 *
 * doc 06 §5.4: sentence case everywhere; labels carry no terminal punctuation,
 * helper text does.
 */

export const strings = {
  page: {
    /* The QUESTION, which is what a stranger arriving with a SHA actually has.
     * doc 06 §3.6 makes this page "the adoptability showcase: it must work as
     * a standalone artifact someone screenshots into an audit report", and the
     * first line of that artifact has to say what the page answers rather than
     * name the tool. §6.1: "Factual, unvarnished, specific."
     *
     * `heading` below is kept and still used — it is the NAVIGATION label and
     * the document title, where naming the tool is exactly right. Two jobs,
     * two strings, neither borrowed for the other. */
    question: "Who produced this commit?",
    heading: "Verify a commit",
    /* The page's whole claim, stated before any result so a reader knows what
     * they are about to be shown. doc 06 P1: evidence over assertion. */
    intro:
      "Enter a commit SHA. Three checks run live, when you ask, against Fulcio and Rekor. This page cannot read the ledger, so it has no other way to answer.",
    what: "this commit's proof",
  },

  form: {
    commitLabel: "Commit SHA",
    commitHint: "A commit SHA, or any name for a commit this server can resolve.",
    repoLabel: "Repository",
    repoHint: "Optional. If empty, every repository on this server is searched.",
    submit: "Check this commit",
    /* Not an error state: nothing has been asked yet. */
    idleTitle: "No commit named yet",
    idleDetail: "Enter a commit SHA above to run the three checks.",
  },

  /* doc 06 §6.1's model error copy, which was written for this page. */
  blocked: {
    title: (upstreams: string) => `${upstreams} unreachable — verification can't run`,
    detail: "Retry, or verify offline with the material below.",
    /* An upstream the response does not mention at all. Absence is not an
     * answer, and reading it as one would be the database-only verdict this
     * page exists to refuse (I5). */
    silent: (upstreams: string) =>
      `${upstreams} did not report a live check, so nothing here rests on one.`,
  },

  liveCheck: {
    heading: "Live checks",
    detail:
      "What this server asked each service when you submitted, and what came back.",
    endpoint: "Endpoint",
    checkedAt: "Checked at",
    answered: "Answered",
    unanswered: "Did not answer",
    absent: "Not reported",
    /* Named for assistive technology; the table is real data, not chrome. */
    tableLabel: "Upstream live checks",
    upstream: "Upstream",
    outcome: "Outcome",
  },

  trailer: {
    heading: "What the commit message claims",
    detail:
      "What the commit message says about who made it. This is only a claim until a certificate backs it up.",
    identity: "Agent-Identity",
    run: "Agent-Run",
    task: "Agent-Task",
    absent: "Not present.",
    none: "This commit has no Agent-Identity line, so it claims no agent made it.",
  },

  certificate: {
    heading: "Signing certificate",
    detail: "What the certificate that signed this commit says about itself.",
    spiffeId: "Identity in the certificate",
    issuer: "Issuer",
    serial: "Serial number",
    notBefore: "Valid from",
    notAfter: "Valid until",
    fingerprint: "SHA-256 fingerprint",
    none: "No certificate was found for this commit.",
  },

  entry: {
    heading: "Public log entry",
    detail: "The Rekor record this commit's signature was checked against.",
    uuid: "Entry ID",
    logIndex: "Log number",
    logId: "Log ID",
    integratedAt: "Integrated at",
    /* doc 06 P2: a timestamp the log did not sign is a number in a response,
     * not a statement by the log, and the difference has to be visible. */
    attested: "Signed by the log",
    unattested: "Not signed by the log. Treat the time above as unverified.",
    none: "No public log entry was found for this commit.",
    raw: "The entry as the log returned it",
  },

  rederivation: {
    heading: "Claims recomputed",
    detail:
      "This server recomputed each claim from the material it gave you, and says where they differ.",
    agrees: "Agrees",
    contradicts: "Disagrees",
    underivable: "Could not be worked out",
    /* The endpoint does not carry these today (see the module comment in
     * response.ts). Saying so is better than an empty section a reader takes
     * for a clean bill. */
    absent:
      "This response held no recomputed claims, so nothing here was checked a second time.",
    contradicted:
      "The response disagrees with its own material, so none of it is taken on trust.",
  },

  offline: {
    heading: "Check this yourself",
    detail:
      "Nothing here has to be taken on trust. Everything the checks used is on this page, and anyone can ask the services in the live checks table directly.",
    command: "Command",
    commandValue: "innsegl verify <commit sha> --repo <path> --fulcio-url <url> --rekor-url <url>",
    commitObjectId: "Commit ID, recomputed",
    dataAsOf: "Response produced at",
    repo: "Repository",
  },

  failure: {
    /* doc 06 §4.6's dependency-error state, said about this page's own
     * dependency rather than about the ledger. */
    unreachableTitle: "Can't reach this server",
    unreachableDetail: "Showing nothing rather than guessing.",
    notFoundTitle: "No such commit here",
    malformedTitle: "This server's answer is not a proof",
    malformedDetail:
      "Nothing is rendered from it. A response that cannot be read cannot be evidence.",
    rejectedTitle: "This server refused the request",
  },
} as const;

export type PublicVerifyStrings = typeof strings;

/** Display names for the two upstreams doc 06 §3.6 names, so `fulcio` reads as
 * Fulcio in prose. An upstream this build does not know keeps its own
 * spelling: renaming a dependency in the interface would hide which one it is. */
const UPSTREAM_DISPLAY_NAMES: Readonly<Record<string, string>> = {
  fulcio: "Fulcio",
  rekor: "Rekor",
};

export function upstreamName(name: string): string {
  return UPSTREAM_DISPLAY_NAMES[name] ?? name;
}
