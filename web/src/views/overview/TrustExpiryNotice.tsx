// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0073: a warning a year and 90 days before any CA in use expires — the
 * Fulcio root, the SPIRE upstream CA, the gateway CA.
 *
 * The dates are GET /api/v1/health's `trust_expiries`, which the query API
 * reads from the deployment's trust history; the thresholds are applied on
 * the server, so the dashboard and `innsegl status` cannot disagree about
 * which CA is near expiry. Nothing renders when none is. A GET only (P6).
 */

import { useEffect, useState } from "react";

import { DEFAULT_API_BASE } from "./data";
import { strings } from "./strings";
import { degraded, hairline } from "./styles";

/** One CA in use and when it expires. `warning` is empty when it is not near. */
export interface TrustExpiry {
  readonly name: string;
  readonly notAfter: string;
  readonly warning: string;
}

/** One thing the trust watch found wrong, and when it was first seen. */
export interface TrustProblem {
  readonly text: string;
  readonly since: string;
}

/** Both halves of the health response's trust state. */
export interface TrustState {
  readonly expiries: readonly TrustExpiry[];
  readonly problems: readonly TrustProblem[];
}

/** `GET /api/v1/health`'s `trust_expiries` and `trust_problems`. Entries that
 * are not shaped like one are dropped rather than rendered half-read. */
export async function fetchTrustState(base: string, signal: AbortSignal): Promise<TrustState> {
  const response = await fetch(`${base}/health`, { signal, headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${base}/health answered ${response.status}`);
  const body = (await response.json()) as { trust_expiries?: unknown; trust_problems?: unknown };
  const problems: TrustProblem[] = [];
  for (const item of Array.isArray(body.trust_problems) ? (body.trust_problems as unknown[]) : []) {
    const o = item as Record<string, unknown>;
    if (typeof o["text"] !== "string" || typeof o["since"] !== "string") continue;
    problems.push({ text: o["text"], since: o["since"] });
  }
  return { expiries: expiriesOf(body.trust_expiries), problems };
}

/** The expiries alone. */
export async function fetchTrustExpiries(
  base: string,
  signal: AbortSignal,
): Promise<readonly TrustExpiry[]> {
  return (await fetchTrustState(base, signal)).expiries;
}

function expiriesOf(value: unknown): readonly TrustExpiry[] {
  const list = Array.isArray(value) ? (value as unknown[]) : [];
  const out: TrustExpiry[] = [];
  for (const item of list) {
    const o = item as Record<string, unknown>;
    if (typeof o["name"] !== "string" || typeof o["not_after"] !== "string") continue;
    out.push({
      name: o["name"],
      notAfter: o["not_after"],
      warning: typeof o["warning"] === "string" ? o["warning"] : "",
    });
  }
  return out;
}

const NO_TRUST_STATE: TrustState = { expiries: [], problems: [] };

/** The trust state, read once per mount. Empty until it arrives, and on a
 * failed read: the warning is an addition to the page, never a blocker. */
export function useTrustState(base: string = DEFAULT_API_BASE): TrustState {
  const [state, setState] = useState<TrustState>(NO_TRUST_STATE);
  useEffect(() => {
    const controller = new AbortController();
    fetchTrustState(base, controller.signal).then(setState, () => setState(NO_TRUST_STATE));
    return () => controller.abort();
  }, [base]);
  return state;
}

export interface TrustExpiryNoticeProps {
  readonly expiries: readonly TrustExpiry[];
  readonly problems?: readonly TrustProblem[];
}

export function TrustExpiryNotice({ expiries, problems = [] }: TrustExpiryNoticeProps) {
  const near = expiries.filter((e) => e.warning !== "");
  if (near.length === 0 && problems.length === 0) return null;
  return (
    <section
      aria-label={strings.trustExpiry.regionLabel}
      className={`${hairline} ${degraded} flex flex-col gap-1 rounded-md p-3`}
    >
      {problems.map((p) => (
        <p key={p.text}>{strings.trustExpiry.problem(p.text, p.since.slice(0, 10))}</p>
      ))}
      {near.map((e) => (
        <p key={e.name}>{strings.trustExpiry.line(e.name, e.warning, e.notAfter.slice(0, 10))}</p>
      ))}
    </section>
  );
}
