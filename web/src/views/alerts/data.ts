// SPDX-License-Identifier: Apache-2.0

/*
 * What the notification menu and the alert detail view read — ADR-0054,
 * doc 06 §7.
 *
 * Two GETs for the menu, both already served and both already read by the
 * overview before ADR-0054 moved alerts off it:
 *
 *   GET /api/v1/alerts?limit=50   the open alerts to list
 *   GET /api/v1/overview          `open_alerts`, the aggregate count
 *
 * They are reported apart for the reason the overview gave: a failed list
 * must not make the menu say LESS than the count it already has (P2), so the
 * badge falls back to the count and the menu says only the count is known.
 *
 * The header lives on every page, so unlike a view it is not re-read by a
 * navigation. It reads again on an interval instead, which is what lets a new
 * alert reach a page that is already open — and what the menu's polite live
 * region announces. Nothing is cached between reads (doc 06 §8 anti-pattern
 * 1): each answer replaces the last.
 *
 * The detail view has no endpoint of its own to call — `internal/api` serves
 * the feed, not one alert — so it pages the feed by cursor until the event ID
 * turns up or the feed ends, and says which.
 */

import { useCallback, useEffect, useState } from "react";

import { DEFAULT_API_BASE, fetchAlerts, fetchOverview } from "../overview/data";
import type { AlertRecord, AlertsPage } from "../overview/types";

/** How often the header reads again. A minute: an alert is a ledger event
 * the reconciler appends on its own cadence, not a keystroke. */
export const DEFAULT_POLL_MS = 60_000;

/** internal/api's MaxPageSize, so a search reads as few pages as it can. */
const SEARCH_PAGE_SIZE = 200;
/** A bound on the search, so a runaway cursor cannot page forever. */
const SEARCH_MAX_PAGES = 50;

export interface OpenAlerts {
  /** True until the first pair of reads has settled. */
  readonly loading: boolean;
  /** Null when the list did not answer. */
  readonly alerts: readonly AlertRecord[] | null;
  /** `open_alerts` from the overview; null when that did not answer. */
  readonly openCount: number | null;
}

export interface UseOpenAlertsOptions {
  readonly base?: string;
  /** 0 reads once and never again. */
  readonly pollMs?: number;
}

export function useOpenAlerts({
  base = DEFAULT_API_BASE,
  pollMs = DEFAULT_POLL_MS,
}: UseOpenAlertsOptions = {}): OpenAlerts {
  const [state, setState] = useState<OpenAlerts>({
    loading: true,
    alerts: null,
    openCount: null,
  });

  useEffect(() => {
    let live = true;
    let controller = new AbortController();

    const read = async () => {
      controller = new AbortController();
      const [alerts, overview] = await Promise.allSettled([
        fetchAlerts(base, controller.signal),
        fetchOverview(base, controller.signal),
      ]);
      if (!live) return;
      setState({
        loading: false,
        alerts: alerts.status === "fulfilled" ? alerts.value : null,
        openCount: overview.status === "fulfilled" ? overview.value.open_alerts : null,
      });
    };

    void read();
    const timer = pollMs > 0 ? setInterval(() => void read(), pollMs) : undefined;
    return () => {
      live = false;
      controller.abort();
      if (timer !== undefined) clearInterval(timer);
    };
  }, [base, pollMs]);

  return state;
}

async function getPage(url: string, signal: AbortSignal): Promise<AlertsPage> {
  const response = await fetch(url, { signal, headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  const body = (await response.json()) as unknown;
  if (
    typeof body !== "object" ||
    body === null ||
    !Array.isArray((body as Record<string, unknown>)["alerts"])
  ) {
    throw new Error(`${url} did not answer with an alerts page`);
  }
  return body as AlertsPage;
}

/** One alert by its event ID, or null when the feed does not hold it. */
export async function findAlert(
  base: string,
  eventId: string,
  signal: AbortSignal,
): Promise<AlertRecord | null> {
  let cursor = "";
  for (let page = 0; page < SEARCH_MAX_PAGES; page++) {
    const url =
      cursor === ""
        ? `${base}/alerts?limit=${SEARCH_PAGE_SIZE}`
        : `${base}/alerts?limit=${SEARCH_PAGE_SIZE}&cursor=${encodeURIComponent(cursor)}`;
    const body = await getPage(url, signal);
    const hit = body.alerts.find((a) => a.event_id === eventId);
    if (hit !== undefined) return hit;
    if (!body.next_cursor) return null;
    cursor = body.next_cursor;
  }
  return null;
}

export interface AlertResource {
  readonly status: "loading" | "found" | "absent" | "failed";
  readonly alert: AlertRecord | null;
  readonly error: string;
  readonly reload: () => void;
}

export function useAlert(base: string, eventId: string): AlertResource {
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const [state, setState] = useState<Omit<AlertResource, "reload">>({
    status: "loading",
    alert: null,
    error: "",
  });

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading", alert: null, error: "" });
    findAlert(base, eventId, controller.signal).then(
      (alert) => {
        if (controller.signal.aborted) return;
        setState(
          alert === null
            ? { status: "absent", alert: null, error: "" }
            : { status: "found", alert, error: "" },
        );
      },
      (reason: unknown) => {
        if (controller.signal.aborted) return;
        setState({
          status: "failed",
          alert: null,
          error: reason instanceof Error ? reason.message : String(reason),
        });
      },
    );
    return () => controller.abort();
  }, [base, eventId, nonce]);

  return { ...state, reload };
}
