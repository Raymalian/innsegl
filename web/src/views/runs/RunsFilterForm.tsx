// SPDX-License-Identifier: Apache-2.0

/*
 * The runs table's filters — doc 06 §3.2.
 *
 *   "Filters: repo, agent type, status, date range, free-text over IDs and
 *    tasks. Filters are URL-encoded so any filtered view is shareable."
 *
 * ── THE URL IS THE FILTER ──────────────────────────────────────────────────
 *
 * Submitting navigates. There is no filter state that outlives this form: the
 * address bar holds the query, the view reads the query, and the request is
 * that query with a different path. A filter kept in React state would survive
 * a reload and not a copied link, which is exactly the failure doc 06 §7 names
 * when it asks for shareability, and FE-010 is what would catch it.
 *
 * What IS local is the DRAFT — what has been typed but not yet applied. That
 * cannot live in the URL without navigating on every keystroke, which would
 * mean a query against the hot tier per keystroke. The draft is seeded from
 * the URL and the form is remounted (`key`) whenever the URL changes, so the
 * controls are a function of the address bar the moment anything is applied.
 * Two readers who arrive at the same filtered view therefore see identical
 * controls, however they got there — which is the half of FE-010 that a
 * round-trip test of the parser alone would not reach.
 *
 * Applying clears the cursor. A keyset cursor is a position in one ordering of
 * one filtered set (internal/api's `chain_position < $7`); carrying it into a
 * different filter would silently drop everything above an unrelated row.
 *
 * ── DATES ──────────────────────────────────────────────────────────────────
 *
 * internal/api's `runFilterFrom` parses `from` and `to` as RFC 3339 and
 * answers 400 to anything else, so a bare `2026-08-01` in a shared link would
 * be a broken link. The control is a date, the URL is a timestamp, and the
 * conversion is here: the start of the day for `from`, the last second of it
 * for `to`, so a one-day range includes that day.
 *
 * Every id below is a constant. There is one filter form on the page, so the
 * ids do not need to be generated — and a generated id would make two renders
 * of the same URL differ in their markup, which is the thing FE-010 measures.
 */

import { useState, type FormEvent } from "react";

import {
  RUN_STATUSES,
  emptyRunsFilters,
  type RunStatus,
  type RunsFilters,
} from "../../app/routes";
import { navigate } from "../../app/router";
import { strings as common } from "../../components/common";

import { runsLinkPath } from "./api";
import { strings } from "./strings";
import {
  filterActions,
  filterControl,
  filterField,
  filterForm,
  filterGrid,
  filterHint,
  filterLabel,
  primaryButton,
  secondaryButton,
} from "./styles";

const ID = {
  repo: "runs-filter-repo",
  agentType: "runs-filter-agent-type",
  status: "runs-filter-status",
  from: "runs-filter-from",
  to: "runs-filter-to",
  search: "runs-filter-search",
  searchHint: "runs-filter-search-hint",
} as const;

/** What a `<input type="date">` shows for an RFC 3339 instant. */
export function dateInputOf(timestamp: string): string {
  const day = timestamp.slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : "";
}

/** The first instant of a day, UTC. Empty stays empty: an absent bound is not
 * a bound at the epoch. */
export function startOfDay(day: string): string {
  return day === "" ? "" : `${day}T00:00:00Z`;
}

/** The last second of a day, UTC, so a one-day range contains that day. */
export function endOfDay(day: string): string {
  return day === "" ? "" : `${day}T23:59:59Z`;
}

interface Draft {
  repo: string;
  agentType: string;
  status: RunStatus | "";
  from: string;
  to: string;
  search: string;
}

function draftOf(filters: RunsFilters): Draft {
  return {
    repo: filters.repo,
    agentType: filters.agentType,
    status: filters.status,
    from: dateInputOf(filters.from),
    to: dateInputOf(filters.to),
    search: filters.search,
  };
}

const isRunStatus = (value: string): value is RunStatus =>
  (RUN_STATUSES as readonly string[]).includes(value);

export interface RunsFilterFormProps {
  readonly filters: RunsFilters;
}

export function RunsFilterForm({ filters }: RunsFilterFormProps) {
  const [draft, setDraft] = useState<Draft>(() => draftOf(filters));

  const apply = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    navigate(
      runsLinkPath({
        repo: draft.repo,
        agentType: draft.agentType,
        status: draft.status,
        search: draft.search,
        from: startOfDay(draft.from),
        to: endOfDay(draft.to),
        // A cursor is a position in the set the OLD filters described.
        cursor: "",
        limit: filters.limit,
      }),
    );
  };

  const clear = () => {
    navigate(runsLinkPath({ ...emptyRunsFilters(), limit: filters.limit }));
  };

  return (
    <form
      className={filterForm}
      aria-label={strings.labels.filters.region}
      onSubmit={apply}
    >
      <div className={filterGrid}>
        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.repo}>
            {strings.labels.filters.repo}
          </label>
          <input
            id={ID.repo}
            name="repo"
            type="text"
            className={filterControl}
            value={draft.repo}
            onChange={(event) =>
              setDraft({ ...draft, repo: event.target.value })
            }
          />
        </div>

        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.agentType}>
            {strings.labels.filters.agentType}
          </label>
          <input
            id={ID.agentType}
            name="agent_type"
            type="text"
            className={filterControl}
            value={draft.agentType}
            onChange={(event) =>
              setDraft({ ...draft, agentType: event.target.value })
            }
          />
        </div>

        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.status}>
            {strings.labels.filters.status}
          </label>
          <select
            id={ID.status}
            name="status"
            className={filterControl}
            value={draft.status}
            onChange={(event) =>
              setDraft({
                ...draft,
                status: isRunStatus(event.target.value)
                  ? event.target.value
                  : "",
              })
            }
          >
            <option value="">{strings.labels.filters.anyStatus}</option>
            {RUN_STATUSES.map((status) => (
              <option key={status} value={status}>
                {common.status[status].label}
              </option>
            ))}
          </select>
        </div>

        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.from}>
            {strings.labels.filters.from}
          </label>
          <input
            id={ID.from}
            name="from"
            type="date"
            className={filterControl}
            value={draft.from}
            onChange={(event) =>
              setDraft({ ...draft, from: event.target.value })
            }
          />
        </div>

        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.to}>
            {strings.labels.filters.to}
          </label>
          <input
            id={ID.to}
            name="to"
            type="date"
            className={filterControl}
            value={draft.to}
            onChange={(event) => setDraft({ ...draft, to: event.target.value })}
          />
        </div>

        <div className={filterField}>
          <label className={filterLabel} htmlFor={ID.search}>
            {strings.labels.filters.search}
          </label>
          <input
            id={ID.search}
            name="q"
            type="search"
            className={filterControl}
            aria-describedby={ID.searchHint}
            value={draft.search}
            onChange={(event) =>
              setDraft({ ...draft, search: event.target.value })
            }
          />
        </div>
      </div>

      <div className={filterActions}>
        <button type="submit" className={primaryButton}>
          {strings.labels.filters.apply}
        </button>
        {/* Reading with no filters is still a read. doc 06 P6 forbids mutating
         * controls; this one changes an address. */}
        <button type="button" className={secondaryButton} onClick={clear}>
          {strings.labels.filters.clear}
        </button>
        <span id={ID.searchHint} className={filterHint}>
          {strings.sentences.filters.searchHint}
        </span>
      </div>
    </form>
  );
}
