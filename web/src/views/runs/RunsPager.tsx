// SPDX-License-Identifier: Apache-2.0

/*
 * Paging — doc 06 §3.2's "paginated", §7's "server-side pagination".
 *
 * internal/api issues a KEYSET cursor, not an offset: `next_cursor` is the
 * chain position of the last row served, and the next page is
 * `chain_position < cursor`. That is why there is a "next" link and no
 * "previous" one — a keyset has no backwards cursor to offer, and inventing
 * one by counting rows would be the offset paging the API deliberately does
 * not do. The way back is the browser's back button, and it works because the
 * cursor is in the URL like every other piece of this view's state (doc 06
 * §7).
 *
 * Both links are real <a href>s through the router's Link, so they can be
 * middle-clicked, bookmarked and copied. A page of this table is as shareable
 * as a filter on it.
 *
 * The page bound is stated on the page, not just enforced in a function: the
 * reader is told how many rows this view will ever ask for at once.
 */

import { Link } from "../../app/router";
import type { RunsFilters } from "../../app/routes";

import { runsLinkPath, type RunPage } from "./api";
import { strings } from "./strings";
import { pager, pagerLink, pagerNote } from "./styles";

export interface RunsPagerProps {
  readonly filters: RunsFilters;
  readonly page: RunPage;
}

export function RunsPager({ filters, page }: RunsPagerProps) {
  const nextCursor = page.next_cursor ?? "";
  return (
    <nav aria-label={strings.labels.page.region} className={pager}>
      <span>{strings.formats.showing(page.runs.length, page.total)}</span>

      {filters.cursor === "" ? null : (
        <Link
          to={runsLinkPath({ ...filters, cursor: "" })}
          className={pagerLink}
        >
          {strings.labels.page.first}
        </Link>
      )}

      {nextCursor === "" ? null : (
        <Link
          to={runsLinkPath({ ...filters, cursor: nextCursor })}
          className={pagerLink}
        >
          {strings.labels.page.next}
        </Link>
      )}

      <span className={pagerNote}>{strings.sentences.page.keyset}</span>
      <span className={pagerNote}>{strings.formats.bounded(page.limit)}</span>
    </nav>
  );
}
