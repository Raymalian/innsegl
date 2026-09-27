# ADR-0054: Alerts live in a header notification menu

- Status: accepted
- Date: 2026-09-27
- Deciders: the operator

## Context

doc 06 §4.5 makes an alert a page-level banner, and §3.1 pins the alert feed
to the top of the overview. The dashboard built it that way: one filled red
banner per open alert, stacked above the overview's heading.

That held while alerts were rare. With several open, the stack pushed every
metric below the fold, and it showed only on the overview. A reader on any
other page saw nothing. Each banner also carried raw reasons and identifiers,
which read as noise in a list.

doc 06 P3 still stands: failure is loud, and the alarm is designed first.

## Decision

Open alerts are a **notification menu in the persistent header**, on every
view, beside the anchoring heartbeat.

1. A bell button with a count badge. The badge is filled red when any alert is
   open and absent when none is. When neither read answers, the badge shows
   the count as unknown, in amber, never as zero (P2).
2. The button opens a menu of open alerts, newest first. Each item has a short
   title, a one-line summary and a time. No raw hash or field name.
3. Each item opens a detail view at `/alerts/<event_id>`. It shows every field
   the alerts feed carries, the long identifiers in identifier chips, and the
   raw-record link (P1).
4. The header reads the alerts feed and the overview's `open_alerts` itself,
   again on an interval. A polite live region announces new alerts.
5. The menu and the detail view offer no dismiss and no resolve. ADR-0044
   keeps the dashboard read-only; an alert leaves the list only when an
   operator resolves it and the ledger records that.

### Resolving

The detail page of an open alert shows the `innsegl resolve-alert` command an
operator runs, with the event ID filled in and a copy control. It is text to
copy, not a button. A resolved alert shows who resolved it, when, and why.
Alerts that clear on their own are ADR-0055.

The overview no longer renders alert banners. The banner component stays for
conditions about the thing on screen: the per-commit mismatch in the
verification panel, and a run's own drift, which the run detail view now shows
as a compact inline notice.

The detail view is a seventh route beside doc 06 §3's six. It has no index and
no nav entry: the menu is its list.

## Alternatives considered

- **Keep the banners and cap them lower.** Still one page only, and still
  pushes the metrics down.
- **A single summary banner on every page.** Loud, but a banner on every view
  for a condition an operator may take hours to resolve trains readers to
  ignore it, which is the opposite of P3.
- **A dismiss control in the menu.** A reader could clear the alarm without
  clearing the condition. ADR-0044 and §4.5's "persistent until the condition
  clears" both rule it out.

## Consequences

- doc 06 §4.5 and §3.1 describe the old placement. This ADR is the operative
  reading until a human amends them.
- The route table has seven entries. FE-016 and FE-090 count them.
- Every view makes two more reads, once a minute. Both are GETs the query API
  already serves.
- Exit cost: moving alerts back to the page is a new ADR; the menu reads its
  own data, so removing it touches the header and nothing else.
