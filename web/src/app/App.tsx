// SPDX-License-Identifier: Apache-2.0

// The application shell: persistent header, flat navigation, one main region,
// and the route table deciding what goes in it.
//
// Three things are deliberately NOT here.
//
// No view. The six views of doc 06 §3, and the alert detail ADR-0054 added,
// each own their own directory. The shell renders whatever the `views` registry supplies for the
// current route and an honest placeholder otherwise — a placeholder that says
// in as many words that nothing on it came from the ledger, because doc 06 P2
// forbids a screen that could be mistaken for evidence.
//
// No anchoring heartbeat. doc 06 §3.1 puts it in the persistent header on
// every view; the data behind it is RM-044's. The shell owns the landmark and
// leaves the content to a prop, so that view can fill a slot rather than
// reach into the header.
//
// No copy. Every string comes from the catalogue through useStrings(), and
// FE-020 parses this file to prove it.
//
// One deliberate exception to "no view": #445's account page at /account.
// It is imported directly rather than through the `views` registry because
// it is not one of doc 06 §3's six views at all — the same reading that
// already keeps AuthGate's sign-in/setup pages, which this page sits beside
// conceptually, out of routes.ts's `VIEWS`. `isAccountPath` reads the
// address directly, the one piece of view state this page needs.

import { useEffect, type ComponentType, type ReactNode } from "react";

import { AppMark } from "./AppMark";
import { ThemeToggle } from "./ThemeToggle";
import { useStrings } from "./i18n";
import { Link, usePath, useRoute } from "./router";
import { NAV_VIEWS, isAccountPath, navRoute, type Route, type ViewName } from "./routes";
import { documentTitle, type Strings } from "./strings";
import { AccountPage } from "../views/auth";
import { strings as authStrings } from "../views/auth/strings";

/** Where the main region begins, and where the skip link lands. */
const MAIN_ID = "main";

/**
 * The wordmark — the one place in the shell that spends doc 06 §5.2's display
 * serif, and the only serif in this file.
 *
 * It is a NAME, set once, in the chrome. It is not copy a reader reads in
 * sentences and not a value anybody compares by eye, which is what §5.2's
 * restriction is protecting ("never sets body copy, never sets a label, and
 * never sets anything a reader might copy"). `src/app/serif-discipline.test.ts`
 * holds the whole product's list and this is its row.
 */
const wordmark =
  "flex items-center gap-2 font-serif text-heading font-semibold tracking-display";

export interface ViewProps {
  route: Route;
}

/**
 * The seam wave 4 plugs into: a component per view, keyed by the route table's
 * own names. A view that is not registered renders the placeholder, so the
 * shell is complete and navigable before any view exists.
 */
export type ViewRegistry = Partial<Record<ViewName, ComponentType<ViewProps>>>;

export interface AppProps {
  views?: ViewRegistry;
  /** doc 06 §3.1's anchoring heartbeat, supplied by RM-044. */
  heartbeat?: ReactNode;
  /** ADR-0054's notification menu: open alerts, on every view. The shell
   * owns the place in the header; the menu reads its own data. */
  alerts?: ReactNode;
  /** RM-260/RM-261's sign-out control (ADR-0062), on every view. App.tsx
   * holds no auth state of its own; AuthGate supplies this only once there
   * is a session to end. */
  account?: ReactNode;
}

/**
 * The width a view's content may take. The product keeps one readable
 * content width (doc 06 §5.4); the run page is the exception, laid out
 * across the whole window in its approved mockup so a step's row, its diffs
 * and the side-by-side view are not squeezed beside the navigation.
 */
export function contentWidthClass(route: Route): "max-w-none" | "max-w-content" {
  return route.view === "run" && route.chain !== true ? "max-w-none" : "max-w-content";
}

export function App({ views = {}, heartbeat, alerts, account }: AppProps) {
  const path = usePath();
  const route = useRoute();
  const strings = useStrings();
  const onAccountPage = isAccountPath(path);
  const heading = onAccountPage ? authStrings.account.heading : headingFor(route, strings);

  useEffect(() => {
    document.title = documentTitle(heading, strings);
  }, [heading, strings]);

  const View = route.view === "notFound" ? undefined : views[route.view];

  return (
    <div className="min-h-screen bg-page font-sans text-body text-ink">
      <a
        href={`#${MAIN_ID}`}
        className="sr-only focus:not-sr-only focus:absolute focus:m-2 focus:rounded-sm focus:bg-raised focus:p-2 focus:text-accent"
      >
        {strings.labels.app.skipToContent}
      </a>

      <header className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2">
        {/* The mark and the wordmark are one thing, so they are one element:
          * the seal never wraps away from the word it belongs to. The seal is
          * silent — see AppMark.tsx — so this span reads "Innsegl" once. */}
        <span className={wordmark}>
          <AppMark />
          {strings.labels.app.name}
        </span>
        {/* doc 06 §3.1's anchoring heartbeat, and the ONLY rendering of it in
          * the product: "Anchoring heartbeat in the persistent header (all
          * views) ... never hidden". The overview's body carried a second copy
          * until FE-114; see views/overview/Overview.tsx for what that cost.
          *
          * Pushed to the trailing edge rather than left against the wordmark:
          * it is a standing readout of how far behind the public record the
          * ledger is, not a subtitle of the product name. */}
        <div
          role="status"
          aria-label={strings.labels.header.anchoring}
          className="min-w-0 text-micro text-ink-secondary sm:flex-1 sm:text-right"
        >
          {heartbeat}
        </div>
        {/* ADR-0054: open alerts are a bell in the header, not banners stacked
          * on one page. Beside the heartbeat, because both are standing
          * readouts of the ledger's health that belong on every view. */}
        {alerts}
        <ThemeToggle />
        {account}
      </header>

      <div className={`mx-auto flex w-full ${contentWidthClass(route)} flex-wrap gap-4 p-4`}>
        <nav
          aria-label={strings.labels.nav.region}
          className="w-full shrink-0 sm:w-[12rem]"
        >
          <ul className="flex flex-wrap gap-1 sm:flex-col">
            {NAV_VIEWS.map((view) => (
              <li key={view}>
                <Link
                  to={navRoute(view)}
                  className="block rounded-sm px-3 py-2 text-ink-secondary hover:bg-hover aria-[current]:bg-accent-surface aria-[current]:text-accent"
                >
                  {strings.labels.views[view]}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <main id={MAIN_ID} tabIndex={-1} className="min-w-0 flex-1">
          {onAccountPage ? (
            <AccountPage />
          ) : View ? (
            <View route={route} />
          ) : (
            <Placeholder heading={heading} route={route} />
          )}
        </main>
      </div>
    </div>
  );
}

function headingFor(route: Route, strings: Strings): string {
  return route.view === "notFound"
    ? strings.labels.notFound.heading
    : strings.labels.views[route.view];
}

/**
 * What a view's place looks like before the view exists, and what an address
 * that matches no view looks like for good. Both are copy from the catalogue,
 * and both say plainly that there is no data here (doc 06 P2, §4.6).
 */
function Placeholder({ heading, route }: { heading: string; route: Route }) {
  const strings = useStrings();
  return (
    <section className="max-w-prose leading-prose">
      <h1 className="text-heading font-semibold text-ink">{heading}</h1>
      {route.view === "notFound" ? (
        <p className="mt-2 text-ink-secondary">{strings.sentences.notFound.body}</p>
      ) : (
        <>
          <p className="mt-2 text-ink-secondary">
            {strings.sentences.placeholder.unbuilt}
          </p>
          <p className="mt-2 text-ink-secondary">
            {strings.sentences.placeholder.notEvidence}
          </p>
        </>
      )}
    </section>
  );
}
