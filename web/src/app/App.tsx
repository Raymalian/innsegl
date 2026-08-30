// SPDX-License-Identifier: Apache-2.0

// The application shell: persistent header, flat navigation, one main region,
// and the route table deciding what goes in it.
//
// Three things are deliberately NOT here.
//
// No view. The six views of doc 06 §3 are wave 4's, and each owns its own
// directory. The shell renders whatever the `views` registry supplies for the
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

import { useEffect, type ComponentType, type ReactNode } from "react";

import { ThemeToggle } from "./ThemeToggle";
import { useStrings } from "./i18n";
import { Link, useRoute } from "./router";
import { NAV_VIEWS, navRoute, type Route, type ViewName } from "./routes";
import { documentTitle, type Strings } from "./strings";

/** Where the main region begins, and where the skip link lands. */
const MAIN_ID = "main";

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
}

export function App({ views = {}, heartbeat }: AppProps) {
  const route = useRoute();
  const strings = useStrings();
  const heading = headingFor(route, strings);

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

      <header className="flex flex-wrap items-center gap-4 border-b border-line px-4 py-3">
        <span className="text-heading font-semibold tracking-display">
          {strings.labels.app.name}
        </span>
        <div
          role="status"
          aria-label={strings.labels.header.anchoring}
          className="min-w-0 flex-1 text-micro text-ink-secondary"
        >
          {heartbeat}
        </div>
        <ThemeToggle />
      </header>

      <div className="mx-auto flex w-full max-w-content flex-wrap gap-4 p-4">
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
          {View ? <View route={route} /> : <Placeholder heading={heading} route={route} />}
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
