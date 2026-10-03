// SPDX-License-Identifier: Apache-2.0

/*
 * The alerts page, wired — RM-330 (#506), doc 06 §4.6, P2.
 *
 * Loading with a bound, a failed read (amber, with the reason), and the page.
 * There is no "absent" state: an empty feed is a page that says no alerts
 * have been raised. After a resolution the feed is read again, so what the
 * page shows is what the ledger now holds, never a local guess.
 */

import type { ViewProps } from "../../app/App";
import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { StalenessIndicator } from "../../components/common/StalenessIndicator";
import type { WebAuthnBrowser } from "../auth/client";
import { DEFAULT_API_BASE } from "../overview/data";
import { AlertsPage } from "./AlertsPage";
import { useAllAlerts } from "./data";
import { strings } from "./strings";

export interface AlertsViewProps extends ViewProps {
  readonly apiBase?: string;
  readonly now?: Date;
  readonly browser?: WebAuthnBrowser;
}

export function AlertsView({ route, apiBase = DEFAULT_API_BASE, now, browser }: AlertsViewProps) {
  const resource = useAllAlerts(apiBase);
  const filters = route.view === "alerts" ? route.filters : { kind: "" as const, run: "" };

  switch (resource.status) {
    case "loading":
      return <LoadingState what={strings.page.loadingWhat} onRetry={resource.reload} />;
    case "failed":
      return (
        <ErrorState detail={strings.page.failedWith(resource.error)} onRetry={resource.reload} />
      );
    case "ready":
      return (
        <>
          <StalenessIndicator />
          <AlertsPage
            alerts={resource.alerts}
            complete={resource.complete}
            filters={filters}
            onResolved={resource.reload}
            apiBase={apiBase}
            {...(now === undefined ? {} : { now })}
            {...(browser === undefined ? {} : { browser })}
          />
        </>
      );
  }
}
