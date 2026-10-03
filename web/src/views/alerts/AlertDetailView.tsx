// SPDX-License-Identifier: Apache-2.0

/*
 * The alert detail view, wired — ADR-0054, doc 06 §4.6, P2.
 *
 * Four states, not two, for the reason every other view gives: loading with a
 * bound, a failed read (amber, with the reason), an alert the feed does not
 * hold (neutral — it is a fact about the address, not a fault), and the alert.
 */

import type { ViewProps } from "../../app/App";
import { EmptyState } from "../../components/common/EmptyState";
import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { StalenessIndicator } from "../../components/common/StalenessIndicator";
import { DEFAULT_API_BASE } from "../overview/data";
import { AlertDetail } from "./AlertDetail";
import { useAlert } from "./data";
import { strings } from "./strings";

export interface AlertDetailViewProps extends ViewProps {
  readonly apiBase?: string;
  readonly now?: Date;
}

export function AlertDetailView({
  route,
  apiBase = DEFAULT_API_BASE,
  now,
}: AlertDetailViewProps) {
  const eventId = route.view === "alert" ? route.eventId : "";
  const resource = useAlert(apiBase, eventId);

  switch (resource.status) {
    case "loading":
      return <LoadingState what={strings.detail.loadingWhat} onRetry={resource.reload} />;
    case "failed":
      return (
        <ErrorState
          detail={strings.detail.failedWith(resource.error)}
          onRetry={resource.reload}
        />
      );
    case "absent":
      return (
        <EmptyState
          title={strings.detail.notFoundTitle}
          detail={strings.detail.notFoundDetail}
        />
      );
    case "found":
      return (
        <>
          <StalenessIndicator />
          <AlertDetail
            alert={resource.alert!}
            apiBase={apiBase}
            onResolved={resource.reload}
            {...(now === undefined ? {} : { now })}
          />
        </>
      );
  }
}
