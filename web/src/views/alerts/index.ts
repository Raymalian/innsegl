// SPDX-License-Identifier: Apache-2.0

/*
 * Alerts: the header's notification menu, the alerts page (RM-330) and the
 * one-alert detail view both link to — ADR-0054.
 */

export { AlertDetail } from "./AlertDetail";
export type { AlertDetailProps } from "./AlertDetail";

export { AlertDetailView } from "./AlertDetailView";

export { AlertsPage } from "./AlertsPage";
export type { AlertsPageProps } from "./AlertsPage";

export { AlertsView } from "./AlertsView";
export type { AlertsViewProps } from "./AlertsView";

export { ResolveForm } from "./ResolveForm";
export type { ResolveFormProps } from "./ResolveForm";
export type { AlertDetailViewProps } from "./AlertDetailView";

export { HeaderAlerts } from "./HeaderAlerts";
export type { HeaderAlertsProps } from "./HeaderAlerts";

export { NotificationMenu } from "./NotificationMenu";
export type { NotificationMenuProps } from "./NotificationMenu";

export {
  DEFAULT_POLL_MS,
  fetchAllAlerts,
  findAlert,
  useAlert,
  useAllAlerts,
  useOpenAlerts,
} from "./data";
export type { AlertResource, AllAlerts, OpenAlerts, UseOpenAlertsOptions } from "./data";

export { alertSummary, alertTitle, openNewestFirst } from "./summary";

export { strings } from "./strings";
export type { AlertStrings } from "./strings";
