// SPDX-License-Identifier: Apache-2.0

/*
 * Open alerts: the header's notification menu and the one-alert detail view
 * it links to — ADR-0054.
 */

export { AlertDetail } from "./AlertDetail";
export type { AlertDetailProps } from "./AlertDetail";

export { AlertDetailView } from "./AlertDetailView";
export type { AlertDetailViewProps } from "./AlertDetailView";

export { HeaderAlerts } from "./HeaderAlerts";
export type { HeaderAlertsProps } from "./HeaderAlerts";

export { NotificationMenu } from "./NotificationMenu";
export type { NotificationMenuProps } from "./NotificationMenu";

export { DEFAULT_POLL_MS, findAlert, useAlert, useOpenAlerts } from "./data";
export type { AlertResource, OpenAlerts, UseOpenAlertsOptions } from "./data";

export { alertSummary, alertTitle, openNewestFirst } from "./summary";

export { strings } from "./strings";
export type { AlertStrings } from "./strings";
