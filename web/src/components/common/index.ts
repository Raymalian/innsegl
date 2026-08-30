// SPDX-License-Identifier: Apache-2.0

/*
 * The shared components every view composes from — doc 06 §4, issue #50.
 *
 * What is deliberately NOT here: the three-check verification panel (§4.1) and
 * the verification tri-state badge (§4.2's second half). They belong to RM-043
 * (#51), which owns the panel the badge rolls up to, and they are the only
 * things in the product entitled to a green (ADR-0038 decision 4). Nothing in
 * this directory is a cryptographic verification, so nothing in it is green.
 */

export { AlertBanner } from "./AlertBanner";
export type { Alert, AlertBannerProps, AlertKind } from "./AlertBanner";

export { AnchoringHeartbeat } from "./AnchoringHeartbeat";
export type { AnchoringHeartbeatProps } from "./AnchoringHeartbeat";

export { EmptyState } from "./EmptyState";
export type { EmptyStateProps } from "./EmptyState";

export { ErrorState } from "./ErrorState";
export type { ErrorStateProps } from "./ErrorState";

export { Icon } from "./Icon";
export type { IconName, IconProps } from "./Icon";

export { IdentifierChip } from "./IdentifierChip";
export type { IdentifierChipProps } from "./IdentifierChip";

export {
  DEFAULT_MAX_LENGTH,
  ELLIPSIS,
  truncateIdentifier,
  trustDomainOf,
} from "./identifier";
export type { IdentifierKind, TruncateOptions } from "./identifier";

export { DEFAULT_TIMEOUT_MS, LoadingState } from "./LoadingState";
export type { LoadingStateProps } from "./LoadingState";

export {
  StalenessIndicator,
  StalenessProvider,
  useReadPath,
} from "./StalenessIndicator";
export type { ReadPathState } from "./StalenessIndicator";

export { StatusBadge } from "./StatusBadge";
export type { RunStatus, StatusBadgeProps } from "./StatusBadge";

export { strings } from "./strings";
export type { Strings } from "./strings";

export {
  elapsedSince,
  formatAbsoluteUtc,
  formatDuration,
  toDateTimeAttribute,
} from "./time";
