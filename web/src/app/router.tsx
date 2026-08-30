// SPDX-License-Identifier: Apache-2.0

// The router. There is no routing dependency: `history.pushState` plus
// `popstate` is the whole mechanism, and the route table in routes.ts is the
// whole vocabulary.
//
// Two consequences are deliberate.
//
// The address bar is the single source of truth for what is on screen. There
// is no route object held in React state that could disagree with it, so a
// filter cannot exist in a form that survives a reload but not a copied link
// — which is the exact failure FD §7 names when it asks for shareability.
//
// Every destination is a real <a href>. That is what makes the nav keyboard
// operable (FD §6.4), middle-clickable, and copyable from a context menu
// without the shell implementing any of those; a modified click is handed
// straight back to the browser. A <div onClick> would have needed a tabindex,
// a key handler and a role, and would still not have offered "copy link
// address" — which for a product whose links are evidence is not a detail.

import {
  useCallback,
  useMemo,
  useSyncExternalStore,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from "react";

import { VIEW_ROOTS, parseRoute, routeToPath, type Route } from "./routes";

/** The event a same-document navigation dispatches; popstate covers the rest. */
const NAVIGATED = "innsegl:navigated";

/** The path the address bar currently holds, query string included. */
export function currentPath(): string {
  return `${window.location.pathname}${window.location.search}`;
}

export interface NavigateOptions {
  /** Replace the current history entry instead of pushing a new one. */
  replace?: boolean;
}

/**
 * Go to a route. Accepts a Route so callers cannot assemble a path by hand and
 * get the encoding subtly wrong; a string is accepted for a path that already
 * came out of routeToPath.
 */
export function navigate(to: Route | string, options: NavigateOptions = {}): void {
  const path = typeof to === "string" ? to : routeToPath(to);
  if (path === currentPath() && !options.replace) return;
  if (options.replace) {
    window.history.replaceState(null, "", path);
  } else {
    window.history.pushState(null, "", path);
  }
  window.dispatchEvent(new Event(NAVIGATED));
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("popstate", onChange);
  window.addEventListener(NAVIGATED, onChange);
  return () => {
    window.removeEventListener("popstate", onChange);
    window.removeEventListener(NAVIGATED, onChange);
  };
}

/** The current path, as a value React can render from. */
export function usePath(): string {
  return useSyncExternalStore(subscribe, currentPath, currentPath);
}

/** The current route. Re-parsed only when the path actually changes. */
export function useRoute(): Route {
  const path = usePath();
  return useMemo(() => parseRoute(path), [path]);
}

export interface LinkProps
  extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> {
  to: Route | string;
  replace?: boolean;
  children: ReactNode;
}

/**
 * A navigation link. Renders an anchor with a complete href and intercepts
 * only the plain left click; every other activation — a modified click, a
 * middle click, the context menu — belongs to the browser.
 *
 * `aria-current` marks the destination the reader is already at, so the active
 * item is announced rather than only coloured (FD §6.4, "Never color alone").
 */
export function Link({ to, replace, children, onClick, ...rest }: LinkProps) {
  const path = usePath();
  const href = typeof to === "string" ? to : routeToPath(to);

  const handleClick = useCallback(
    (event: MouseEvent<HTMLAnchorElement>) => {
      onClick?.(event);
      if (event.defaultPrevented) return;
      if (event.button !== 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      navigate(href, { replace: replace ?? false });
    },
    [href, onClick, replace],
  );

  return (
    <a {...rest} href={href} aria-current={currentness(href, path)} onClick={handleClick}>
      {children}
    </a>
  );
}

/**
 * "page" when this link points at exactly where the reader is; "true" when it
 * points at the section a detail view belongs to — doc 06 §3's navigation is
 * flat, so a run detail is still inside runs and the rail should say so.
 */
function currentness(href: string, path: string): "page" | "true" | undefined {
  if (href === path) return "page";
  const here = parseRoute(path);
  const there = parseRoute(href);
  if (here.view === "notFound" || there.view === "notFound") return undefined;
  return VIEW_ROOTS[here.view] === VIEW_ROOTS[there.view] ? "true" : undefined;
}
