// SPDX-License-Identifier: Apache-2.0

/*
 * RM-333 (#511) — what the account page's sections share: a load that
 * knows the difference between "this failed" and "this deployment keeps no
 * organisation records" (a 503 from the accounts store's absence), the
 * copy control, and the section shell.
 */

import { useCallback, useEffect, useId, useState, type ReactNode } from "react";

import { AuthRequestError } from "./client";
import { strings } from "./strings";
import {
  degraded,
  mutedText,
  noticeBase,
  noticeBody,
  section,
  sectionHeader,
  sectionHeading,
  sectionIntro,
  smallButton,
} from "./styles";

export type SectionLoad<T> =
  | { readonly status: "loading" }
  | { readonly status: "loaded"; readonly data: T }
  | { readonly status: "unavailable" }
  | { readonly status: "failed"; readonly message: string };

/** Loads one section's read, and reloads it on demand. A 503 is the
 * deployment having no accounts store: a fact to state quietly, never a
 * page failure. */
export function useSectionLoad<T>(load: () => Promise<T>): readonly [SectionLoad<T>, () => void] {
  const [state, setState] = useState<SectionLoad<T>>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const data = await load();
        if (live) setState({ status: "loaded", data });
      } catch (err) {
        if (!live) return;
        if (err instanceof AuthRequestError && err.status === 503) {
          setState({ status: "unavailable" });
          return;
        }
        setState({
          status: "failed",
          message: err instanceof AuthRequestError ? err.message : strings.account.sectionFailed,
        });
      }
    })();
    return () => {
      live = false;
    };
    // `load` is a module-level fetch function; the attempt counter is what
    // asks for a fresh read.
  }, [attempt]);

  return [state, reload] as const;
}

/** The non-data states of a section, rendered the same way everywhere. */
export function SectionStatus({ load }: { readonly load: SectionLoad<unknown> }) {
  switch (load.status) {
    case "loading":
      return <p className={`text-micro ${mutedText}`}>{strings.session.checking}</p>;
    case "unavailable":
      return <p className={`text-micro ${mutedText}`}>{strings.account.spineUnavailable}</p>;
    case "failed":
      return (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{load.message}</span>
        </p>
      );
    case "loaded":
      return null;
  }
}

/** One page section: a serif heading, an optional action on its trailing
 * edge, and a sentence saying what the section is. */
export function AccountSection({
  heading,
  intro,
  action,
  children,
}: {
  readonly heading: string;
  readonly intro?: string;
  readonly action?: ReactNode;
  readonly children: ReactNode;
}) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className={section}>
      <div className={sectionHeader}>
        <h2 id={headingId} className={sectionHeading}>
          {heading}
        </h2>
        {action}
      </div>
      {intro !== undefined && <p className={sectionIntro}>{intro}</p>}
      {children}
    </section>
  );
}

/** Copies one value. Says "Copied" only once the clipboard accepted it:
 * an unverified claim is worse than an admitted failure (P2). */
export function CopyButton({ value, label }: { readonly value: string; readonly label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      const clipboard = navigator.clipboard;
      if (clipboard === undefined) throw new Error("no clipboard");
      await clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <button type="button" onClick={() => void copy()} className={smallButton}>
      {copied ? strings.account.copied : label}
    </button>
  );
}

/** The later of two optional instants, or null when neither happened. */
export function latest(a: string | null, b: string | null): string | null {
  if (a === null) return b;
  if (b === null) return a;
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
}

/** A catalogue word for a server value (a role, a kind, a status), or the
 * value itself when the catalogue has none: shown as it arrived, never
 * dropped (P2). */
export function wordFor(catalogue: Readonly<Record<string, string>>, key: string): string {
  return (catalogue as Readonly<Record<string, string | undefined>>)[key] ?? key;
}

/** Where a privilege the role lacks is exercised instead, when it is. */
export function noteFor(action: string): string | undefined {
  return (strings.account.privilegeNotes as Readonly<Record<string, string | undefined>>)[action];
}
