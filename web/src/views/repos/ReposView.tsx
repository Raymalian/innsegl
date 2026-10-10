// SPDX-License-Identifier: Apache-2.0

/*
 * The repositories index. One table; each name opens that repository's page.
 *
 * Wiring (the app shell's, not this directory's): a route `{ view: "repos" }`
 * at `/repos`, a nav item, and one entry in the view registry.
 */

import { useEffect, useState } from "react";

import {
  EmptyState,
  ErrorState,
  LoadingState,
  StalenessIndicator,
  formatAbsoluteUtc,
  toDateTimeAttribute,
} from "../../components/common";
import { displayName } from "../../app/pseudonym";
import { Link } from "../../app/router";
import {
  identifierText,
  link,
  listHeading,
  sectionShell,
  secondaryText,
  table,
  tableCell,
  tableHeader,
  tableScroll,
  viewShell,
} from "../repo/styles";
import { fetchRepos } from "./query";
import type { LoadRepos, RepoList } from "./query";
import { strings } from "./strings";

export interface ReposViewProps {
  readonly load?: LoadRepos;
}

type Phase =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly list: RepoList }
  | { readonly phase: "error"; readonly message: string };

export function ReposView({ load = fetchRepos }: ReposViewProps) {
  const [state, setState] = useState<Phase>({ phase: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState({ phase: "loading" });
    load(controller.signal).then(
      (list) => {
        if (!controller.signal.aborted) setState({ phase: "ready", list });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setState({
            phase: "error",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      },
    );
    return () => controller.abort();
  }, [load, attempt]);

  const retry = () => setAttempt((n) => n + 1);

  return (
    <div className={viewShell}>
      <header className="flex flex-col gap-2">
        <h1 className={listHeading}>{strings.labels.title}</h1>
        <p className={secondaryText}>{strings.sentences.intro}</p>
      </header>
      <StalenessIndicator />
      {state.phase === "loading" ? (
        <LoadingState what={strings.nouns.repos} onRetry={retry} />
      ) : null}
      {state.phase === "error" ? (
        <ErrorState detail={state.message} onRetry={retry} />
      ) : null}
      {state.phase === "ready" ? <Table list={state.list} /> : null}
    </div>
  );
}

function Table({ list }: { readonly list: RepoList }) {
  if (list.repos.length === 0) {
    return (
      <EmptyState title={strings.labels.noRepos} detail={strings.sentences.empty} />
    );
  }
  return (
    <section className={sectionShell}>
      <div className={tableScroll}>
        <table className={table}>
          <caption className="sr-only">{strings.labels.title}</caption>
          <thead>
            <tr>
              <th scope="col" className={tableHeader}>{strings.labels.repository}</th>
              <th scope="col" className={tableHeader}>{strings.labels.lastActivity}</th>
              <th scope="col" className={tableHeader}>{strings.labels.runs}</th>
              <th scope="col" className={tableHeader}>{strings.labels.commits}</th>
            </tr>
          </thead>
          <tbody>
            {list.repos.map((row) => {
              const at = new Date(row.last_event_at);
              return (
                <tr key={row.repo}>
                  <td className={tableCell}>
                    <Link
                      to={{ view: "repo", repo: row.repo, from: "", to: "" }}
                      className={`${link} ${identifierText} break-all`}
                    >
                      {displayName(row.repo)}
                    </Link>
                  </td>
                  <td className={tableCell}>
                    <time
                      dateTime={toDateTimeAttribute(at)}
                      title={formatAbsoluteUtc(at)}
                      className={identifierText}
                    >
                      {formatAbsoluteUtc(at)}
                    </time>
                  </td>
                  <td className={`${tableCell} ${identifierText}`}>{row.runs}</td>
                  <td className={`${tableCell} ${identifierText}`}>{row.commits}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
