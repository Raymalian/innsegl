// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's accounts amendment (#445) — the page the top bar's own name
 * link opens: the signed-in person's profile, the passkeys they manage, and
 * their recovery codes. Reached at /account; App.tsx renders it in the main
 * region in place of a routed view, the same exception AuthGate already
 * makes for the sign-in/setup pages — account management is shell/auth
 * infrastructure, not one of doc 06 §3's six ledger views, so it is not in
 * routes.ts's `VIEWS`.
 *
 * Self-contained, like every other view: it fetches its own account read
 * rather than taking one as a prop, and reloads it after every mutation
 * rather than reconciling an optimistic local copy — the account is small
 * and the actions are rare, so a round trip after each one is simpler than
 * a second source of truth to keep in step.
 *
 * RM-333 (#511) adds the organisation half (AccountOrganisation.tsx): what
 * the role allows, the machines, connecting a new one, the repositories and
 * the agents — and the person's own sign-ins. Each of those sections loads
 * its own read, so one that fails, or a deployment that keeps no
 * organisation records, leaves the rest of the page standing.
 */

import { useEffect, useId, useState, type FormEvent } from "react";

import { navigate } from "../../app/router";
import {
  AgentsSection,
  MachinesSection,
  PrivilegesSection,
  RepositoriesSection,
} from "./AccountOrganisation";
import { MembersSection } from "./AccountMembers";
import { RecoveryCodesStep } from "./RecoveryCodesStep";
import { AccountSection, CopyButton, SectionStatus, useSectionLoad, wordFor } from "./accountShared";
import {
  AuthRequestError,
  addPasskey,
  fetchAccount,
  fetchSessions,
  generateRecoveryCodes,
  realBrowser,
  removePasskey,
  renamePasskey,
  signOutOtherSessions,
  updateAccount,
  type WebAuthnBrowser,
} from "./client";
import { formatDate, formatDateTime } from "./format";
import { strings } from "./strings";
import type { Account, AccountPasskey } from "./types";
import {
  accountShell,
  card,
  cell,
  columnHeader,
  currentBadge,
  degraded,
  factList,
  factTerm,
  factValue,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  idValue,
  identityGrid,
  identityName,
  inlineLinkButton,
  introText,
  mutedText,
  noticeBase,
  noticeBody,
  neutralPill,
  orgList,
  orgRow,
  pageHeading,
  pageIntro,
  primaryButton,
  proseText,
  rowHeader,
  secondaryButton,
  secondaryText,
  section,
  sectionHeading,
  smallButton,
  srOnly,
  table,
  scrollingTablePanel,
} from "./styles";

export interface AccountPageProps {
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
}

type Load =
  | { readonly status: "loading" }
  | { readonly status: "loaded"; readonly account: Account }
  | { readonly status: "failed"; readonly message: string };

/** `?notice=recovery-signin` on the very first render only — captured once
 * so stripping the query a moment later (below) does not make the banner
 * it names flash and vanish on its own redirect. */
function initialNoticeFlag(): boolean {
  return new URLSearchParams(window.location.search).get("notice") === "recovery-signin";
}

export function AccountPage({ browser = realBrowser() }: AccountPageProps) {
  const headingId = useId();
  const [load, setLoad] = useState<Load>({ status: "loading" });
  const [showRecoverySignInNotice] = useState(initialNoticeFlag);

  const reload = () => {
    void (async () => {
      try {
        const account = await fetchAccount();
        setLoad({ status: "loaded", account });
      } catch (err) {
        setLoad({
          status: "failed",
          message: err instanceof AuthRequestError ? err.message : strings.account.loadFailed,
        });
      }
    })();
  };

  useEffect(reload, []);

  // A refresh of /account?notice=… would otherwise show the banner again
  // forever; the state above already captured whether to show it once.
  useEffect(() => {
    if (showRecoverySignInNotice) navigate("/account", { replace: true });
  }, [showRecoverySignInNotice]);

  return (
    <section aria-labelledby={headingId} className={accountShell}>
      <header className={pageIntro}>
        <h1 id={headingId} className={pageHeading}>
          {strings.account.heading}
        </h1>
        <p className={introText}>{strings.account.summary}</p>
      </header>

      {load.status === "loading" && <p className={proseText}>{strings.session.checking}</p>}

      {load.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{load.message}</span>
        </p>
      )}

      {load.status === "loaded" && (
        <AccountLoaded
          account={load.account}
          reload={reload}
          browser={browser}
          showRecoverySignInNotice={showRecoverySignInNotice}
        />
      )}
    </section>
  );
}

function AccountLoaded({
  account,
  reload,
  browser,
  showRecoverySignInNotice,
}: {
  readonly account: Account;
  readonly reload: () => void;
  readonly browser: WebAuthnBrowser;
  readonly showRecoverySignInNotice: boolean;
}) {
  return (
    <>
      {showRecoverySignInNotice && (
        <p className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>
            {strings.account.recoverySignInNotice} {account.recovery_codes_remaining}{" "}
            {strings.account.codesRemainingSuffix}
          </span>
        </p>
      )}

      <ProfileSection account={account} reload={reload} />
      <PrivilegesSection organisations={account.organisations} />
      <MachinesSection organisations={account.organisations} browser={browser} />
      <MembersSection organisations={account.organisations} browser={browser} />
      <RepositoriesSection multiOrg={account.organisations.length > 1} />
      <AgentsSection />
      <PasskeysSection account={account} reload={reload} browser={browser} />
      <RecoverySection account={account} reload={reload} />
      <SessionsSection />
    </>
  );
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

type ProfilePhase =
  | { readonly status: "viewing" }
  | { readonly status: "editing"; readonly name: string }
  | { readonly status: "saving"; readonly name: string }
  | { readonly status: "failed"; readonly name: string; readonly message: string };

function ProfileSection({
  account,
  reload,
}: {
  readonly account: Account;
  readonly reload: () => void;
}) {
  const headingId = useId();
  const nameId = useId();
  const [phase, setPhase] = useState<ProfilePhase>({ status: "viewing" });
  const a = strings.account;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (phase.status !== "editing") return;
    const name = phase.name.trim();
    setPhase({ status: "saving", name });
    try {
      await updateAccount(name);
      setPhase({ status: "viewing" });
      reload();
    } catch (err) {
      setPhase({
        status: "failed",
        name,
        message: err instanceof AuthRequestError ? err.message : a.loadFailed,
      });
    }
  };

  const editing = phase.status === "editing" || phase.status === "saving" || phase.status === "failed";

  return (
    <section aria-labelledby={headingId} className={`${card} ${identityGrid}`}>
      <div className="flex min-w-0 flex-col gap-3">
        {editing ? (
          <>
            <h2 id={headingId} className={srOnly}>
              {account.display_name}
            </h2>
            <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
              <div className={fieldStack}>
                <label htmlFor={nameId} className={fieldLabel}>
                  {a.nameLabel}
                </label>
                <input
                  id={nameId}
                  type="text"
                  required
                  autoComplete="off"
                  value={phase.name}
                  onChange={(event) => setPhase({ status: "editing", name: event.target.value })}
                  className={`${fieldInput} ${focusRing}`}
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={phase.status === "saving"}
                  className={`${primaryButton} ${focusRing}`}
                >
                  {phase.status === "saving" ? a.saving : a.saveButton}
                </button>
                <button
                  type="button"
                  onClick={() => setPhase({ status: "viewing" })}
                  className={`${secondaryButton} ${focusRing}`}
                >
                  {a.cancelButton}
                </button>
              </div>
              {phase.status === "failed" && (
                <p role="alert" className={`${noticeBase} ${degraded}`}>
                  <span className={noticeBody}>{phase.message}</span>
                </p>
              )}
            </form>
          </>
        ) : (
          <div className="flex flex-wrap items-baseline gap-3">
            <h2 id={headingId} className={identityName}>
              {account.display_name}
            </h2>
            <button
              type="button"
              onClick={() => setPhase({ status: "editing", name: account.display_name })}
              className={inlineLinkButton}
            >
              {a.editButton}
            </button>
          </div>
        )}
        <dl className={factList}>
          <dt className={factTerm}>{a.userIdLabel}</dt>
          <dd className={`${factValue} flex flex-wrap items-center gap-2`}>
            <code className={idValue}>{account.user_id}</code>
            <CopyButton value={account.user_id} label={a.copyUserId} />
          </dd>
          <dt className={factTerm}>{a.memberSince}</dt>
          <dd className={`${factValue} ${secondaryText}`}>{formatDate(account.created_at)}</dd>
        </dl>
      </div>
      <dl className="flex min-w-0 flex-col gap-2">
        <dt className={factTerm}>{a.organisationLabel}</dt>
        <dd className={orgList}>
          {account.organisations.length === 0 ? (
            <span className={secondaryText}>{a.noOrganisation}</span>
          ) : (
            account.organisations.map((org) => (
              <div key={org.id} className="flex flex-col gap-0.5">
                <span className={orgRow}>
                  <span className="font-medium text-ink">{org.name}</span>
                  <span className={neutralPill}>{wordFor(a.roles, org.role)}</span>
                </span>
                {org.operator && (
                  <span className={`text-micro ${mutedText}`}>{a.operatorOrganisation}</span>
                )}
              </div>
            ))
          )}
        </dd>
      </dl>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

type RowPhase =
  | { readonly status: "idle" }
  | { readonly status: "renaming"; readonly name: string }
  | { readonly status: "renaming-working"; readonly name: string }
  | { readonly status: "confirming-remove" }
  | { readonly status: "removing" }
  | { readonly status: "row-failed"; readonly message: string };

function PasskeysSection({
  account,
  reload,
  browser,
}: {
  readonly account: Account;
  readonly reload: () => void;
  readonly browser: WebAuthnBrowser;
}) {
  const headingId = useId();
  const tableHeadingId = useId();
  const [rows, setRows] = useState<Record<string, RowPhase>>({});
  const rowOf = (id: string): RowPhase => rows[id] ?? { status: "idle" };
  const setRow = (id: string, phase: RowPhase) => setRows((prev) => ({ ...prev, [id]: phase }));

  const lastOne = account.passkeys.length <= 1;

  const rename = async (passkey: AccountPasskey) => {
    const phase = rowOf(passkey.id);
    if (phase.status !== "renaming") return;
    const name = phase.name.trim();
    setRow(passkey.id, { status: "renaming-working", name });
    try {
      await renamePasskey(passkey.id, name);
      setRow(passkey.id, { status: "idle" });
      reload();
    } catch (err) {
      setRow(passkey.id, {
        status: "row-failed",
        message: err instanceof AuthRequestError ? err.message : strings.account.loadFailed,
      });
    }
  };

  const remove = async (passkey: AccountPasskey) => {
    setRow(passkey.id, { status: "removing" });
    try {
      await removePasskey(passkey.id);
      setRow(passkey.id, { status: "idle" });
      reload();
    } catch (err) {
      setRow(passkey.id, {
        status: "row-failed",
        message: err instanceof AuthRequestError ? err.message : strings.account.removeFailed,
      });
    }
  };

  return (
    <section aria-labelledby={headingId} className={section}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id={headingId} className={sectionHeading}>
          {strings.account.passkeysHeading}
        </h2>
      </div>

      <div className={scrollingTablePanel}>
        <table className={table}>
          <caption className={srOnly} id={tableHeadingId}>
            {strings.account.passkeysHeading}
          </caption>
          <thead>
            <tr>
              <th scope="col" className={columnHeader}>
                {strings.account.passkeyNameHeader}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.account.passkeyAddedHeader}
              </th>
              <th scope="col" className={columnHeader}>
                {strings.account.passkeyLastUsedHeader}
              </th>
              <th scope="col" className={columnHeader}>
                <span className={srOnly}>{strings.account.passkeyActionsHeader}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {account.passkeys.map((passkey) => {
              const phase = rowOf(passkey.id);
              return (
                <tr key={passkey.id}>
                  <th scope="row" className={rowHeader}>
                    {phase.status === "renaming" || phase.status === "renaming-working" ? (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void rename(passkey);
                        }}
                        className="flex items-center gap-2"
                      >
                        <label htmlFor={`${passkey.id}-rename`} className={srOnly}>
                          {strings.account.passkeyNameHeader}
                        </label>
                        <input
                          id={`${passkey.id}-rename`}
                          type="text"
                          required
                          autoComplete="off"
                          value={phase.name}
                          onChange={(event) =>
                            setRow(passkey.id, { status: "renaming", name: event.target.value })
                          }
                          className={`${fieldInput} ${focusRing}`}
                        />
                        <button
                          type="submit"
                          disabled={phase.status === "renaming-working"}
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.saveButton}
                        </button>
                        <button
                          type="button"
                          onClick={() => setRow(passkey.id, { status: "idle" })}
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.cancelButton}
                        </button>
                      </form>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="whitespace-nowrap">{passkey.name === "" ? strings.account.unnamedPasskey : passkey.name}</span>
                        {passkey.current && <span className={currentBadge}>{strings.account.currentDevice}</span>}
                      </div>
                    )}
                  </th>
                  <td className={`${cell} whitespace-nowrap`}>{formatDate(passkey.created_at)}</td>
                  <td className={`${cell} whitespace-nowrap`}>
                    {passkey.last_used_at === null
                      ? strings.account.passkeyNeverUsed
                      : formatDate(passkey.last_used_at)}
                  </td>
                  <td className={cell}>
                    {phase.status === "confirming-remove" ? (
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={secondaryText}>{strings.account.removeConfirmPrompt}</span>
                        <button
                          type="button"
                          onClick={() => void remove(passkey)}
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.removeConfirmButton}
                        </button>
                        <button
                          type="button"
                          onClick={() => setRow(passkey.id, { status: "idle" })}
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.removeCancelButton}
                        </button>
                      </div>
                    ) : phase.status === "renaming" || phase.status === "renaming-working" ? null : (
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setRow(passkey.id, { status: "renaming", name: passkey.name })
                          }
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.renameButton}
                        </button>
                        <button
                          type="button"
                          disabled={lastOne || phase.status === "removing"}
                          title={lastOne ? strings.account.removeLastTooltip : undefined}
                          onClick={() => setRow(passkey.id, { status: "confirming-remove" })}
                          className={`${secondaryButton} ${focusRing}`}
                        >
                          {strings.account.removeButton}
                        </button>
                      </div>
                    )}
                    {phase.status === "row-failed" && (
                      <p role="alert" className={`mt-2 ${mutedText}`}>
                        {phase.message}
                      </p>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <AddPasskeySection account={account} reload={reload} browser={browser} />
    </section>
  );
}

// ---------------------------------------------------------------------------
// Add a passkey
// ---------------------------------------------------------------------------

type AddPhase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

function defaultPasskeyName(count: number): string {
  return `Passkey ${count + 1}`;
}

function AddPasskeySection({
  account,
  reload,
  browser,
}: {
  readonly account: Account;
  readonly reload: () => void;
  readonly browser: WebAuthnBrowser;
}) {
  const nameId = useId();
  const nameHintId = useId();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(() => defaultPasskeyName(account.passkeys.length));
  const [phase, setPhase] = useState<AddPhase>({ status: "idle" });

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      await addPasskey(name.trim(), browser);
      setPhase({ status: "idle" });
      setOpen(false);
      setName(defaultPasskeyName(account.passkeys.length + 1));
      reload();
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className={smallButton}>
        {strings.account.addOpenButton}
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <form onSubmit={(e) => void submit(e)} className="flex flex-wrap items-end gap-2">
        <div className={`${fieldStack} min-w-[12rem] flex-1 sm:max-w-xs`}>
          <label htmlFor={nameId} className={`text-micro ${fieldLabel}`}>
            {strings.account.addNameLabel}
          </label>
          <input
            id={nameId}
            type="text"
            required
            autoComplete="off"
            aria-describedby={nameHintId}
            value={name}
            onChange={(event) => setName(event.target.value)}
            className={`${fieldInput} ${focusRing}`}
          />
        </div>
        <button
          type="submit"
          disabled={phase.status === "working"}
          className={`${primaryButton.replace("self-start", "self-end")} ${focusRing}`}
        >
          {phase.status === "working" ? strings.account.addWorking : strings.account.addButton}
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setPhase({ status: "idle" });
          }}
          className={`${secondaryButton.replace("self-start", "self-end")} ${focusRing}`}
        >
          {strings.account.cancelButton}
        </button>
      </form>
      <span id={nameHintId} className={`text-micro ${secondaryText}`}>
        {strings.account.addNameHint}
      </span>
      {phase.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{phase.message}</span>
        </p>
      )}
    </div>
  );
}

function messageFor(err: unknown): string {
  if (err instanceof AuthRequestError) return err.message;
  if (err instanceof Error && err.message.includes("passkey support")) {
    return strings.account.addUnsupported;
  }
  if (err instanceof Error && /abort|cancel/i.test(err.message)) {
    return strings.account.addCancelled;
  }
  return strings.account.addFailed;
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

type RecoveryPhase =
  | { readonly status: "idle" }
  | { readonly status: "confirming" }
  | { readonly status: "working" }
  | { readonly status: "codes"; readonly codes: string[] }
  | { readonly status: "failed"; readonly message: string };

function RecoverySection({
  account,
  reload,
}: {
  readonly account: Account;
  readonly reload: () => void;
}) {
  const headingId = useId();
  const [phase, setPhase] = useState<RecoveryPhase>({ status: "idle" });

  const generate = async () => {
    setPhase({ status: "working" });
    try {
      const result = await generateRecoveryCodes();
      setPhase({ status: "codes", codes: [...result.codes] });
    } catch (err) {
      setPhase({
        status: "failed",
        message: err instanceof AuthRequestError ? err.message : strings.account.loadFailed,
      });
    }
  };

  return (
    <section aria-labelledby={headingId} className={section}>
      <h2 id={headingId} className={sectionHeading}>
        {strings.account.recoveryHeading}
      </h2>
      <div className={card}>
        {phase.status === "codes" ? (
          <RecoveryCodesStep
            codes={phase.codes}
            onContinue={() => {
              setPhase({ status: "idle" });
              reload();
            }}
          />
        ) : (
          <>
            <p className={proseText}>
              {account.recovery_codes_remaining} {strings.account.recoveryOf}
            </p>
            {phase.status === "confirming" ? (
              <div className="flex flex-wrap items-center gap-2">
                <span className={secondaryText}>{strings.account.regenerateConfirmPrompt}</span>
                <button
                  type="button"
                  onClick={() => void generate()}
                  className={`${secondaryButton} ${focusRing}`}
                >
                  {strings.account.regenerateConfirmButton}
                </button>
                <button
                  type="button"
                  onClick={() => setPhase({ status: "idle" })}
                  className={`${secondaryButton} ${focusRing}`}
                >
                  {strings.account.regenerateCancelButton}
                </button>
              </div>
            ) : (
              <button
                type="button"
                disabled={phase.status === "working"}
                onClick={() => setPhase({ status: "confirming" })}
                className={`${secondaryButton} ${focusRing}`}
              >
                {strings.account.regenerateButton}
              </button>
            )}
            {phase.status === "failed" && (
              <p role="alert" className={`${noticeBase} ${degraded}`}>
                <span className={noticeBody}>{phase.message}</span>
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Sign-ins (RM-333, #511)
// ---------------------------------------------------------------------------

type SignOutPhase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "done"; readonly count: number }
  | { readonly status: "failed"; readonly message: string };

function SessionsSection() {
  const [load, reload] = useSectionLoad(fetchSessions);
  const [phase, setPhase] = useState<SignOutPhase>({ status: "idle" });
  const a = strings.account;
  const others = load.status === "loaded" ? load.data.filter((x) => !x.current).length : 0;

  const signOutOthers = async () => {
    setPhase({ status: "working" });
    try {
      const count = await signOutOtherSessions();
      setPhase({ status: "done", count });
      reload();
    } catch (err) {
      setPhase({
        status: "failed",
        message: err instanceof AuthRequestError ? err.message : a.sectionFailed,
      });
    }
  };

  return (
    <AccountSection heading={a.sessionsHeading} intro={a.sessionsIntro}>
      <SectionStatus load={load} />
      {load.status === "loaded" && (
        <>
          <div className={scrollingTablePanel}>
            <table className={table}>
              <caption className={srOnly}>{a.sessionsHeading}</caption>
              <thead>
                <tr>
                  <th scope="col" className={columnHeader}>
                    {a.sessionStartedHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.sessionMethodHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.sessionExpiresHeader}
                  </th>
                </tr>
              </thead>
              <tbody>
                {load.data.map((session) => (
                  <tr key={session.id}>
                    <th scope="row" className={`${rowHeader} whitespace-nowrap`}>
                      <span className="inline-flex flex-wrap items-center gap-2">
                        {formatDateTime(session.created_at)}
                        {session.current && <span className={currentBadge}>{a.thisBrowser}</span>}
                      </span>
                    </th>
                    <td className={`${cell} whitespace-nowrap`}>
                      {session.passkey_name === null
                        ? a.sessionRecoveryCode
                        : a.sessionPasskey(session.passkey_name)}
                    </td>
                    <td className={`${cell} whitespace-nowrap`}>{formatDateTime(session.expires_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={others === 0 || phase.status === "working"}
              onClick={() => void signOutOthers()}
              className={`${secondaryButton} ${focusRing}`}
            >
              {phase.status === "working" ? a.signOutOthersWorking : a.signOutOthers}
            </button>
            <span role="status" className={`text-micro ${secondaryText}`}>
              {phase.status === "done"
                ? `${a.signedOutOthers} ${phase.count}`
                : others === 0
                  ? a.noOtherSessions
                  : ""}
            </span>
          </div>
          {phase.status === "failed" && (
            <p role="alert" className={`${noticeBase} ${degraded}`}>
              <span className={noticeBody}>{phase.message}</span>
            </p>
          )}
        </>
      )}
    </AccountSection>
  );
}
