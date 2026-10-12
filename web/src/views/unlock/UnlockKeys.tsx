// SPDX-License-Identifier: Apache-2.0

/*
 * #616 (ADR-0082): the account page's "Unlock keys" section, and the
 * unlock page. The banner shown when the core reports that the CA cannot
 * sign is on every page now (CannotSignBanner.tsx, mounted by App.tsx).
 *
 * Mounted once, from AccountPage. Only an owner or admin of the operator
 * organisation sees any of it, the same bar the API holds; for anyone else
 * it renders nothing and reads nothing. A 403 or 404 from the API (another
 * role, or an API without these routes) also renders nothing.
 *
 * The unlock page is this component's own region on /account, opened by
 * `/account?unlock` in the address, which is where the banner links.
 */

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";

import { CopyButton, wordFor } from "../auth/accountShared";
import { AuthRequestError, type WebAuthnBrowser } from "../auth/client";
import { formatDate } from "../auth/format";
import {
  card,
  cell,
  columnHeader,
  commandValue,
  degraded,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  idValue,
  machineStatusPill,
  mutedText,
  neutralPill,
  noticeBase,
  noticeBody,
  primaryButton,
  proseText,
  rowHeader,
  scrollingTablePanel,
  secondaryButton,
  secondaryText,
  section,
  sectionHeader,
  sectionHeading,
  sectionIntro,
  secretBlock,
  secretRow,
  smallButton,
  srOnly,
  table,
} from "../auth/styles";
import type { AccountOrganisation } from "../auth/types";
import {
  NoPRFError,
  NoWebAuthnError,
  NotSealedToThisKeyError,
  browserSupport,
  enrolUnlockKey,
  fetchUnlockKeys,
  revokeUnlockKey,
  unlockCA,
  type BrowserSupport,
  type CustodyStatus,
  type UnlockKey,
  type UnlockKeyList,
} from "./api";
import { strings } from "./strings";
import { custodyChangedEvent } from "./CannotSignBanner";
import { navigate, usePath } from "../../app/router";

export interface UnlockKeysProps {
  readonly organisations: readonly AccountOrganisation[];
  readonly browser: WebAuthnBrowser;
  /** Injected for tests; defaults to the real one. */
  readonly userAgent?: string;
}

const s = strings.section;

export function UnlockKeys({ organisations, browser, userAgent }: UnlockKeysProps) {
  const operator = organisations.filter((o) => o.operator && (o.role === "owner" || o.role === "admin"));
  if (operator.length === 0) return null;
  return (
    <UnlockKeysLoaded
      browser={browser}
      isOwner={operator.some((o) => o.role === "owner")}
      support={browserSupport(browser.supported, userAgent ?? navigator.userAgent)}
    />
  );
}

type ListLoad =
  | { readonly status: "loading" }
  | { readonly status: "loaded"; readonly data: UnlockKeyList }
  | { readonly status: "hidden" }
  | { readonly status: "failed"; readonly message: string };

function hiddenFor(err: unknown): boolean {
  return err instanceof AuthRequestError && (err.status === 403 || err.status === 404);
}

function initialUnlockOpen(): boolean {
  return new URLSearchParams(window.location.search).has("unlock");
}

/** The words for a ceremony that did not finish. */
function messageFor(err: unknown, fallback: string): string {
  if (err instanceof NoPRFError) return strings.support.noPRF;
  if (err instanceof NoWebAuthnError) return strings.support.none;
  if (err instanceof NotSealedToThisKeyError) return strings.unlock.notSealed;
  if (err instanceof AuthRequestError) return err.message;
  if (err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError")) {
    return strings.support.cancelled;
  }
  return fallback;
}

function UnlockKeysLoaded({
  browser,
  isOwner,
  support,
}: {
  readonly browser: WebAuthnBrowser;
  readonly isOwner: boolean;
  readonly support: BrowserSupport;
}) {
  const [list, setList] = useState<ListLoad>({ status: "loading" });
  const [unlockOpen, setUnlockOpen] = useState(initialUnlockOpen);
  // The banner on every page links here (CannotSignBanner.tsx): opening
  // /account?unlock while this page is already showing opens the unlock page.
  const path = usePath();
  useEffect(() => {
    if (new URL(path, "http://dashboard.invalid").searchParams.has("unlock")) setUnlockOpen(true);
  }, [path]);

  const reloadList = useCallback(() => {
    void (async () => {
      try {
        setList({ status: "loaded", data: await fetchUnlockKeys() });
      } catch (err) {
        setList(
          hiddenFor(err)
            ? { status: "hidden" }
            : { status: "failed", message: err instanceof AuthRequestError ? err.message : s.loadFailed },
        );
      }
    })();
  }, []);

  useEffect(() => {
    reloadList();
  }, [reloadList]);

  if (list.status === "hidden") return null;

  return (
    <>
      {unlockOpen && (
        <UnlockPage
          browser={browser}
          support={support}
          onUnlocked={() => {
            reloadList();
            window.dispatchEvent(new Event(custodyChangedEvent));
          }}
          onClose={() => {
            setUnlockOpen(false);
            navigate("/account", { replace: true });
          }}
        />
      )}
      <UnlockKeysSection
        list={list}
        browser={browser}
        isOwner={isOwner}
        support={support}
        reload={reloadList}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// The unlock page
// ---------------------------------------------------------------------------

type UnlockPhase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "done"; readonly canSign: boolean }
  | { readonly status: "failed"; readonly message: string };

function SupportNote({ support }: { readonly support: BrowserSupport }) {
  if (support === "ok") return null;
  return (
    <p className={`${noticeBase} ${degraded}`}>
      <span className={noticeBody}>{support === "webkit" ? strings.support.webkit : strings.support.none}</span>
    </p>
  );
}

function UnlockPage({
  browser,
  support,
  onUnlocked,
  onClose,
}: {
  readonly browser: WebAuthnBrowser;
  readonly support: BrowserSupport;
  readonly onUnlocked: (status: CustodyStatus) => void;
  readonly onClose: () => void;
}) {
  const headingId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [phase, setPhase] = useState<UnlockPhase>({ status: "idle" });
  const u = strings.unlock;

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const run = async () => {
    setPhase({ status: "working" });
    try {
      const status = await unlockCA(browser);
      setPhase({ status: "done", canSign: status.can_sign });
      onUnlocked(status);
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err, u.failed) });
    }
  };

  return (
    <section id="unlock" aria-labelledby={headingId} className={`${card} ${section}`}>
      <div className={sectionHeader}>
        <h2 id={headingId} ref={headingRef} tabIndex={-1} className={`${sectionHeading} ${focusRing}`}>
          {u.heading}
        </h2>
        <button type="button" onClick={onClose} className={smallButton}>
          {u.close}
        </button>
      </div>
      <p className={`max-w-prose ${proseText}`}>{u.intro}</p>
      <SupportNote support={support} />
      {phase.status !== "done" && (
        <button
          type="button"
          disabled={support !== "ok" || phase.status === "working"}
          onClick={() => void run()}
          className={`${primaryButton} ${focusRing}`}
        >
          {phase.status === "working" ? u.working : u.button}
        </button>
      )}
      {phase.status === "done" && (
        <p role="status" className={`${noticeBase} ${phase.canSign ? secondaryText : degraded}`}>
          <span className={noticeBody}>{phase.canSign ? u.done : u.doneButStill}</span>
        </p>
      )}
      {phase.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{phase.message}</span>
        </p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// The section
// ---------------------------------------------------------------------------

function UnlockKeysSection({
  list,
  browser,
  isOwner,
  support,
  reload,
}: {
  readonly list: ListLoad;
  readonly browser: WebAuthnBrowser;
  readonly isOwner: boolean;
  readonly support: BrowserSupport;
  readonly reload: () => void;
}) {
  const headingId = useId();
  const keys = list.status === "loaded" ? list.data.keys : [];

  return (
    <section aria-labelledby={headingId} className={section}>
      <div className={sectionHeader}>
        <h2 id={headingId} className={sectionHeading}>
          {s.heading}
        </h2>
      </div>
      <p className={sectionIntro}>{s.intro}</p>

      {list.status === "loading" && <p className={`text-micro ${mutedText}`}>{s.loading}</p>}
      {list.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{list.message}</span>
        </p>
      )}

      {list.status === "loaded" && (
        <>
          {!list.data.custody.enabled ? (
            <p className={`text-micro ${secondaryText}`}>{s.custodyOff}</p>
          ) : (
            !list.data.custody.reachable && <p className={`text-micro ${secondaryText}`}>{s.custodyUnreachable}</p>
          )}
          {list.data.custody.enabled && !keys.some((k) => k.state === "active") && (
            <ActivationNote keys={keys} />
          )}
          {keys.length === 0 ? (
            <p className={`text-micro ${secondaryText}`}>{s.empty}</p>
          ) : (
            <KeysTable keys={keys} browser={browser} isOwner={isOwner} reload={reload} />
          )}
          <AddUnlockKey count={keys.length} browser={browser} support={support} reload={reload} />
        </>
      )}
    </section>
  );
}

function ActivationNote({ keys }: { readonly keys: readonly UnlockKey[] }) {
  const pending = keys.filter((k) => k.state === "pending");
  const commands =
    pending.length === 0
      ? [s.activationCommand(s.activationPlaceholder)]
      : pending.map((k) => s.activationCommand(k.custody_recipient));
  return (
    <div className={secretBlock}>
      <p className={`max-w-prose text-micro leading-prose ${secondaryText}`}>{s.activationNote}</p>
      {commands.map((command) => (
        <div key={command} className={secretRow}>
          <code className={`${commandValue} break-all`}>{command}</code>
          {pending.length > 0 && <CopyButton value={command} label={s.copyCommand} />}
        </div>
      ))}
    </div>
  );
}

type RowPhase =
  | { readonly status: "idle" }
  | { readonly status: "confirming" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

function statePill(state: string): string {
  return machineStatusPill[state] ?? neutralPill;
}

function KeysTable({
  keys,
  browser,
  isOwner,
  reload,
}: {
  readonly keys: readonly UnlockKey[];
  readonly browser: WebAuthnBrowser;
  readonly isOwner: boolean;
  readonly reload: () => void;
}) {
  const [rows, setRows] = useState<Record<string, RowPhase>>({});
  const rowOf = (id: string): RowPhase => rows[id] ?? { status: "idle" };
  const setRow = (id: string, phase: RowPhase) => setRows((prev) => ({ ...prev, [id]: phase }));

  const revoke = async (id: string) => {
    setRow(id, { status: "working" });
    try {
      await revokeUnlockKey(id, browser);
      setRow(id, { status: "idle" });
      reload();
    } catch (err) {
      setRow(id, { status: "failed", message: messageFor(err, s.revokeFailed) });
    }
  };

  return (
    <div className={scrollingTablePanel}>
      <table className={table}>
        <caption className={srOnly}>{s.heading}</caption>
        <thead>
          <tr>
            <th scope="col" className={columnHeader}>{s.labelHeader}</th>
            <th scope="col" className={columnHeader}>{s.stateHeader}</th>
            <th scope="col" className={columnHeader}>{s.fingerprintHeader}</th>
            <th scope="col" className={columnHeader}>{s.addedHeader}</th>
            <th scope="col" className={columnHeader}>{s.lastUsedHeader}</th>
            <th scope="col" className={columnHeader}>
              <span className={srOnly}>{s.actionsHeader}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => {
            const phase = rowOf(k.id);
            const revocable = k.state !== "revoked" && (k.mine || isOwner);
            return (
              <tr key={k.id}>
                <th scope="row" className={rowHeader}>
                  <div className="flex flex-col gap-0.5">
                    <span className="whitespace-nowrap">{k.label}</span>
                    {!k.mine && <span className={`text-micro ${mutedText}`}>{s.ownerOf(k.owner)}</span>}
                  </div>
                </th>
                <td className={cell}>
                  <span className={statePill(k.state)}>{wordFor(s.states, k.state)}</span>
                </td>
                <td className={cell}>
                  <code className={`${idValue} break-all`}>{k.custody_fingerprint}</code>
                </td>
                <td className={`${cell} whitespace-nowrap`}>{formatDate(k.created_at)}</td>
                <td className={`${cell} whitespace-nowrap`}>
                  {k.last_used_at === null ? s.neverUsed : formatDate(k.last_used_at)}
                </td>
                <td className={cell}>
                  {revocable && phase.status === "confirming" && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`max-w-prose text-micro ${secondaryText}`}>{s.revokeConfirmPrompt}</span>
                      <button type="button" onClick={() => void revoke(k.id)} className={secondaryButton}>
                        {s.revokeConfirmButton}
                      </button>
                      <button type="button" onClick={() => setRow(k.id, { status: "idle" })} className={secondaryButton}>
                        {s.revokeCancelButton}
                      </button>
                    </div>
                  )}
                  {revocable && phase.status !== "confirming" && (
                    <button
                      type="button"
                      disabled={phase.status === "working"}
                      onClick={() => setRow(k.id, { status: "confirming" })}
                      className={secondaryButton}
                    >
                      {phase.status === "working" ? s.revokeWorking : s.revokeButton}
                    </button>
                  )}
                  {phase.status === "failed" && (
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
  );
}

type AddPhase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "added" }
  | { readonly status: "failed"; readonly message: string };

function AddUnlockKey({
  count,
  browser,
  support,
  reload,
}: {
  readonly count: number;
  readonly browser: WebAuthnBrowser;
  readonly support: BrowserSupport;
  readonly reload: () => void;
}) {
  const labelId = useId();
  const hintId = useId();
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState(() => s.defaultLabel(count + 1));
  const [phase, setPhase] = useState<AddPhase>({ status: "idle" });

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      await enrolUnlockKey(label.trim(), browser);
      setPhase({ status: "added" });
      setOpen(false);
      setLabel(s.defaultLabel(count + 2));
      reload();
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err, s.addFailed) });
    }
  };

  return (
    <div className="flex flex-col gap-2">
      {phase.status === "added" && (
        <p role="status" className={`text-micro ${secondaryText}`}>
          {s.addedNotice}
        </p>
      )}
      {!open ? (
        <button
          type="button"
          onClick={() => {
            setOpen(true);
            setPhase({ status: "idle" });
          }}
          className={smallButton}
        >
          {s.addOpenButton}
        </button>
      ) : (
        <div className={`${card}`}>
          <p className={`max-w-prose text-micro leading-prose ${secondaryText}`}>{s.addSteps}</p>
          <SupportNote support={support} />
          <form onSubmit={(e) => void submit(e)} className="flex flex-wrap items-end gap-2">
            <div className={`${fieldStack} min-w-[12rem] flex-1 sm:max-w-xs`}>
              <label htmlFor={labelId} className={`text-micro ${fieldLabel}`}>
                {s.addLabel}
              </label>
              <input
                id={labelId}
                type="text"
                required
                maxLength={64}
                autoComplete="off"
                aria-describedby={hintId}
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                className={`${fieldInput} ${focusRing}`}
              />
            </div>
            <button
              type="submit"
              disabled={support !== "ok" || phase.status === "working"}
              className={`${primaryButton.replace("self-start", "self-end")} ${focusRing}`}
            >
              {phase.status === "working" ? s.addWorking : s.addButton}
            </button>
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                setPhase({ status: "idle" });
              }}
              className={`${secondaryButton.replace("self-start", "self-end")} ${focusRing}`}
            >
              {s.cancelButton}
            </button>
          </form>
          <span id={hintId} className={`text-micro ${secondaryText}`}>
            {s.addLabelHint}
          </span>
          {phase.status === "failed" && (
            <p role="alert" className={`${noticeBase} ${degraded}`}>
              <span className={noticeBody}>{phase.message}</span>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
