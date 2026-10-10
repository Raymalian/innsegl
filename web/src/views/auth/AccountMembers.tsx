// SPDX-License-Identifier: Apache-2.0

/*
 * The members section of the account page (#480, #481; E28). For each of
 * the person's organisations: who is in it and with which role. An owner or
 * admin also changes a member's role and removes a member, each confirmed
 * with a passkey, and makes an invitation link (shown once, after a passkey)
 * or withdraws a pending one. The server checks every one of these against
 * the role table (api.RoleMay) again; what this page offers is a courtesy,
 * not the rule.
 *
 * Nobody changes their own membership here: a person leaves or is demoted
 * by another owner or admin, so the last owner cannot lock themselves out.
 */

import { useId, useState } from "react";

import { AccountSection, CopyButton, SectionStatus, useSectionLoad } from "./accountShared";
import {
  AuthRequestError,
  changeMemberRole,
  createInvitation,
  fetchMembers,
  removeMember,
  withdrawInvitation,
  type WebAuthnBrowser,
} from "./client";
import { formatDate, formatDateTime } from "./format";
import { strings } from "./strings";
import type { AccountMembers, AccountOrganisation, InvitationLink } from "./types";
import {
  card,
  cell,
  columnHeader,
  commandValue,
  currentBadge,
  fieldLabel,
  focusRing,
  inlineSelect,
  mutedText,
  rowHeader,
  scrollingTablePanel,
  secondaryButton,
  secondaryText,
  secretBlock,
  srOnly,
  subHeading,
  table,
} from "./styles";

const a = strings.account;
const ROLES = ["owner", "admin", "member"] as const;

function message(err: unknown, fallback: string): string {
  if (err instanceof AuthRequestError) return err.message;
  return fallback;
}

export function MembersSection({
  organisations,
  browser,
}: {
  readonly organisations: readonly AccountOrganisation[];
  readonly browser: WebAuthnBrowser;
}) {
  if (organisations.length === 0) return null;
  return (
    <AccountSection heading={a.membersHeading} intro={a.membersIntro}>
      {organisations.map((org) => (
        <OrganisationMembers key={org.id} org={org} named={organisations.length > 1} browser={browser} />
      ))}
    </AccountSection>
  );
}

type Busy = { readonly what: string; readonly message?: string } | null;

function OrganisationMembers({
  org,
  named,
  browser,
}: {
  readonly org: AccountOrganisation;
  readonly named: boolean;
  readonly browser: WebAuthnBrowser;
}) {
  const [load, reload] = useSectionLoad<AccountMembers>(() => fetchMembers(org.id));
  const [roles, setRoles] = useState<Record<string, string>>({});
  const [removing, setRemoving] = useState<string | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [inviteRole, setInviteRole] = useState("member");
  const [link, setLink] = useState<InvitationLink | null>(null);
  const inviteRoleId = useId();
  const linkLabelId = useId();

  const run = async (what: string, act: () => Promise<unknown>, failed: string) => {
    setBusy({ what });
    try {
      await act();
      setBusy(null);
      reload();
    } catch (err) {
      setBusy({ what, message: message(err, failed) });
    }
  };

  const data = load.status === "loaded" ? load.data : null;
  const manage = data?.can_manage === true;
  const pending = data?.invitations.filter((i) => i.state === "pending") ?? [];

  return (
    <div className={card}>
      {named && <h3 className={subHeading}>{org.name}</h3>}
      <SectionStatus load={load} />
      {data && (
        <div className={scrollingTablePanel}>
          <table className={table}>
            <caption className={srOnly}>{a.membersCaption(org.name)}</caption>
            <thead>
              <tr>
                <th scope="col" className={columnHeader}>{a.memberNameHeader}</th>
                <th scope="col" className={columnHeader}>{a.memberRoleHeader}</th>
                <th scope="col" className={columnHeader}>{a.memberSinceHeader}</th>
                {manage && (
                  <th scope="col" className={columnHeader}>
                    <span className={srOnly}>{a.memberActionsHeader}</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {data.members.map((m) => {
                const chosen = roles[m.user_id] ?? m.role;
                return (
                  <tr key={m.user_id}>
                    <th scope="row" className={rowHeader}>
                      <span className="whitespace-nowrap">{m.display_name}</span>{" "}
                      {m.you && <span className={currentBadge}>{a.memberYou}</span>}
                    </th>
                    <td className={cell}>{a.roles[m.role as keyof typeof a.roles] ?? m.role}</td>
                    <td className={`${cell} whitespace-nowrap`}>{formatDate(m.since)}</td>
                    {manage && (
                      <td className={cell}>
                        {!m.you && (
                          <div className="flex flex-wrap items-center gap-2">
                            <label className="flex items-center gap-1">
                              <span className={srOnly}>{a.memberRoleLabel(m.display_name)}</span>
                              <select
                                value={chosen}
                                onChange={(e) => setRoles((r) => ({ ...r, [m.user_id]: e.target.value }))}
                                className={inlineSelect}
                              >
                                {ROLES.map((r) => (
                                  <option key={r} value={r}>
                                    {a.roles[r]}
                                  </option>
                                ))}
                              </select>
                            </label>
                            <button
                              type="button"
                              disabled={chosen === m.role}
                              onClick={() =>
                                void run(`role-${m.user_id}`, () => changeMemberRole(org.id, m.user_id, chosen, browser), a.memberRoleFailed)
                              }
                              className={`${secondaryButton} ${focusRing}`}
                            >
                              {a.memberRoleButton}
                            </button>
                            {removing === m.user_id ? (
                              <>
                                <span className={`text-micro ${secondaryText}`}>{a.memberRemovePrompt}</span>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setRemoving(null);
                                    void run(`remove-${m.user_id}`, () => removeMember(org.id, m.user_id, browser), a.memberRemoveFailed);
                                  }}
                                  className={`${secondaryButton} ${focusRing}`}
                                >
                                  {a.memberRemoveConfirmButton}
                                </button>
                                <button type="button" onClick={() => setRemoving(null)} className={`${secondaryButton} ${focusRing}`}>
                                  {a.revokeCancelButton}
                                </button>
                              </>
                            ) : (
                              <button type="button" onClick={() => setRemoving(m.user_id)} className={`${secondaryButton} ${focusRing}`}>
                                {a.memberRemoveButton}
                              </button>
                            )}
                          </div>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {manage && (
        <div className="flex flex-col gap-3">
          <h4 className={subHeading}>{a.invitationsHeading}</h4>
          {pending.length === 0 ? (
            <p className={`text-micro ${secondaryText}`}>{a.noPendingInvitations}</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {pending.map((i) => (
                <li key={i.id} className="flex flex-wrap items-center gap-2 text-micro">
                  <span>{a.pendingInvitation(a.roles[i.role as keyof typeof a.roles] ?? i.role, formatDateTime(i.expires_at))}</span>
                  <button
                    type="button"
                    onClick={() => void run(`withdraw-${i.id}`, () => withdrawInvitation(org.id, i.id), a.inviteWithdrawFailed)}
                    className={`${secondaryButton} ${focusRing}`}
                  >
                    {a.inviteWithdrawButton}
                  </button>
                </li>
              ))}
            </ul>
          )}

          {link ? (
            <div className={secretBlock}>
              <span id={linkLabelId} className={`text-micro ${fieldLabel}`}>{a.inviteLinkLabel}</span>
              <div className="flex flex-wrap items-center gap-2">
                <code aria-labelledby={linkLabelId} className={commandValue}>{link.link}</code>
                <CopyButton value={link.link} label={a.copyInviteLink} />
              </div>
              <span className={`text-micro ${secondaryText}`}>{a.inviteLinkOnce(formatDateTime(link.expires_at))}</span>
              <button type="button" onClick={() => setLink(null)} className={`${secondaryButton} ${focusRing}`}>
                {a.connectDone}
              </button>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <label htmlFor={inviteRoleId} className={`text-micro ${fieldLabel}`}>{a.inviteRoleLabel}</label>
              <select id={inviteRoleId} value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} className={inlineSelect}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {a.roles[r]}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() =>
                  void (async () => {
                    setBusy({ what: "invite" });
                    try {
                      setLink(await createInvitation(org.id, inviteRole, browser));
                      setBusy(null);
                      reload();
                    } catch (err) {
                      setBusy({ what: "invite", message: message(err, a.inviteFailed) });
                    }
                  })()
                }
                className={`${secondaryButton} ${focusRing}`}
              >
                {a.inviteButton}
              </button>
            </div>
          )}
        </div>
      )}

      {busy?.message !== undefined && busy !== null && (
        <p role="alert" className={`text-micro ${mutedText}`}>
          {busy.message}
        </p>
      )}
    </div>
  );
}
