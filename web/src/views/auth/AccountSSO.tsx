// SPDX-License-Identifier: Apache-2.0

/*
 * The organisation sign-in section of the account page (#485, E30).
 *
 * An organisation's owner sets its own identity provider here: a sign-in
 * name, the issuer, the client id and (for a confidential client) the
 * secret, saved after a passkey. The page shows the redirect URI to
 * register at the provider. The secret never comes back; the page only
 * knows whether one is saved.
 *
 * Every member connects the organisation's sign-in to their own account
 * here, once, while signed in: the browser goes to the provider and comes
 * back connected. From then on the sign-in page takes it. Connected
 * sign-ins are listed by organisation (never by anything the provider
 * calls the person) and can be disconnected. Passkeys keep working.
 *
 * The server checks the owner role again on every change; what this page
 * offers is a courtesy, not the rule.
 */

import { useId, useState, type FormEvent } from "react";

import { AccountSection, CopyButton, SectionStatus, useSectionLoad } from "./accountShared";
import {
  AuthRequestError,
  beginLinkOrganisationSignIn,
  disconnectSignIn,
  fetchOrganisationSignIn,
  removeOrganisationSignIn,
  saveOrganisationSignIn,
  type WebAuthnBrowser,
} from "./client";
import { formatDate } from "./format";
import { strings } from "./strings";
import type { AccountOrganisation, AccountSignIn, AccountSSO } from "./types";
import {
  card,
  commandValue,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  mutedText,
  secondaryButton,
  secondaryText,
  secretBlock,
  subHeading,
} from "./styles";

const a = strings.account;

function message(err: unknown, fallback: string): string {
  if (err instanceof AuthRequestError) return err.message;
  return fallback;
}

export interface OrganisationSignInSectionProps {
  readonly organisations: readonly AccountOrganisation[];
  readonly signIns: readonly AccountSignIn[];
  readonly browser: WebAuthnBrowser;
  /** Re-reads the account, after a sign-in is disconnected. */
  readonly reload: () => void;
  /** Sends the browser to the provider. Injected for tests. */
  readonly goTo?: (url: string) => void;
}

export function OrganisationSignInSection({
  organisations,
  signIns,
  browser,
  reload,
  goTo = (url: string) => window.location.assign(url),
}: OrganisationSignInSectionProps) {
  const [failure, setFailure] = useState<string | null>(null);
  if (organisations.length === 0 && signIns.length === 0) return null;

  const disconnect = async (id: number) => {
    setFailure(null);
    try {
      await disconnectSignIn(id);
      reload();
    } catch (err) {
      setFailure(message(err, a.ssoDisconnectFailed));
    }
  };

  return (
    <AccountSection heading={a.ssoHeading} intro={a.ssoIntro}>
      {signIns.length > 0 && (
        <div className={card}>
          <h3 className={subHeading}>{a.ssoLinkedHeading}</h3>
          <ul className="flex flex-col gap-2">
            {signIns.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2 text-micro">
                <span className="font-medium">{a.ssoLinkedItem(s.organisation, s.sign_in_name)}</span>
                <span className={secondaryText}>
                  {a.ssoLinkedWhen(
                    formatDate(s.linked_at),
                    s.last_used_at === null ? null : formatDate(s.last_used_at),
                  )}
                </span>
                <button
                  type="button"
                  onClick={() => void disconnect(s.id)}
                  className={`${secondaryButton} ${focusRing}`}
                >
                  {a.ssoDisconnectButton}
                </button>
              </li>
            ))}
          </ul>
          {failure !== null && (
            <p role="alert" className={`text-micro ${mutedText}`}>
              {failure}
            </p>
          )}
        </div>
      )}
      {organisations.map((org) => (
        <OrganisationSignIn
          key={org.id}
          org={org}
          named={organisations.length > 1}
          connectedNames={signIns.map((s) => s.sign_in_name).filter((n) => n !== "")}
          browser={browser}
          goTo={goTo}
        />
      ))}
    </AccountSection>
  );
}

function OrganisationSignIn({
  org,
  named,
  connectedNames,
  browser,
  goTo,
}: {
  readonly org: AccountOrganisation;
  readonly named: boolean;
  readonly connectedNames: readonly string[];
  readonly browser: WebAuthnBrowser;
  readonly goTo: (url: string) => void;
}) {
  const [load, reload] = useSectionLoad<AccountSSO>(() => fetchOrganisationSignIn(org.id));
  const [connecting, setConnecting] = useState<string | null>(null);
  const data = load.status === "loaded" ? load.data : null;

  const connect = async () => {
    setConnecting("");
    try {
      goTo(await beginLinkOrganisationSignIn(org.id));
    } catch (err) {
      setConnecting(message(err, a.ssoConnectFailed));
    }
  };

  return (
    <div className={card}>
      {named && <h3 className={subHeading}>{org.name}</h3>}
      <SectionStatus load={load} />
      {data !== null && !data.configured && !data.can_manage && (
        <p className={`text-micro ${secondaryText}`}>{a.ssoNotConfigured}</p>
      )}
      {data?.configured === true && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-micro">{a.ssoSignInName(data.sign_in_name ?? "")}</span>
          {connectedNames.includes(data.sign_in_name ?? "") ? (
            <span className={`text-micro ${secondaryText}`}>{a.ssoConnected}</span>
          ) : (
            <button
              type="button"
              disabled={connecting === ""}
              onClick={() => void connect()}
              className={`${secondaryButton} ${focusRing}`}
            >
              {connecting === "" ? a.ssoConnectWorking : a.ssoConnectButton}
            </button>
          )}
        </div>
      )}
      {connecting !== null && connecting !== "" && (
        <p role="alert" className={`text-micro ${mutedText}`}>
          {connecting}
        </p>
      )}
      {data?.can_manage === true && <OwnerSettings org={org} view={data} browser={browser} saved={reload} />}
    </div>
  );
}

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "saved" }
  | { readonly status: "failed"; readonly message: string };

function OwnerSettings({
  org,
  view,
  browser,
  saved,
}: {
  readonly org: AccountOrganisation;
  readonly view: AccountSSO;
  readonly browser: WebAuthnBrowser;
  readonly saved: () => void;
}) {
  const nameId = useId();
  const nameHintId = useId();
  const issuerId = useId();
  const issuerHintId = useId();
  const clientId = useId();
  const secretId = useId();
  const secretHintId = useId();
  const redirectId = useId();
  const [name, setName] = useState(view.sign_in_name ?? "");
  const [issuer, setIssuer] = useState(view.issuer ?? "");
  const [client, setClient] = useState(view.client_id ?? "");
  const [secret, setSecret] = useState("");
  const [phase, setPhase] = useState<Phase>({ status: "idle" });
  const [removing, setRemoving] = useState(false);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      await saveOrganisationSignIn(
        org.id,
        {
          sign_in_name: name.trim(),
          issuer: issuer.trim(),
          client_id: client.trim(),
          client_secret: secret,
          keep_secret: secret === "" && view.has_client_secret,
        },
        browser,
      );
      setSecret("");
      setPhase({ status: "saved" });
      saved();
    } catch (err) {
      setPhase({ status: "failed", message: message(err, a.ssoSaveFailed) });
    }
  };

  const remove = async () => {
    setRemoving(false);
    setPhase({ status: "working" });
    try {
      await removeOrganisationSignIn(org.id, browser);
      setPhase({ status: "idle" });
      saved();
    } catch (err) {
      setPhase({ status: "failed", message: message(err, a.ssoRemoveFailed) });
    }
  };

  return (
    <form onSubmit={(e) => void save(e)} className="flex flex-col gap-3">
      <h4 className={subHeading}>{a.ssoOwnerHeading}</h4>
      <p className={`text-micro ${secondaryText}`}>{a.ssoOwnerIntro}</p>
      {view.redirect_uri !== undefined && (
        <div className={secretBlock}>
          <span id={redirectId} className={`text-micro ${fieldLabel}`}>
            {a.ssoRedirectLabel}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <code aria-labelledby={redirectId} className={commandValue}>
              {view.redirect_uri}
            </code>
            <CopyButton value={view.redirect_uri} label={a.copyRedirect} />
          </div>
        </div>
      )}
      <div className={fieldStack}>
        <label htmlFor={nameId} className={fieldLabel}>
          {a.ssoNameLabel}
        </label>
        <input
          id={nameId}
          required
          spellCheck={false}
          autoCapitalize="none"
          aria-describedby={nameHintId}
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={`${fieldInput} font-mono ${focusRing}`}
        />
        <span id={nameHintId} className={`text-micro ${secondaryText}`}>
          {a.ssoNameHint}
        </span>
      </div>
      <div className={fieldStack}>
        <label htmlFor={issuerId} className={fieldLabel}>
          {a.ssoIssuerLabel}
        </label>
        <input
          id={issuerId}
          type="url"
          required
          spellCheck={false}
          autoCapitalize="none"
          aria-describedby={issuerHintId}
          value={issuer}
          onChange={(e) => setIssuer(e.target.value)}
          className={`${fieldInput} font-mono ${focusRing}`}
        />
        <span id={issuerHintId} className={`text-micro ${secondaryText}`}>
          {a.ssoIssuerHint}
        </span>
      </div>
      <div className={fieldStack}>
        <label htmlFor={clientId} className={fieldLabel}>
          {a.ssoClientLabel}
        </label>
        <input
          id={clientId}
          required
          spellCheck={false}
          autoCapitalize="none"
          value={client}
          onChange={(e) => setClient(e.target.value)}
          className={`${fieldInput} font-mono ${focusRing}`}
        />
      </div>
      <div className={fieldStack}>
        <label htmlFor={secretId} className={fieldLabel}>
          {a.ssoSecretLabel}
        </label>
        <input
          id={secretId}
          type="password"
          autoComplete="off"
          aria-describedby={secretHintId}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          className={`${fieldInput} font-mono ${focusRing}`}
        />
        <span id={secretHintId} className={`text-micro ${secondaryText}`}>
          {view.has_client_secret ? a.ssoSecretKeepHint : a.ssoSecretHint}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button type="submit" disabled={phase.status === "working"} className={`${secondaryButton} ${focusRing}`}>
          {phase.status === "working" ? a.ssoSaving : a.ssoSaveButton}
        </button>
        {view.configured &&
          (removing ? (
            <>
              <span className={`text-micro ${secondaryText}`}>{a.ssoRemovePrompt}</span>
              <button type="button" onClick={() => void remove()} className={`${secondaryButton} ${focusRing}`}>
                {a.ssoRemoveConfirmButton}
              </button>
              <button type="button" onClick={() => setRemoving(false)} className={`${secondaryButton} ${focusRing}`}>
                {a.revokeCancelButton}
              </button>
            </>
          ) : (
            <button type="button" onClick={() => setRemoving(true)} className={`${secondaryButton} ${focusRing}`}>
              {a.ssoRemoveButton}
            </button>
          ))}
      </div>
      {phase.status === "saved" && <p className={`text-micro ${secondaryText}`}>{a.ssoSaved}</p>}
      {phase.status === "failed" && (
        <p role="alert" className={`text-micro ${mutedText}`}>
          {phase.message}
        </p>
      )}
    </form>
  );
}
