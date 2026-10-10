// SPDX-License-Identifier: Apache-2.0

/*
 * #445 (ADR-0062's accounts amendment) — the account page: profile name
 * editable inline, every passkey with rename/remove (the last one guarded),
 * adding a passkey via the same WebAuthn ceremony enrolment uses, and
 * recovery-code generation through the save step SetupPage also uses.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AccountPage } from "./AccountPage";
import { strings } from "./strings";
import type {
  Account,
  AccountAgents,
  AccountMachine,
  AccountOrganisation,
  AccountRepository,
  AccountSession,
} from "./types";
import type { WebAuthnBrowser } from "./client";

const ALL_ACTIONS = [
  "read_ledger",
  "resolve_alerts",
  "manage_own_sign_in",
  "connect_machine",
  "revoke_machine",
  "grant_repositories",
  "manage_members",
] as const;

function privileges(role: string) {
  const manages = role === "owner" || role === "admin";
  return ALL_ACTIONS.map((action) => ({
    action,
    allowed:
      action === "connect_machine" || action === "revoke_machine"
        ? manages
        : action !== "grant_repositories" && action !== "manage_members",
  }));
}

const ORG_OWNER: AccountOrganisation = {
  id: "org-1",
  name: "example-org",
  role: "owner",
  operator: true,
  privileges: privileges("owner"),
};

const ORG_MEMBER: AccountOrganisation = { ...ORG_OWNER, role: "member", privileges: privileges("member") };

function machines(canManage = true): AccountMachine[] {
  return [
    {
      id: "m-1",
      organisation_id: "org-1",
      organisation: "example-org",
      name: "build-runner-1",
      kind: "service",
      status: "active",
      repos: ["github.com/example/app"],
      enrolled_at: "2026-09-05T00:00:00Z",
      last_renewed_at: "2026-09-20T00:00:00Z",
      last_run_at: "2026-09-29T00:00:00Z",
      revoked_at: null,
      can_manage: canManage,
    },
    {
      id: "m-2",
      organisation_id: "org-1",
      organisation: "example-org",
      name: "laptop",
      kind: "workstation",
      status: "revoked",
      repos: ["*"],
      enrolled_at: "2026-09-02T00:00:00Z",
      last_renewed_at: null,
      last_run_at: null,
      revoked_at: "2026-09-25T00:00:00Z",
      can_manage: canManage,
    },
  ];
}

const SESSIONS: AccountSession[] = [
  {
    id: "s-1",
    created_at: "2026-10-01T00:00:00Z",
    expires_at: "2026-10-02T00:00:00Z",
    current: true,
    passkey_name: "MacBook",
  },
  {
    id: "s-2",
    created_at: "2026-09-30T00:00:00Z",
    expires_at: "2026-10-01T12:00:00Z",
    current: false,
    passkey_name: null,
  },
];

const REPOSITORIES: AccountRepository[] = [
  {
    repo: "github.com/example/app",
    organisation_id: "org-1",
    organisation: "example-org",
    since: "2026-09-03T00:00:00Z",
    runs: 12,
    commits: 30,
    last_event_at: "2026-09-29T00:00:00Z",
  },
  {
    repo: "github.com/example/docs",
    organisation_id: "org-1",
    organisation: "example-org",
    since: "2026-09-04T00:00:00Z",
    runs: 0,
    commits: 0,
    last_event_at: null,
  },
];

const AGENTS: AccountAgents = {
  agent_types: [
    { agent_type: "claude-code", runs: 9, last_registered_at: "2026-09-29T00:00:00Z" },
    { agent_type: "reviewer", runs: 3, last_registered_at: "2026-09-28T00:00:00Z" },
  ],
  recent_runs: [
    {
      run_id: "run-abc",
      agent_type: "claude-code",
      task_ref: "fix the build",
      registered_at: "2026-09-29T00:00:00Z",
      machine_id: "m-1",
      machine_name: "build-runner-1",
    },
  ],
};

interface Spine {
  machines?: AccountMachine[] | "unavailable";
  sessions?: AccountSession[];
  repositories?: AccountRepository[] | "unavailable";
  agents?: AccountAgents | "unavailable";
  caFingerprint?: string;
}

function account(overrides: Partial<Account> = {}): Account {
  return {
    user_id: "user-1",
    display_name: "Dev Operator",
    created_at: "2026-09-01T00:00:00Z",
    passkeys: [
      {
        id: "pk-1",
        name: "MacBook",
        created_at: "2026-09-01T00:00:00Z",
        last_used_at: "2026-09-30T00:00:00Z",
        current: true,
      },
      {
        id: "pk-2",
        name: "Phone",
        created_at: "2026-09-10T00:00:00Z",
        last_used_at: null,
        current: false,
      },
    ],
    recovery_codes_remaining: 8,
    organisations: [ORG_OWNER],
    sign_ins: [],
    ...overrides,
  };
}

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

function workingBrowser(): WebAuthnBrowser {
  return {
    supported: true,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: (json) => json as never,
      parseRequestOptionsFromJSON: (json) => json as never,
    },
    credentials: {
      create: async () => ({ toJSON: () => ({ id: "cred-new" }) }) as unknown as Credential,
      get: async () => ({ toJSON: () => ({ id: "cred-new" }) }) as unknown as Credential,
    },
  };
}

/** Routes every request this page can make against one in-memory account,
 * so a mutation's effect is visible on the next GET — the same "the real
 * server would do this" level of fidelity Playwright's page.route mocks
 * give, kept here so this file does not have to hand-wire call counts. */
function installAccountFetch(initial: Account, spine: Spine = {}) {
  let current = initial;
  let machineList = spine.machines ?? machines();
  let sessionList = spine.sessions ?? SESSIONS;
  const unavailable = () =>
    respond({ error: { code: "unavailable", message: "no accounts store" } }, 503);
  const calls: Array<{ url: string; method: string; body: unknown }> = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, method, body });

      if (url.endsWith("/api/v1/account") && method === "GET") {
        return respond(current);
      }
      if (url.endsWith("/api/v1/account") && method === "PATCH") {
        current = { ...current, display_name: (body as { display_name: string }).display_name };
        return respond(current);
      }
      const renameMatch = /\/api\/v1\/account\/passkeys\/([^/]+)$/.exec(url);
      if (renameMatch && method === "PATCH") {
        const id = renameMatch[1];
        current = {
          ...current,
          passkeys: current.passkeys.map((p) =>
            p.id === id ? { ...p, name: (body as { name: string }).name } : p,
          ),
        };
        return respond(current.passkeys.find((p) => p.id === id));
      }
      if (renameMatch && method === "DELETE") {
        const id = renameMatch[1];
        if (current.passkeys.length <= 1) {
          return respond({ error: { code: "conflict", message: "the last passkey cannot be removed" } }, 409);
        }
        current = { ...current, passkeys: current.passkeys.filter((p) => p.id !== id) };
        return respond({});
      }
      if (url.endsWith("/account/passkeys/begin") && method === "POST") {
        return respond({ ceremony_id: "cer-1", publicKey: { challenge: "abc" } });
      }
      if (url.endsWith("/account/passkeys/finish") && method === "POST") {
        const added = {
          id: "pk-new",
          name: "Passkey 3",
          created_at: "2026-10-01T00:00:00Z",
          last_used_at: null,
          current: false,
        };
        current = { ...current, passkeys: [...current.passkeys, added] };
        return respond(added);
      }
      if (url.endsWith("/account/machines") && method === "GET") {
        return machineList === "unavailable" ? unavailable() : respond({ machines: machineList, ca_fingerprint: spine.caFingerprint ?? "" });
      }
      if (url.endsWith("/account/machines/revoke/begin") && method === "POST") {
        return respond({ ceremony_id: "cer-revoke", publicKey: { challenge: "abc" } });
      }
      if (url.endsWith("/account/machines/revoke/finish") && method === "POST") {
        if (machineList === "unavailable") return unavailable();
        machineList = machineList.map((m) =>
          m.id === "m-1" ? { ...m, status: "revoked", revoked_at: "2026-10-01T00:00:00Z" } : m,
        );
        return respond(machineList[0]);
      }
      if (url.includes("/account/members?") && method === "GET") {
        if (machineList === "unavailable") return unavailable();
        return respond({
          can_manage: false,
          members: [{ user_id: "user-1", display_name: "Dev Operator", role: "owner", since: "2026-09-01T00:00:00Z", you: true }],
          invitations: [],
        });
      }
      const statusMatch = /\/account\/machines\/(suspend|resume)\/(begin|finish)$/.exec(url);
      if (statusMatch && method === "POST") {
        if (statusMatch[2] === "begin") {
          return respond({ ceremony_id: `cer-${statusMatch[1]}`, publicKey: { challenge: "abc" } });
        }
        if (machineList === "unavailable") return unavailable();
        const to = statusMatch[1] === "suspend" ? "suspended" : "active";
        machineList = machineList.map((m) => (m.id === "m-1" ? { ...m, status: to } : m));
        return respond(machineList[0]);
      }
      if (url.endsWith("/account/enrolment-tokens/begin") && method === "POST") {
        return respond({ ceremony_id: "cer-token", publicKey: { challenge: "abc" } });
      }
      if (url.endsWith("/account/enrolment-tokens/finish") && method === "POST") {
        return respond({
          token: "ie_0123456789abcdef_secret",
          expires_at: "2026-10-01T00:15:00Z",
          organisation_id: "org-1",
          kind: "workstation",
          repos: ["*"],
        });
      }
      if (url.endsWith("/account/sessions") && method === "GET") {
        return respond({ sessions: sessionList });
      }
      if (url.endsWith("/account/sessions/sign-out-others") && method === "POST") {
        const before = sessionList.length;
        sessionList = sessionList.filter((x) => x.current);
        return respond({ signed_out: before - sessionList.length });
      }
      if (url.endsWith("/account/repositories") && method === "GET") {
        const r = spine.repositories ?? REPOSITORIES;
        return r === "unavailable" ? unavailable() : respond({ repositories: r });
      }
      if (url.endsWith("/account/agents") && method === "GET") {
        const a = spine.agents ?? AGENTS;
        return a === "unavailable" ? unavailable() : respond(a);
      }
      if (url.endsWith("/account/recovery-codes") && method === "POST") {
        current = { ...current, recovery_codes_remaining: 10 };
        return respond({ codes: Array.from({ length: 10 }, (_, i) => `new-code-${i}`) });
      }
      if (url.includes("/account/sso?") && method === "GET") {
        if (machineList === "unavailable") return unavailable();
        return respond({ organisation_id: "org-1", configured: false, has_client_secret: false, can_manage: false });
      }
      throw new Error(`unexpected fetch ${method} ${url}`);
    }),
  );

  return { calls, current: () => current };
}

beforeEach(() => {
  window.history.replaceState(null, "", "/account");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AccountPage", () => {
  it("loads and shows the profile name, every passkey, and codes remaining", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    expect(await screen.findByText("Dev Operator")).toBeInTheDocument();
    // Scoped: the machines table has a Name column too, and it may load first.
    const passkeys = screen.getByRole("region", { name: strings.account.passkeysHeading });
    expect(within(passkeys).getByRole("columnheader", { name: strings.account.passkeyNameHeader })).toBeInTheDocument();
    expect(screen.getByText("MacBook")).toBeInTheDocument();
    expect(screen.getByText("Phone")).toBeInTheDocument();
    expect(screen.getByText(strings.account.currentDevice)).toBeInTheDocument();
    expect(screen.getByText(strings.account.passkeyNeverUsed)).toBeInTheDocument();
    expect(screen.getByText(`8 ${strings.account.recoveryOf}`)).toBeInTheDocument();
  });

  it("names a passkey enrolled before passkeys had names", async () => {
    const [first, ...rest] = account().passkeys;
    if (first === undefined) throw new Error("fixture has no passkey");
    installAccountFetch(account({ passkeys: [{ ...first, name: "" }, ...rest] }));
    render(<AccountPage browser={workingBrowser()} />);

    expect(await screen.findByText(strings.account.unnamedPasskey)).toBeInTheDocument();
  });

  it("edits and saves the display name inline", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await user.click(await screen.findByRole("button", { name: strings.account.editButton }));
    const input = screen.getByDisplayValue("Dev Operator");
    await user.clear(input);
    await user.type(input, "New Name");
    await user.click(screen.getByRole("button", { name: strings.account.saveButton }));

    await waitFor(() => expect(screen.getByText("New Name")).toBeInTheDocument());
    expect(fetches.current().display_name).toBe("New Name");
  });

  it("renames a passkey inline", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    const macRow = screen.getByText("MacBook").closest("tr");
    if (macRow === null) throw new Error("no row for MacBook");
    await user.click(within(macRow).getByRole("button", { name: strings.account.renameButton }));
    const input = within(macRow).getByDisplayValue("MacBook");
    await user.clear(input);
    await user.type(input, "Work laptop");
    await user.click(within(macRow).getByRole("button", { name: strings.account.saveButton }));

    await waitFor(() => expect(screen.getByText("Work laptop")).toBeInTheDocument());
  });

  it("removes a passkey after a confirm step, when it is not the last one", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("Phone");
    const phoneRow = screen.getByText("Phone").closest("tr");
    if (phoneRow === null) throw new Error("no row for Phone");
    await user.click(within(phoneRow).getByRole("button", { name: strings.account.removeButton }));
    expect(within(phoneRow).getByText(strings.account.removeConfirmPrompt)).toBeInTheDocument();
    await user.click(within(phoneRow).getByRole("button", { name: strings.account.removeConfirmButton }));

    await waitFor(() => expect(screen.queryByText("Phone")).not.toBeInTheDocument());
  });

  it("disables Remove, with a tooltip, on the account's last passkey", async () => {
    installAccountFetch(account({ passkeys: [account().passkeys[0]!] }));
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    const row = screen.getByText("MacBook").closest("tr");
    if (row === null) throw new Error("no row for MacBook");
    const remove = within(row).getByRole("button", { name: strings.account.removeButton });
    expect(remove).toBeDisabled();
    expect(remove).toHaveAttribute("title", strings.account.removeLastTooltip);
  });

  it("adds a passkey through the WebAuthn ceremony, defaulting its name", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText("MacBook");
    // Compact: the name field is not on the page until the action is chosen.
    expect(screen.queryByDisplayValue("Passkey 3")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.account.addOpenButton }));
    expect(screen.getByDisplayValue("Passkey 3")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.account.addButton }));

    await waitFor(() => expect(screen.getByText("Passkey 3")).toBeInTheDocument());
  });

  it("generates new recovery codes after a confirm step, then returns to the remaining count", async () => {
    installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    await screen.findByText(`8 ${strings.account.recoveryOf}`);
    await user.click(screen.getByRole("button", { name: strings.account.regenerateButton }));
    expect(screen.getByText(strings.account.regenerateConfirmPrompt)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.account.regenerateConfirmButton }));

    expect(
      await screen.findByRole("heading", { name: strings.recoveryCodes.heading }),
    ).toBeInTheDocument();
    expect(screen.getByText("new-code-0")).toBeInTheDocument();

    await user.click(
      screen.getByRole("checkbox", { name: strings.recoveryCodes.savedCheckbox }),
    );
    await user.click(screen.getByRole("button", { name: strings.recoveryCodes.continueButton }));

    expect(await screen.findByText(`10 ${strings.account.recoveryOf}`)).toBeInTheDocument();
  });

  it("shows the recovery-sign-in notice once, then drops the query from the address", async () => {
    window.history.replaceState(null, "", "/account?notice=recovery-signin");
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    expect(
      await screen.findByText(new RegExp(strings.account.recoverySignInNotice)),
    ).toBeInTheDocument();
    await waitFor(() => expect(window.location.search).toBe(""));
  });

  it("shows a load failure as an alert", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => respond({ error: { code: "unauthorized", message: "no session" } }, 401)),
    );
    render(<AccountPage browser={workingBrowser()} />);

    const alerts = await screen.findAllByRole("alert");
    expect(alerts[0]).toHaveTextContent("no session");
  });
  it("shows the user id with a copy control, and the organisation and role", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    expect(await screen.findByText("user-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: strings.account.copyUserId })).toBeInTheDocument();
    const identity = screen.getByRole("region", { name: "Dev Operator" });
    expect(within(identity).getByText("example-org")).toBeInTheDocument();
    expect(within(identity).getByText(strings.account.roles.owner)).toBeInTheDocument();
  });

  it("lists what the role may and may not do, saying where the rest is done", async () => {
    installAccountFetch(account({ organisations: [ORG_MEMBER] }));
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.privilegesHeading });
    const allowed = within(region).getByRole("list", { name: strings.account.privilegesAllowed });
    const denied = within(region).getByRole("list", { name: strings.account.privilegesDenied });
    expect(within(allowed).getByText(strings.account.privileges.read_ledger)).toBeInTheDocument();
    expect(within(denied).getByText(strings.account.privileges.connect_machine)).toBeInTheDocument();
    expect(within(denied).getByText(strings.account.privileges.grant_repositories)).toBeInTheDocument();
    expect(within(denied).getByText(strings.account.privilegeNotes.grant_repositories)).toBeInTheDocument();
  });

  it("lists the organisation's machines with status, repositories and last activity", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    const row = (await within(region).findByText("build-runner-1")).closest("tr");
    if (row === null) throw new Error("no row for build-runner-1");
    expect(within(row).getByText(strings.account.machineStatus.active)).toBeInTheDocument();
    expect(within(row).getByText(strings.account.machineKind.service)).toBeInTheDocument();
    expect(within(row).getByText("github.com/example/app")).toBeInTheDocument();
    // Last active reads as an age, with the full date on hover.
    expect(within(row).getByText(/ ago$/)).toHaveAttribute("title", expect.stringContaining("2026"));
    const laptop = within(region).getByText("laptop").closest("tr");
    if (laptop === null) throw new Error("no row for laptop");
    expect(within(laptop).getByText(strings.account.machineStatus.revoked)).toBeInTheDocument();
    expect(within(laptop).getByText(strings.account.allRepositories)).toBeInTheDocument();
    expect(within(laptop).getByText(strings.account.notYet)).toBeInTheDocument();
    expect(within(laptop).queryByRole("button", { name: strings.account.revokeButton })).toBeNull();
  });

  it("revokes a machine after a confirm step and a passkey", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    const row = (await within(region).findByText("build-runner-1")).closest("tr");
    if (row === null) throw new Error("no row");
    await user.click(within(row).getByRole("button", { name: strings.account.revokeButton }));
    expect(within(row).getByText(strings.account.revokeConfirmPrompt)).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: strings.account.revokeConfirmButton }));

    await waitFor(() =>
      expect(within(row).getByText(strings.account.machineStatus.revoked)).toBeInTheDocument(),
    );
    const begin = fetches.calls.find((c) => c.url.endsWith("/machines/revoke/begin"));
    expect(begin?.body).toEqual({ machine_id: "m-1" });
    expect(fetches.calls.some((c) => c.url.endsWith("/machines/revoke/finish"))).toBe(true);
  });

  it("does not offer revoke or connect to a member, and says who can", async () => {
    installAccountFetch(account({ organisations: [ORG_MEMBER] }), { machines: machines(false) });
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    await within(region).findByText("build-runner-1");
    expect(within(region).queryByRole("button", { name: strings.account.revokeButton })).toBeNull();
    expect(within(region).queryByRole("button", { name: strings.account.connectButton })).toBeNull();
    expect(within(region).getByText(strings.account.connectNeedsRole)).toBeInTheDocument();
  });

  it("chooses the kind of machine from two described choices", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    const kinds = within(region).getByRole("radiogroup", { name: strings.account.connectKindLabel });
    expect(within(kinds).getByRole("radio", { name: new RegExp(strings.account.machineKind.workstation) })).toBeChecked();
    expect(within(kinds).getByText(strings.account.connectKindHelp.workstation)).toBeInTheDocument();
    expect(within(kinds).getByText(strings.account.connectKindHelp.service)).toBeInTheDocument();

    await user.click(within(kinds).getByRole("radio", { name: new RegExp(strings.account.machineKind.service) }));
    await user.click(within(region).getByRole("button", { name: strings.account.connectButton }));
    await within(region).findByText("ie_0123456789abcdef_secret");
    const begin = fetches.calls.find((c) => c.url.endsWith("/enrolment-tokens/begin"));
    expect(begin?.body).toEqual({ organisation_id: "org-1", kind: "service", repos: ["*"] });
  });

  it("says how long ago a machine was last active, with the date on hover", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-09-29T03:00:00Z") });
    try {
      installAccountFetch(account());
      render(<AccountPage browser={workingBrowser()} />);
      const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
      const cell = await within(region).findByText("3 hours ago");
      expect(cell).toHaveAttribute("title");
    } finally {
      vi.useRealTimers();
    }
  });

  it("pins the core by its CA fingerprint in the connect command when the API knows it", async () => {
    installAccountFetch(account(), { caFingerprint: "sha256:0a1b2c" });
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    await user.click(within(region).getByRole("button", { name: strings.account.connectButton }));

    await within(region).findByText("ie_0123456789abcdef_secret");
    const command = `innsegl connect https://${window.location.hostname}:28095 --token ie_0123456789abcdef_secret --ca-fingerprint sha256:0a1b2c`;
    expect(within(region).getByText(command)).toBeInTheDocument();
    // FE-148: a pinned command has no placeholder to replace.
    expect(within(region).queryByText(strings.account.connectCaNote)).toBeNull();
  });

  it("connects a machine: a passkey, then the token once with the one-line command and its expiry", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    await user.click(within(region).getByRole("button", { name: strings.account.connectButton }));

    expect(await within(region).findByText("ie_0123456789abcdef_secret")).toBeInTheDocument();
    const command = `innsegl connect https://${window.location.hostname}:28095 --token ie_0123456789abcdef_secret --ca ${strings.account.connectCaPlaceholder}`;
    expect(within(region).getByText(command)).toBeInTheDocument();
    expect(within(region).getByText(/00:15/)).toBeInTheDocument();
    expect(within(region).getByRole("button", { name: strings.account.copyToken })).toBeInTheDocument();
    expect(within(region).getByRole("button", { name: strings.account.copyCommand })).toBeInTheDocument();
    const begin = fetches.calls.find((c) => c.url.endsWith("/enrolment-tokens/begin"));
    expect(begin?.body).toEqual({ organisation_id: "org-1", kind: "workstation", repos: ["*"] });

    await user.click(within(region).getByRole("button", { name: strings.account.connectDone }));
    expect(within(region).queryByText("ie_0123456789abcdef_secret")).toBeNull();
  });

  it("says quietly when the deployment keeps no organisation records, without failing the page", async () => {
    installAccountFetch(account(), {
      machines: "unavailable",
      repositories: "unavailable",
      agents: "unavailable",
    });
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    expect(await within(region).findByText(strings.account.spineUnavailable)).toBeInTheDocument();
    expect(screen.getByText("MacBook")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("lists the organisation's repositories with runs, commits and last activity", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.repositoriesHeading });
    const row = (await within(region).findByText("github.com/example/app")).closest("tr");
    if (row === null) throw new Error("no row");
    expect(within(row).getByText("12")).toBeInTheDocument();
    expect(within(row).getByText("30")).toBeInTheDocument();
    const docs = within(region).getByText("github.com/example/docs").closest("tr");
    if (docs === null) throw new Error("no row");
    expect(within(docs).getByText(strings.account.nothingRecorded)).toBeInTheDocument();
  });

  it("summarises agent types and links each recent run to its run page", async () => {
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.agentsHeading });
    const types = await within(region).findByRole("list", { name: strings.account.agentTypesHeading });
    expect(within(types).getByRole("link", { name: /claude-code/ })).toHaveAttribute(
      "href",
      "/agent-types/claude-code",
    );
    expect(within(types).getByText("9")).toBeInTheDocument();
    expect(within(region).getByRole("link", { name: "run-abc" })).toHaveAttribute("href", "/runs/run-abc");
    expect(within(region).getByText("build-runner-1")).toBeInTheDocument();
  });

  it("lists sign-ins, marks this browser, and signs the others out", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.sessionsHeading });
    expect(await within(region).findByText(strings.account.thisBrowser)).toBeInTheDocument();
    expect(within(region).getByText(strings.account.sessionRecoveryCode)).toBeInTheDocument();
    await user.click(within(region).getByRole("button", { name: strings.account.signOutOthers }));

    await waitFor(() =>
      expect(within(region).queryByText(strings.account.sessionRecoveryCode)).toBeNull(),
    );
    expect(fetches.calls.some((c) => c.url.endsWith("/sessions/sign-out-others"))).toBe(true);
  });
});

/*
 * FE-141 (#471, #486): connecting a machine from the dashboard. A fresh
 * passkey, then the single-use token once with the one-line `innsegl
 * connect` command (the "connects a machine" case above). For a person in
 * several organisations the token is minted for the organisation the
 * header's switcher chose, so the machine records where they are looking.
 */
describe("FE-141 connecting a machine from the dashboard", () => {
  afterEach(() => {
    document.cookie = "innsegl_organisation=; Path=/; Max-Age=0";
  });

  it("mints for the organisation the switcher chose", async () => {
    const TEAM: AccountOrganisation = { ...ORG_OWNER, id: "org-2", name: "example-team", operator: false };
    document.cookie = "innsegl_organisation=org-2; Path=/";
    const fetches = installAccountFetch(account({ organisations: [ORG_OWNER, TEAM] }));
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);

    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    expect(within(region).getByLabelText(strings.account.connectOrganisationLabel)).toHaveValue("org-2");
    await user.click(within(region).getByRole("button", { name: strings.account.connectButton }));

    expect(await within(region).findByText("ie_0123456789abcdef_secret")).toBeInTheDocument();
    const begin = fetches.calls.find((c) => c.url.endsWith("/enrolment-tokens/begin"));
    expect(begin?.body).toEqual({ organisation_id: "org-2", kind: "workstation", repos: ["*"] });
  });
});

/*
 * FE-146 (#471): suspend and resume a machine from the account page, each
 * confirmed with a passkey, beside revoke. Suspended is shown and undone;
 * revoked offers nothing.
 */
function rowOf(region: HTMLElement, name: string): HTMLElement {
  const row = within(region)
    .getAllByRole("row")
    .find((r) => r.textContent?.includes(name));
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

describe("FE-146 suspending and resuming a machine", () => {
  it("suspends an active machine and resumes it, each after a passkey", async () => {
    const fetches = installAccountFetch(account());
    const user = userEvent.setup();
    render(<AccountPage browser={workingBrowser()} />);
    const region = await screen.findByRole("region", { name: strings.account.machinesHeading });
    const row = await waitFor(() => rowOf(region, "build-runner-1"));

    await user.click(within(row).getByRole("button", { name: strings.account.suspendButton }));
    expect(within(row).getByText(strings.account.suspendConfirmPrompt)).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: strings.account.suspendConfirmButton }));
    const suspended = await waitFor(() => rowOf(region, "build-runner-1"));
    expect(await within(suspended).findByText(strings.account.machineStatus.suspended)).toBeInTheDocument();
    expect(fetches.calls.some((c) => c.url.endsWith("/machines/suspend/finish"))).toBe(true);

    await user.click(within(suspended).getByRole("button", { name: strings.account.resumeButton }));
    await user.click(within(suspended).getByRole("button", { name: strings.account.resumeConfirmButton }));
    const resumed = await waitFor(() => rowOf(region, "build-runner-1"));
    expect(await within(resumed).findByText(strings.account.machineStatus.active)).toBeInTheDocument();
    expect(fetches.calls.find((c) => c.url.endsWith("/machines/resume/begin"))?.body).toEqual({ machine_id: "m-1" });

    const revoked = rowOf(region, "laptop");
    expect(within(revoked).queryByRole("button")).toBeNull();
  });
});

describe("FE-151 the account page and an organisation's sign-in", () => {
  it("names the organisation whose sign-in opened a session", async () => {
    installAccountFetch(account(), {
      sessions: [{ ...SESSIONS[0]!, passkey_name: null, organisation_sign_in: "example-org" }],
    });
    render(<AccountPage browser={workingBrowser()} />);
    const region = await screen.findByRole("region", { name: strings.account.sessionsHeading });
    expect(await within(region).findByText(strings.account.sessionOrganisation("example-org"))).toBeInTheDocument();
    expect(within(region).queryByText(strings.account.sessionRecoveryCode)).not.toBeInTheDocument();
  });

  it("shows the organisation sign-in section, and says once that a sign-in was connected", async () => {
    window.history.replaceState(null, "", "/account?notice=sso-linked");
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);
    expect(await screen.findByText(strings.account.ssoLinkedNotice)).toBeInTheDocument();
    expect(await screen.findByRole("region", { name: strings.account.ssoHeading })).toBeInTheDocument();
    await waitFor(() => expect(window.location.search).toBe(""));
  });

  it("says why connecting a sign-in was refused, from the catalogue only", async () => {
    window.history.replaceState(null, "", "/account?sso=taken");
    installAccountFetch(account());
    render(<AccountPage browser={workingBrowser()} />);
    expect(await screen.findByText(strings.ssoReasons["taken"] ?? "")).toBeInTheDocument();
    await waitFor(() => expect(window.location.search).toBe(""));
  });
});
