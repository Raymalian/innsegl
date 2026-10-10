// SPDX-License-Identifier: Apache-2.0

/*
 * The account page's reads, as fixtures (#445; RM-333, #511): the account
 * itself, the organisation's machines, repositories and agents, and the
 * person's sign-ins. Example names only. Shared by the a11y, contrast and
 * visual suites and by mock-routes.ts, so every suite renders the same page.
 */

import type { Page, Route } from "@playwright/test";

const PRIVILEGE_ACTIONS = [
  "read_ledger",
  "resolve_alerts",
  "manage_own_sign_in",
  "connect_machine",
  "revoke_machine",
  "grant_repositories",
  "manage_members",
] as const;

export function privilegesFor(role: string): { action: string; allowed: boolean }[] {
  const manages = role === "owner" || role === "admin";
  return PRIVILEGE_ACTIONS.map((action) => ({
    action,
    allowed:
      action === "connect_machine" || action === "revoke_machine"
        ? manages
        : action !== "grant_repositories" && action !== "manage_members",
  }));
}

export function accountFixture(displayName = "Dev Operator") {
  return {
    user_id: "6f1c2a9b3d4e5f60718293a4b5c6d7e8",
    display_name: displayName,
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
    organisations: [
      {
        id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
        name: "example-org",
        role: "owner",
        operator: true,
        privileges: privilegesFor("owner"),
      },
    ],
  };
}

export const MACHINES = {
  machines: [
    {
      id: "4f3e2d1c0b0a99887766554433221100",
      organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      organisation: "example-org",
      name: "build-runner-1",
      kind: "service",
      status: "active",
      repos: ["github.com/example/app", "github.com/example/docs"],
      enrolled_at: "2026-09-05T00:00:00Z",
      last_renewed_at: "2026-09-20T00:00:00Z",
      last_run_at: "2026-09-29T00:00:00Z",
      revoked_at: null,
      can_manage: true,
    },
    {
      id: "00112233445566778899aabbccddeeff",
      organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      organisation: "example-org",
      name: "laptop",
      kind: "workstation",
      status: "active",
      repos: ["*"],
      enrolled_at: "2026-09-02T00:00:00Z",
      last_renewed_at: null,
      last_run_at: null,
      revoked_at: null,
      can_manage: true,
    },
    {
      id: "ffeeddccbbaa99887766554433221100",
      organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      organisation: "example-org",
      name: "old-desktop",
      kind: "workstation",
      status: "revoked",
      repos: ["*"],
      enrolled_at: "2026-08-20T00:00:00Z",
      last_renewed_at: "2026-08-25T00:00:00Z",
      last_run_at: null,
      revoked_at: "2026-09-01T00:00:00Z",
      can_manage: true,
    },
  ],
};

export const REPOSITORIES = {
  repositories: [
    {
      repo: "github.com/example/app",
      organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      organisation: "example-org",
      since: "2026-09-03T00:00:00Z",
      runs: 12,
      commits: 30,
      last_event_at: "2026-09-29T00:00:00Z",
    },
    {
      repo: "github.com/example/docs",
      organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      organisation: "example-org",
      since: "2026-09-04T00:00:00Z",
      runs: 0,
      commits: 0,
      last_event_at: null,
    },
  ],
};

export const AGENTS = {
  agent_types: [
    { agent_type: "claude-code", runs: 9, last_registered_at: "2026-09-29T00:00:00Z" },
    { agent_type: "reviewer", runs: 3, last_registered_at: "2026-09-28T00:00:00Z" },
  ],
  recent_runs: [
    {
      run_id: "01J9Z3K5V7X2B4N6M8P0Q2R4S6",
      agent_type: "claude-code",
      task_ref: "fix the flaky build step",
      registered_at: "2026-09-29T00:00:00Z",
      machine_id: "4f3e2d1c0b0a99887766554433221100",
      machine_name: "build-runner-1",
    },
    {
      run_id: "01J9Z1A3C5E7G9J1L3N5Q7S9U1",
      agent_type: "reviewer",
      task_ref: "review the release notes",
      registered_at: "2026-09-28T00:00:00Z",
      machine_id: "4f3e2d1c0b0a99887766554433221100",
      machine_name: "build-runner-1",
    },
  ],
};

export const SESSIONS = {
  sessions: [
    {
      id: "a1b2c3d4e5f60718",
      created_at: "2026-10-01T08:30:00Z",
      expires_at: "2026-10-02T08:30:00Z",
      current: true,
      passkey_name: "MacBook",
    },
    {
      id: "f0e1d2c3b4a59687",
      created_at: "2026-09-30T17:05:00Z",
      expires_at: "2026-10-01T17:05:00Z",
      current: false,
      passkey_name: null,
    },
  ],
};

export const ENROLMENT_TOKEN = {
  token: "ie_0123456789abcdef_" + "0123456789abcdef".repeat(4),
  expires_at: "2026-10-01T08:45:00Z",
  organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  kind: "workstation",
  repos: ["*"],
};

/** E28: the members section's read, as an owner sees it. */
export const MEMBERS = {
  can_manage: true,
  members: [
    { user_id: "6f1c2a9b3d4e5f60718293a4b5c6d7e8", display_name: "Dev Operator", role: "owner", since: "2026-09-01T00:00:00Z", you: true },
    { user_id: "7a8b9c0d1e2f30415263748596a7b8c9", display_name: "Grace Hopper", role: "admin", since: "2026-09-12T00:00:00Z", you: false },
    { user_id: "8b9c0d1e2f30415263748596a7b8c9d0", display_name: "Ada Lovelace", role: "member", since: "2026-09-20T00:00:00Z", you: false },
  ],
  invitations: [
    { id: 3, role: "member", state: "pending", created_by: "6f1c2a9b3d4e5f60718293a4b5c6d7e8", accepted_by: "", expires_at: "2026-10-04T09:00:00Z" },
  ],
};

/** #485: the organisation sign-in section's read, as an owner sees it. */
export const ORGANISATION_SIGN_IN = {
  organisation_id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  configured: true,
  sign_in_name: "example-org",
  issuer: "https://idp.example.test",
  client_id: "innsegl-dashboard",
  has_client_secret: true,
  redirect_uri: "http://localhost:8082/api/v1/auth/sso/callback",
  can_manage: true,
  updated_at: "2026-09-30T12:00:00Z",
};

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

/**
 * Answers an `/api/v1/account*` request with the fixtures above. Returns
 * false for any other path, so a suite's own router can carry on.
 */
export async function answerAccountRoute(
  route: Route,
  displayName = "Dev Operator",
): Promise<boolean> {
  const req = route.request();
  const p = new URL(req.url()).pathname;
  const method = req.method();
  if (p === "/api/v1/account" && method === "GET") {
    await json(route, accountFixture(displayName));
    return true;
  }
  if (p === "/api/v1/account/machines") {
    await json(route, MACHINES);
    return true;
  }
  if (p === "/api/v1/account/repositories") {
    await json(route, REPOSITORIES);
    return true;
  }
  if (p === "/api/v1/account/agents") {
    await json(route, AGENTS);
    return true;
  }
  if (p === "/api/v1/account/members") {
    await json(route, MEMBERS);
    return true;
  }
  if (p === "/api/v1/account/sessions") {
    await json(route, SESSIONS);
    return true;
  }
  if (p === "/api/v1/account/sso") {
    await json(route, ORGANISATION_SIGN_IN);
    return true;
  }
  if (p.endsWith("/begin") && method === "POST" && p.startsWith("/api/v1/account/")) {
    await json(route, {
      ceremony_id: "cer-1",
      publicKey: {
        challenge: "dGVzdC1jaGFsbGVuZ2U",
        rpId: "localhost",
        allowCredentials: [],
        userVerification: "required",
      },
    });
    return true;
  }
  if (p === "/api/v1/account/enrolment-tokens/finish") {
    await json(route, ENROLMENT_TOKEN);
    return true;
  }
  return false;
}

/** A complete signed-in router for a page that only shows the account. */
export async function installAccountMocks(page: Page, displayName = "Dev Operator"): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === "/api/v1/auth/session") {
      return json(route, { authenticated: true, display_name: displayName });
    }
    if (p === "/api/v1/auth/setup") return json(route, { needed: false });
    if (await answerAccountRoute(route, displayName)) return;
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

/** Stands in for the browser's passkey prompt: `credentials.get` answers a
 * fixed assertion, so a page that asks for a passkey can be driven to its
 * result. The mocked server accepts anything. */
export async function installFakePasskey(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const assertion = {
      toJSON: () => ({ id: "cred", rawId: "cred", type: "public-key", response: {} }),
    };
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: { get: async () => assertion, create: async () => assertion },
    });
    const pkc = (window as unknown as { PublicKeyCredential?: Record<string, unknown> })
      .PublicKeyCredential;
    if (pkc !== undefined) {
      pkc["parseRequestOptionsFromJSON"] = (json: unknown) => json;
      pkc["parseCreationOptionsFromJSON"] = (json: unknown) => json;
    }
  });
}
