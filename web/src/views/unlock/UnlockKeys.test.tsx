// SPDX-License-Identifier: Apache-2.0

/*
 * FE-154 / FE-156, component half (#616): the account page's "Unlock keys"
 * section, the banner when the CA cannot sign, and the unlock page. The API
 * module is replaced; api.test.ts holds the ceremonies themselves.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WebAuthnBrowser } from "../auth/client";
import type { AccountOrganisation } from "../auth/types";
import * as api from "./api";
import { strings } from "./strings";
import { UnlockKeys } from "./UnlockKeys";

vi.mock("./api", async (importOriginal) => {
  const real = await importOriginal<typeof import("./api")>();
  return {
    ...real,
    fetchUnlockKeys: vi.fn(),
    fetchCustodyStatus: vi.fn(),
    enrolUnlockKey: vi.fn(),
    revokeUnlockKey: vi.fn(),
    unlockCA: vi.fn(),
  };
});

const CHROME =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const SAFARI =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";

const browser: WebAuthnBrowser = {
  supported: true,
  publicKeyCredential: {
    parseCreationOptionsFromJSON: (j) => j as never,
    parseRequestOptionsFromJSON: (j) => j as never,
  },
  credentials: { create: async () => null, get: async () => null },
};

function org(role: string, operator = true): AccountOrganisation {
  return { id: "org-1", name: "example-org", role, operator, privileges: [] };
}

function key(overrides: Partial<api.UnlockKey>): api.UnlockKey {
  return {
    id: "k1",
    label: "Desk key",
    state: "active",
    mine: true,
    owner: "Dev Operator",
    custody_recipient: "age1custodyrecipientaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    custody_fingerprint: "SHA256:custodyfp",
    backup_recipient: "age1backup",
    backup_fingerprint: "SHA256:backupfp",
    created_at: "2026-10-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    ...overrides,
  };
}

const fetchKeys = vi.mocked(api.fetchUnlockKeys);
const fetchStatus = vi.mocked(api.fetchCustodyStatus);
const enrol = vi.mocked(api.enrolUnlockKey);
const revoke = vi.mocked(api.revokeUnlockKey);
const unlock = vi.mocked(api.unlockCA);

const SIGNING = { enabled: true, initialized: true, sealed: false, can_sign: true };
const LOCKED = { enabled: true, initialized: true, sealed: true, can_sign: false, reason: "the store is sealed" };

beforeEach(() => {
  fetchKeys.mockResolvedValue({ custody: { enabled: true, reachable: true }, keys: [key({})] });
  fetchStatus.mockResolvedValue(SIGNING);
  window.history.replaceState(null, "", "/account");
});

afterEach(() => {
  vi.clearAllMocks();
});

function renderKeys(role = "owner", userAgent = CHROME, operator = true) {
  return render(<UnlockKeys organisations={[org(role, operator)]} browser={browser} userAgent={userAgent} />);
}

describe("FE-154 the unlock-keys section", () => {
  it("is not shown, and reads nothing, for a member or outside the operator organisation", () => {
    const { container } = renderKeys("member");
    expect(container).toBeEmptyDOMElement();
    renderKeys("owner", CHROME, false);
    expect(fetchKeys).not.toHaveBeenCalled();
    expect(fetchStatus).not.toHaveBeenCalled();
  });

  it("is not shown when the API answers 403 or 404", async () => {
    fetchKeys.mockRejectedValue(new (await import("../auth/client")).AuthRequestError("no", 404));
    fetchStatus.mockRejectedValue(new (await import("../auth/client")).AuthRequestError("no", 404));
    const { container } = renderKeys("admin");
    await waitFor(() => expect(fetchKeys).toHaveBeenCalled());
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("lists each key with its state, and says how the first key is activated", async () => {
    fetchKeys.mockResolvedValue({
      custody: { enabled: true, reachable: true },
      keys: [
        key({ id: "k1", label: "Desk key", state: "pending" }),
        key({ id: "k2", label: "Safe key", state: "revoked", revoked_at: "2026-10-05T00:00:00Z" }),
      ],
    });
    renderKeys();
    const table = await screen.findByRole("table", { name: strings.section.heading });
    const rows = within(table).getAllByRole("row");
    expect(within(rows[1]!).getByText("Desk key")).toBeInTheDocument();
    expect(within(rows[1]!).getByText(strings.section.states["pending"]!)).toBeInTheDocument();
    expect(within(rows[2]!).getByText(strings.section.states["revoked"]!)).toBeInTheDocument();
    // A revoked key has no revoke control.
    expect(within(rows[2]!).queryByRole("button", { name: strings.section.revokeButton })).toBeNull();
    // No key is active: the operator-machine command, with the pending key's recipient.
    expect(screen.getByText(strings.section.activationNote)).toBeInTheDocument();
    expect(
      screen.getByText(strings.section.activationCommand(key({}).custody_recipient)),
    ).toBeInTheDocument();
  });

  it("drops the activation note once a key is active", async () => {
    renderKeys();
    await screen.findByRole("table", { name: strings.section.heading });
    expect(screen.queryByText(strings.section.activationNote)).toBeNull();
  });

  it("says when custody is off or the custodian is not answering", async () => {
    fetchKeys.mockResolvedValue({ custody: { enabled: false, reachable: false }, keys: [] });
    renderKeys();
    expect(await screen.findByText(strings.section.custodyOff)).toBeInTheDocument();
    expect(screen.getByText(strings.section.empty)).toBeInTheDocument();
  });

  it("adds a security key and reloads the list", async () => {
    const user = userEvent.setup();
    enrol.mockResolvedValue(key({ id: "k3", label: "Travel key", state: "pending" }));
    renderKeys();
    await user.click(await screen.findByRole("button", { name: strings.section.addOpenButton }));
    const label = screen.getByLabelText(strings.section.addLabel);
    await user.clear(label);
    await user.type(label, "Travel key");
    await user.click(screen.getByRole("button", { name: strings.section.addButton }));
    await waitFor(() => expect(enrol).toHaveBeenCalledWith("Travel key", browser));
    expect(await screen.findByText(strings.section.addedNotice)).toBeInTheDocument();
    expect(fetchKeys).toHaveBeenCalledTimes(2);
  });

  it("FE-156: a key or browser without PRF gets the fallback message", async () => {
    const user = userEvent.setup();
    enrol.mockRejectedValue(new api.NoPRFError("no prf"));
    renderKeys();
    await user.click(await screen.findByRole("button", { name: strings.section.addOpenButton }));
    await user.click(screen.getByRole("button", { name: strings.section.addButton }));
    expect(await screen.findByText(strings.support.noPRF)).toBeInTheDocument();
  });

  it("FE-156: Safari is told to use Chrome, Edge or Firefox, and cannot start", async () => {
    const user = userEvent.setup();
    renderKeys("owner", SAFARI);
    await user.click(await screen.findByRole("button", { name: strings.section.addOpenButton }));
    expect(screen.getByText(strings.support.webkit)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: strings.section.addButton })).toBeDisabled();
  });

  it("revokes a key only after a confirmation", async () => {
    const user = userEvent.setup();
    revoke.mockResolvedValue(key({ state: "revoked" }));
    renderKeys();
    await user.click(await screen.findByRole("button", { name: strings.section.revokeButton }));
    expect(revoke).not.toHaveBeenCalled();
    expect(screen.getByText(strings.section.revokeConfirmPrompt)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.section.revokeConfirmButton }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("k1", browser));
    await waitFor(() => expect(fetchKeys).toHaveBeenCalledTimes(2));
  });
});

describe("FE-154 the banner and the unlock page", () => {
  it("shows no banner while the CA can sign", async () => {
    renderKeys();
    await screen.findByRole("table", { name: strings.section.heading });
    expect(screen.queryByText(strings.banner.title)).toBeNull();
  });

  it("shows the banner when the CA cannot sign, and unlocks from the page it opens", async () => {
    const user = userEvent.setup();
    fetchStatus.mockResolvedValueOnce(LOCKED).mockResolvedValue(SIGNING);
    unlock.mockResolvedValue(SIGNING);
    renderKeys();
    expect(await screen.findByText(strings.banner.title)).toBeInTheDocument();
    expect(screen.getByText(strings.banner.reason("the store is sealed"))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: strings.banner.action }));

    const page = screen.getByRole("region", { name: strings.unlock.heading });
    await user.click(within(page).getByRole("button", { name: strings.unlock.button }));
    await waitFor(() => expect(unlock).toHaveBeenCalledWith(browser));
    expect(await screen.findByText(strings.unlock.done)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText(strings.banner.title)).toBeNull());
  });

  it("opens the unlock page from ?unlock in the address", async () => {
    window.history.replaceState(null, "", "/account?unlock");
    fetchStatus.mockResolvedValue(LOCKED);
    renderKeys();
    expect(await screen.findByRole("region", { name: strings.unlock.heading })).toBeInTheDocument();
  });

  it("says when the material is not sealed to the key", async () => {
    const user = userEvent.setup();
    fetchStatus.mockResolvedValue(LOCKED);
    unlock.mockRejectedValue(new api.NotSealedToThisKeyError("no"));
    renderKeys();
    await user.click(await screen.findByRole("button", { name: strings.banner.action }));
    await user.click(screen.getByRole("button", { name: strings.unlock.button }));
    expect(await screen.findByText(strings.unlock.notSealed)).toBeInTheDocument();
  });

  it("FE-156: says when the key returned no PRF, and Safari cannot start", async () => {
    const user = userEvent.setup();
    fetchStatus.mockResolvedValue(LOCKED);
    unlock.mockRejectedValue(new api.NoPRFError("no"));
    renderKeys();
    await user.click(await screen.findByRole("button", { name: strings.banner.action }));
    await user.click(screen.getByRole("button", { name: strings.unlock.button }));
    expect(await screen.findByText(strings.support.noPRF)).toBeInTheDocument();
  });

  it("FE-156: Safari sees the browser note on the unlock page and no button to start", async () => {
    window.history.replaceState(null, "", "/account?unlock");
    fetchStatus.mockResolvedValue(LOCKED);
    renderKeys("owner", SAFARI);
    const page = await screen.findByRole("region", { name: strings.unlock.heading });
    expect(within(page).getByText(strings.support.webkit)).toBeInTheDocument();
    expect(within(page).getByRole("button", { name: strings.unlock.button })).toBeDisabled();
  });
});
