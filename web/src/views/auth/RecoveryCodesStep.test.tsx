// SPDX-License-Identifier: Apache-2.0

/*
 * #445 — the recovery-codes save step shared by SetupPage and AccountPage:
 * the ten codes are on screen, "Continue" stays disabled until the reader
 * admits they saved them, and the download link actually carries the codes.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RecoveryCodesStep } from "./RecoveryCodesStep";
import { strings } from "./strings";

const CODES = [
  "abcd-1234",
  "efgh-5678",
  "ijkl-9012",
  "mnop-3456",
  "qrst-7890",
  "uvwx-1234",
  "yzab-5678",
  "cdef-9012",
  "ghij-3456",
  "klmn-7890",
];

describe("RecoveryCodesStep", () => {
  it("shows every code, and a download link carrying all of them as a .txt", () => {
    render(<RecoveryCodesStep codes={CODES} onContinue={() => {}} />);
    for (const code of CODES) {
      expect(screen.getByText(code)).toBeInTheDocument();
    }
    const download = screen.getByRole("link", { name: strings.recoveryCodes.downloadButton });
    expect(download).toHaveAttribute("download", "innsegl-recovery-codes.txt");
    const href = download.getAttribute("href") ?? "";
    expect(decodeURIComponent(href)).toContain(CODES[0]);
    expect(decodeURIComponent(href)).toContain(CODES[9]);
  });

  it("copies every code to the clipboard and confirms it", async () => {
    const user = userEvent.setup();
    render(<RecoveryCodesStep codes={CODES} onContinue={() => {}} />);
    await user.click(screen.getByRole("button", { name: strings.recoveryCodes.copyButton }));
    await expect(navigator.clipboard.readText()).resolves.toBe(CODES.join("\n"));
    expect(
      await screen.findByRole("button", { name: strings.recoveryCodes.copiedButton }),
    ).toBeInTheDocument();
  });

  it("keeps Continue disabled until the saved checkbox is checked, then calls onContinue", async () => {
    const user = userEvent.setup();
    const onContinue = vi.fn();
    render(<RecoveryCodesStep codes={CODES} onContinue={onContinue} />);

    const continueButton = screen.getByRole("button", { name: strings.recoveryCodes.continueButton });
    expect(continueButton).toBeDisabled();

    await user.click(screen.getByRole("checkbox", { name: strings.recoveryCodes.savedCheckbox }));
    expect(continueButton).toBeEnabled();

    await user.click(continueButton);
    expect(onContinue).toHaveBeenCalledTimes(1);
  });
});
