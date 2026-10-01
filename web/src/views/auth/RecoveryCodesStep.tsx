// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's accounts amendment (#445): the "save your recovery codes" step,
 * shared by SetupPage (the account's first ten codes) and AccountPage (a
 * regeneration's ten new ones) — one component, so saving codes reads and
 * behaves identically wherever it happens.
 *
 * The download is a real `<a download>` with a `data:` URI rather than
 * `URL.createObjectURL` — router.tsx's own argument applies here too: a real
 * anchor is keyboard-operable, "save link as"-able, and needs no DOM API
 * jsdom does not implement, for ten short lines of text that never
 * approaches a size where a data URI is the wrong tool.
 */

import { useId, useState } from "react";

import { strings } from "./strings";
import {
  checkboxRow,
  codeCell,
  codesGrid,
  focusRing,
  primaryButton,
  proseText,
  secondaryButton,
  sectionHeading,
} from "./styles";

export interface RecoveryCodesStepProps {
  readonly codes: readonly string[];
  readonly onContinue: () => void;
}

const FILE_NAME = "innsegl-recovery-codes.txt";

export function RecoveryCodesStep({ codes, onContinue }: RecoveryCodesStepProps) {
  const checkboxId = useId();
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);

  const copy = async () => {
    try {
      const clipboard = navigator.clipboard;
      if (clipboard === undefined) throw new Error("no clipboard");
      await clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      // P2: an unverified claim is worse than an admitted failure. The
      // codes stay on screen and the download link still works.
      setCopied(false);
    }
  };

  const fileHref = `data:text/plain;charset=utf-8,${encodeURIComponent(`${codes.join("\n")}\n`)}`;

  return (
    <div className="flex flex-col gap-4">
      <h2 className={sectionHeading}>{strings.recoveryCodes.heading}</h2>
      <p className={proseText}>{strings.recoveryCodes.intro}</p>

      <ol className={codesGrid}>
        {codes.map((code) => (
          <li key={code} className={codeCell}>
            {code}
          </li>
        ))}
      </ol>

      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={() => void copy()} className={`${secondaryButton} ${focusRing}`}>
          {copied ? strings.recoveryCodes.copiedButton : strings.recoveryCodes.copyButton}
        </button>
        <a href={fileHref} download={FILE_NAME} className={`${secondaryButton} ${focusRing}`}>
          {strings.recoveryCodes.downloadButton}
        </a>
      </div>

      <label htmlFor={checkboxId} className={checkboxRow}>
        <input
          id={checkboxId}
          type="checkbox"
          checked={saved}
          onChange={(event) => setSaved(event.target.checked)}
        />
        {strings.recoveryCodes.savedCheckbox}
      </label>

      <button
        type="button"
        disabled={!saved}
        onClick={onContinue}
        className={`${primaryButton} ${focusRing}`}
      >
        {strings.recoveryCodes.continueButton}
      </button>
    </div>
  );
}
