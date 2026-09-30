// SPDX-License-Identifier: Apache-2.0

/*
 * The main column's final "Reply" card — Main.dc.html: the agent's own
 * closing message, with its keyed digest.
 */

import { truncateDigest } from "./derive";
import { strings } from "./strings";
import { bodyNote, replyGutter, replyRow } from "./styles";
import type { RecordMessage } from "./types";

export function Reply({ reply }: { readonly reply: RecordMessage }) {
  return (
    <section className={replyRow} aria-label={strings.reply.heading(reply.digest)}>
      <span className={replyGutter} aria-hidden="true" />
      <div className="flex-grow">
        <div className={bodyNote} title={reply.digest}>
          {strings.reply.heading(truncateDigest(reply.digest))}
        </div>
        <p className="mt-1.5 text-body text-ink">{reply.text}</p>
      </div>
    </section>
  );
}
