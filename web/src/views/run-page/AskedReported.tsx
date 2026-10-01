// SPDX-License-Identifier: Apache-2.0

/*
 * The main column's own "Asked to" / "Reported back" cards (#443, RM-278) —
 * Agent.dc.html. A subagent's whole dialogue with its parent, reduced to the
 * two messages that matter: what it was told to do, and what it said when it
 * was done. Replaces the old Brief/Reply cards, which read the record's
 * `brief`/`replies` — the gateway's own first-message/last-message pair,
 * which a subagent-aware record no longer needs: `agent.asked`/
 * `agent.reported` carry the same role, matched to the spawn rather than to
 * the gateway session.
 *
 * "Asked to" shows its first three lines and a "Show all N lines" toggle;
 * "Reported back" always shows in full, with its only two markdown spans —
 * `**bold**` and `` `code` `` — rendered, and nothing else.
 */

import { useState } from "react";
import type { ReactNode } from "react";

import { linesOf, parseInlineMarkdown } from "./derive";
import { strings } from "./strings";
import { askedBody, askedCard, cardHeadRow, cardKicker, cardShowAll, panelHeading, reportedBody, reportedCard } from "./styles";
import type { RecordText } from "./types";

const ASKED_PREVIEW_LINES = 3;
const REPORTED_PREVIEW_LINES = 4;

export function AskedTo({ asked }: { readonly asked: RecordText }) {
  if (!asked.available) return null;
  return (
    <Message
      id="asked-to-heading"
      heading={strings.agentPage.askedTo}
      caption={strings.agentPage.askedCaption}
      text={asked.text}
      preview={ASKED_PREVIEW_LINES}
      cardClass={askedCard}
      bodyClass={askedBody}
    />
  );
}

export function ReportedBack({ reported }: { readonly reported: RecordText }) {
  if (!reported.available) return null;
  return (
    <Message
      id="reported-back-heading"
      heading={strings.agentPage.reportedBack}
      caption={strings.agentPage.reportedCaption(reported.step)}
      text={reported.text}
      preview={REPORTED_PREVIEW_LINES}
      cardClass={reportedCard}
      bodyClass={reportedBody}
    />
  );
}

/** One of the agent's messages: the first lines, and all of them on
 * request; rendered as text (headings, lists, **bold**, `code`), never as
 * markdown source (#443). */
function Message({
  id,
  heading,
  caption,
  text,
  preview,
  cardClass,
  bodyClass,
}: {
  readonly id: string;
  readonly heading: string;
  readonly caption: string;
  readonly text: string;
  readonly preview: number;
  readonly cardClass: string;
  readonly bodyClass: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const { lines, total } = linesOf(text);
  const shown = expanded ? lines : firstLines(lines, preview);
  return (
    <section className={cardClass} aria-labelledby={id}>
      <div className={cardHeadRow}>
        <h2 id={id} className={panelHeading}>
          {heading}
        </h2>
        <span className={cardKicker}>{caption}</span>
        <span className="flex-grow" />
        {total > preview && !expanded ? (
          <button type="button" className={cardShowAll} onClick={() => setExpanded(true)}>
            {strings.agentPage.showAllLines(total)}
          </button>
        ) : null}
      </div>
      <div className={`${bodyClass} flex flex-col gap-2`}>{renderBlocks(shown)}</div>
    </section>
  );
}

/** The first n lines that carry text, with the blank lines between them. */
function firstLines(lines: readonly string[], n: number): string[] {
  const out: string[] = [];
  let kept = 0;
  for (const line of lines) {
    if (kept >= n) break;
    out.push(line);
    if (line.trim() !== "") kept++;
  }
  return out;
}

type Block =
  | { readonly kind: "heading"; readonly text: string }
  | { readonly kind: "list"; readonly items: string[] }
  | { readonly kind: "para"; readonly text: string };

function blocksOf(lines: readonly string[]): Block[] {
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: string[] = [];
  const flush = () => {
    if (para.length > 0) blocks.push({ kind: "para", text: para.join(" ") });
    if (list.length > 0) blocks.push({ kind: "list", items: list });
    para = [];
    list = [];
  };
  for (const raw of lines) {
    const line = raw.trim();
    const heading = /^#{1,6}\s+(.*)$/.exec(line);
    const item = /^[-*]\s+(.*)$/.exec(line);
    if (line === "") {
      flush();
    } else if (heading) {
      flush();
      blocks.push({ kind: "heading", text: heading[1] ?? "" });
    } else if (item) {
      if (para.length > 0) {
        blocks.push({ kind: "para", text: para.join(" ") });
        para = [];
      }
      list.push(item[1] ?? "");
    } else {
      if (list.length > 0) {
        blocks.push({ kind: "list", items: list });
        list = [];
      }
      para.push(line);
    }
  }
  flush();
  return blocks;
}

function renderBlocks(lines: readonly string[]): ReactNode[] {
  return blocksOf(lines).map((block, i) => {
    if (block.kind === "heading") {
      return (
        <p key={i} className="m-0 font-semibold">
          {renderInline(block.text)}
        </p>
      );
    }
    if (block.kind === "list") {
      return (
        <ul key={i} className="m-0 list-disc pl-5">
          {block.items.map((item, j) => (
            <li key={j}>{renderInline(item)}</li>
          ))}
        </ul>
      );
    }
    return (
      <p key={i} className="m-0">
        {renderInline(block.text)}
      </p>
    );
  });
}

function renderInline(text: string): ReactNode[] {
  return parseInlineMarkdown(text).map((token, i) => {
    if (token.kind === "bold") return <strong key={i}>{token.value}</strong>;
    if (token.kind === "code") return <code key={i} className="font-mono text-[0.9em]">{token.value}</code>;
    return <span key={i}>{token.value}</span>;
  });
}
