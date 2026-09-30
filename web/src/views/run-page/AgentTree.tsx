// SPDX-License-Identifier: Apache-2.0

/*
 * The left aside's "Agent tree" panel — Main.dc.html: the root run, its
 * spawned subagents indented beneath it, the selected run highlighted, and
 * the caption naming which step's spawn carried each child's brief.
 */

import type { ReactNode } from "react";

import { IdentifierChip } from "../../components/common/IdentifierChip";
import { Link } from "../../app/router";
import { AgentBranchIcon, AgentRootIcon } from "./icons";
import { strings } from "./strings";
import { panel, panelHeading, panelHeadingRow, panelPad, treeRow, treeRowChild, treeRowId, treeRowIcon, treeRowName, treeRowSelected } from "./styles";
import type { RecordTree } from "./types";

export interface AgentTreeProps {
  readonly tree: RecordTree;
  readonly selectedRunId: string;
}

export function AgentTree({ tree, selectedRunId }: AgentTreeProps) {
  const root = tree.nodes.find((n) => n.run_id === tree.root_run_id);
  const children = tree.nodes.filter((n) => n.run_id !== tree.root_run_id);

  return (
    <section className={panel} aria-labelledby="agent-tree-heading">
      <div className={panelHeadingRow}>
        <h2 id="agent-tree-heading" className={panelHeading}>
          {strings.tree.heading}
        </h2>
      </div>
      <div className="flex flex-col gap-0.5 p-2">
        {root === undefined ? null : (
          <TreeRow
            runId={root.run_id}
            agentType={root.agent_type}
            selected={root.run_id === selectedRunId}
            icon={<AgentRootIcon className={treeRowIcon} />}
            bold
          />
        )}
        {children.map((node) => (
          <TreeRow
            key={node.run_id}
            runId={node.run_id}
            agentType={node.agent_type}
            selected={node.run_id === selectedRunId}
            icon={<AgentBranchIcon className={treeRowIcon} />}
            indent
          />
        ))}
      </div>
      {children.map((node) => (
        <p key={node.run_id} className={panelPad}>
          {strings.tree.linkedBy(node.spawned_by)}
        </p>
      ))}
    </section>
  );
}

function TreeRow({
  runId,
  agentType,
  selected,
  icon,
  indent = false,
  bold = false,
}: {
  readonly runId: string;
  readonly agentType: string;
  readonly selected: boolean;
  readonly icon: ReactNode;
  readonly indent?: boolean;
  readonly bold?: boolean;
}) {
  return (
    <Link
      to={{ view: "run", runId }}
      className={`${treeRow} ${selected ? treeRowSelected : ""} ${indent ? treeRowChild : ""}`}
    >
      {icon}
      <span className={`${treeRowName} ${bold ? "font-semibold" : ""}`}>{agentType}</span>
      <span className={treeRowId}>
        <IdentifierChip value={runId} kind="run" maxLength={12} />
      </span>
    </Link>
  );
}
