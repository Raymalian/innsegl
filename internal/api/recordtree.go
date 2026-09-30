// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"time"
)

// recordtree.go builds RecordTree (record.go): the whole family a run
// belongs to, root first, with each non-root member's own SpawnedBy.

// buildTree turns recordquery.go's family() rows into RecordTree.
func (rs *recordServer) buildTree(ctx context.Context, family []familyNode, logDir string) (RecordTree, error) {
	if len(family) == 0 {
		return RecordTree{}, nil
	}
	root := family[0].RunID
	for _, n := range family {
		if n.ParentRunID == "" {
			root = n.RunID
			break
		}
	}

	ids := make([]string, 0, len(family))
	for _, n := range family {
		ids = append(ids, n.RunID)
	}
	facts, err := rs.store.familyFacts(ctx, ids)
	if err != nil {
		return RecordTree{}, err
	}
	now := time.Now().UTC()
	horizon := rs.store.RestoreHorizon()

	spawnedBy, err := rs.spawnedByForFamily(ctx, logDir, family)
	if err != nil {
		return RecordTree{}, err
	}

	nodes := make([]RecordTreeNode, 0, len(family))
	for _, n := range family {
		f := facts[n.RunID]
		retiredAt, retired := f.RetiredAt, f.Retired
		status, _ := statusAndAt(f, retiredAt, retired, now, horizon)
		node := RecordTreeNode{
			RunID: n.RunID, AgentType: n.AgentType, ParentRunID: n.ParentRunID, Status: status,
		}
		if n.RunID == root {
			node.SpawnedBy = 0
		} else if by, ok := spawnedBy[n.RunID]; ok {
			node.SpawnedBy = by
		}
		nodes = append(nodes, node)
	}

	return RecordTree{RootRunID: root, Nodes: nodes}, nil
}
