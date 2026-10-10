// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
)

// API-038 (#467, the E23 exit criterion): a step's diff is read from the
// core's per-repository mirror, which holds the trees a client pushed as
// snapshot refs. The run page needs no snapshot store of its own.
func TestAPI038AStepsDiffIsReadFromTheRepositorysMirror(t *testing.T) {
	mirror := newBareStore(t)
	before := mirror.tree(t, map[string]string{"a.txt": mirror.blob(t, "one\n")})
	after := mirror.tree(t, map[string]string{"a.txt": mirror.blob(t, "one\ntwo\n"), "b.txt": mirror.blob(t, "new\n")})

	prover, err := NewProver(ProofConfig{
		FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:1",
		Repos:   staticRepos{"github.com/acme/widgets": mirror.dir},
		GitPath: mirror.gitPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := &recordServer{prover: prover, cfg: snapshotStoreConfig{gitPath: mirror.gitPath}}

	dir, ok := rs.storeDirFor(context.Background(), "github.com/acme/widgets")
	if !ok || dir != mirror.dir {
		t.Fatalf("storeDirFor = %q %v, want the repository's mirror %s", dir, ok, mirror.dir)
	}
	rows, err := diffTreeNumstat(context.Background(), rs.cfg, dir, before, after)
	if err != nil || len(rows) != 2 {
		t.Fatalf("diffTreeNumstat on the mirror = %+v %v, want two files", rows, err)
	}
	if _, ok := rs.storeDirFor(context.Background(), "github.com/acme/elsewhere"); ok {
		t.Fatal("a repository the mirror does not hold answered a store")
	}
	if _, ok := rs.storeDirFor(context.Background(), ""); ok {
		t.Fatal("no repository answered a store")
	}
}
