// SPDX-License-Identifier: Apache-2.0

package commitpath_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// SNAP-009: a branch the mirror refuses as a rewrite is told apart from any
// other failed push, so the client can say so.
func TestSNAP009ARewrittenBranchIsRefusedAsDiverged(t *testing.T) {
	srv, _ := mpCore(t)
	dir := mpRepoDir(t)
	c := commitpath.Client{BaseURL: srv.URL}
	first := mpGit(t, dir, "rev-parse", "HEAD")
	if err := c.PushBranch(t.Context(), dir, "main", first); err != nil {
		t.Fatal(err)
	}
	mpGit(t, dir, "commit", "-q", "--amend", "--no-gpg-sign", "-m", "rewritten")
	rewritten := mpGit(t, dir, "rev-parse", "HEAD")
	err := c.PushBranch(t.Context(), dir, "main", rewritten)
	if !errors.Is(err, commitpath.ErrBranchDiverged) {
		t.Fatalf("pushing a rewrite = %v, want ErrBranchDiverged", err)
	}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_client/status" {
			if _, werr := w.Write([]byte(`{"installation_id":"` + mpInstallation + `"}`)); werr != nil {
				t.Error(werr)
			}
			return
		}
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	err = commitpath.Client{BaseURL: down.URL}.PushBranch(t.Context(), dir, "main", first)
	if err == nil || errors.Is(err, commitpath.ErrBranchDiverged) {
		t.Fatalf("a push the core could not take = %v, want a plain failure", err)
	}
}
