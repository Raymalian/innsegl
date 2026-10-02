// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/mirror"
)

// coregit.go — #464/#465, ADR-0065: the hosted core's per-repository mirror
// and the authenticated push endpoint that feeds it.
//
// A hosted client runs git on its own machine, so the objects of a commit
// it asks the core to sign exist only there. Its `innsegl sign` pushes them,
// through the client service, to commitpath.GitPathPrefix on the gateway's
// listener; the commit-sign path then reads the mirror (mcp.CommitMirror).
//
// The endpoint is mounted on the inner mux, so the client-certificate guard
// stands in front of it like every other client route; the handler checks
// the installation and the repository's scope again, and refuses with the
// guard's own 401. A single-host core, or a hosted core with no
// INNSEGL_MIRROR_DIR, mounts nothing.

// openCoreMirror opens the mirror store at dir, or answers nil when dir is
// empty (no mirror is kept).
func openCoreMirror(dir string) (*mirror.Store, error) {
	if dir == "" {
		return nil, nil
	}
	store, err := mirror.New(dir)
	if err != nil {
		return nil, fmt.Errorf("open the repository mirror ($%s): %w", mirror.EnvDir, err)
	}
	return store, nil
}

// commitMirror is the sign path's mirror: a nil interface, never a nil
// pointer inside one, when there is none.
func commitMirror(h *hostedCore) mcp.CommitMirror {
	if h == nil || h.mirror == nil {
		return nil
	}
	return h.mirror
}

// mountCoreGit serves the receive endpoint on a hosted core that keeps a
// mirror, and nothing otherwise.
func mountCoreGit(mux *http.ServeMux, h *hostedCore) error {
	if h == nil || h.mirror == nil {
		return nil
	}
	handler, err := mirror.NewHandler(mirror.HandlerConfig{
		Store:        h.mirror,
		Scope:        h.scope,
		Installation: gateway.InstallationFromContext,
		Refuse:       gateway.WriteClientRefusal,
	})
	if err != nil {
		return err
	}
	mux.Handle(commitpath.GitPathPrefix, handler)
	return nil
}
