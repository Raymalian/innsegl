// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

type noRelayedCalls struct{}

func (noRelayedCalls) LookupPending(string) (commitpath.RelayedCall, bool) {
	return commitpath.RelayedCall{}, false
}

// The commit path's two endpoints are served beside the proxy when the
// gateway has an identity stack to resolve tool calls against, and not at
// all when it has none: a gateway without one cannot authorise a commit.
func TestGatewayMountsTheCommitPathOnlyWithAResolver(t *testing.T) {
	proxied := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for _, tc := range []struct {
		name     string
		resolver commitpath.Resolver
		want     int
	}{
		{"with a resolver", noRelayedCalls{}, http.StatusForbidden},
		{"without one", nil, http.StatusTeapot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/", proxied)
			mountCommitPath(mux, tc.resolver)
			for _, path := range []string{commitpath.TrailersPath, commitpath.SignPath} {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path,
					strings.NewReader(`{"tool_use_id":"toolu_01Unknown"}`))
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != tc.want {
					t.Errorf("POST %s = %d, want %d: %s", path, rec.Code, tc.want, rec.Body)
				}
			}
		})
	}
}
