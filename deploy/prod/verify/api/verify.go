// SPDX-License-Identifier: Apache-2.0

// Package handler is the Vercel Go entrypoint for verify.innsegl.dev.
//
// Vercel's Go runtime builds one function per file in this directory that
// exports Handler(http.ResponseWriter, *http.Request) — see
// https://vercel.com/docs/functions/runtimes/go. Everything this file does
// is read environment configuration once and hand every request to
// internal/edge.Handler; internal/edge is where the actual logic (and its
// tests) live, so this file stays thin enough that there is nothing here to
// get wrong that a test would not already have caught one layer down.
package handler

import (
	"log"
	"net/http"
	"os"

	"innsegl.dev/innsegl/deploy/prod/verify/internal/edge"
)

// buildHandler reads this deployment's configuration from the environment.
// It is called once per request rather than cached: everything it does is
// local (field assignment, a URL join) with no network call, so the cost of
// not caching it is negligible next to the GitHub/Fulcio/Rekor round trips
// every request already makes — and a handler rebuilt every time is a
// handler with no cross-request state to get wrong or to make this file
// harder to test than the thin wrapper it is meant to be.
// Vercel Project Settings names these; see the deploy notes in this
// directory's issue (#69) for the values ADR-0042 requires:
//
//	INNSEGL_FULCIO_URL   this deployment's own Fulcio (unchanged by ADR-0042)
//	INNSEGL_REKOR_URL    the PUBLIC Rekor anchor under ADR-0042 (rekor.sigstore.dev),
//	                     or this deployment's own Rekor where the adopter answered
//	                     "only us" (doc 05 §1)
//	INNSEGL_OIDC_ISSUER  optional; constrains the certificate's OIDC issuer
//	INNSEGL_VERIFY_REPO  optional; defaults to edge.DefaultRepo
//	GITHUB_TOKEN         optional; raises GitHub's unauthenticated rate limit
func buildHandler() (*edge.Handler, error) {
	return edge.New(edge.Config{
		Repo:        os.Getenv("INNSEGL_VERIFY_REPO"),
		FulcioURL:   os.Getenv("INNSEGL_FULCIO_URL"),
		RekorURL:    os.Getenv("INNSEGL_REKOR_URL"),
		Issuer:      os.Getenv("INNSEGL_OIDC_ISSUER"),
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
	})
}

// Handler is the exported Vercel entrypoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	served, err := buildHandler()
	if err != nil {
		// A configuration internal/verify itself refused (ErrConfig) — a
		// deployment problem, not a per-request one.
		log.Printf("verify.innsegl.dev: misconfigured: %v", err)
		http.Error(w, "verify: misconfigured", http.StatusInternalServerError)
		return
	}
	served.ServeHTTP(w, r)
}
