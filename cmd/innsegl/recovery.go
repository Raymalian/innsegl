// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
)

const recoveryBase = "/_core/recovery/"

type recoveryStore interface {
	RegisterRecovery(context.Context, string, []byte) error
	BeginRecovery(context.Context, string, string, string) (string, error)
	Recover(context.Context, string, string, string, string, []byte, accounts.IssueFunc) error
}

func recoveryHandler(store recoveryStore, authority clientAuthority, log *serveLog) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeCoreError(w, 405, "innsegl core: recovery requires POST")
			return
		}
		var in struct {
			Installation string `json:"installation_id"`
			CSR          string `json:"csr"`
			Challenge    string `json:"challenge"`
			Signature    string `json:"signature"`
			Public       string `json:"recovery_key"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrolBody)).Decode(&in); err != nil {
			writeCoreError(w, 400, "innsegl core: invalid recovery request")
			return
		}
		origin := "https://" + r.Host
		if r.URL.Path == recoveryBase+"enroll" {
			id, ok := gateway.InstallationFromContext(r.Context())
			if !ok {
				gateway.WriteClientRefusal(w)
				return
			}
			public, err := base64.StdEncoding.DecodeString(in.Public)
			if err != nil || len(public) != 32 {
				writeCoreError(w, 400, "innsegl core: invalid recovery key")
				return
			}
			err = store.RegisterRecovery(r.Context(), id, public)
			if errors.Is(err, accounts.ErrNotFound) {
				gateway.WriteClientRefusal(w)
				return
			}
			if err != nil {
				log.warn("device proof enrollment unavailable", "err", err)
				writeCoreError(w, 503, "innsegl core: recovery enrollment unavailable; retry")
				return
			}
			writeCoreJSON(w, 200, map[string]bool{"recovery_enrolled": true})
			return
		}
		der, id, ok := decodeCSR(in.CSR, authority.TrustDomain())
		if !ok || id != in.Installation {
			gateway.WriteClientRefusal(w)
			return
		}
		switch r.URL.Path {
		case recoveryBase + "challenge":
			nonce, err := store.BeginRecovery(r.Context(), id, origin, in.CSR)
			if err != nil {
				writeCoreError(w, 503, "innsegl core: recovery unavailable; retry")
				return
			}
			writeCoreJSON(w, 200, map[string]string{"challenge": nonce})
			return
		case recoveryBase + "issue":
			signature, err := base64.StdEncoding.DecodeString(in.Signature)
			if err != nil {
				gateway.WriteClientRefusal(w)
				return
			}
			var out issuedCertificate
			err = store.Recover(r.Context(), id, origin, in.CSR, in.Challenge, signature, func(ctx context.Context, _ accounts.Installation) error {
				var mintErr error
				out, mintErr = mint(ctx, authority, der, id)
				return mintErr
			})
			if errors.Is(err, accounts.ErrNotFound) {
				gateway.WriteClientRefusal(w)
				return
			}
			if err != nil {
				log.warn("device recovery unavailable", "err", err)
				writeCoreError(w, 503, "innsegl core: recovery unavailable; retry")
				return
			}
			writeCoreJSON(w, 200, out)
		default:
			http.NotFound(w, r)
		}
	})
}
