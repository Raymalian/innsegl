// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/gateway"
)

// ADR-0076: the operator's machine unlocks the CA key store through the core.
// The core carries three things between that machine and the custodian, the
// only process on the store's network that the core can reach: the store's
// status, the sealed unlock material, and the unlock itself. It reads none of
// them and logs none of them.
const (
	coreCACustodyPath         = cacustody.CorePath
	coreCACustodyMaterialPath = cacustody.CoreMaterialPath
	coreCACustodyUnlockPath   = cacustody.CoreUnlockPath

	// envCACustodianURL is where the core reaches the custodian. Unset, this
	// core keeps its CA key in a file and says custody is off.
	envCACustodianURL = "INNSEGL_CA_CUSTODIAN_URL"

	// maxCoreUnlockBody bounds what the core forwards; the material is three
	// short strings.
	maxCoreUnlockBody = 64 << 10
)

type caCustodyStatus = cacustody.CoreStatus

const caCustodyForbidden = "innsegl core: ca custody: only an active workstation of the operator's " +
	"organisation, enrolled by its owner or an admin, may unlock the CA"

// caCustodyHandler serves the three routes behind the client guard, to the
// same machines the trust-key backup is served to.
func caCustodyHandler(custodian string, store trustBackupStore, limit *backupLimiter, log *serveLog) http.HandlerFunc {
	client := &http.Client{Timeout: 60 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		var want string
		switch r.URL.Path {
		case coreCACustodyPath, coreCACustodyMaterialPath:
			want = http.MethodGet
		case coreCACustodyUnlockPath:
			want = http.MethodPost
		default:
			writeCoreError(w, http.StatusNotFound, "innsegl core: ca custody: no such route")
			return
		}
		if r.Method != want {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: ca custody: only "+want+" is accepted here")
			return
		}
		if !admitOperatorMachine(w, r, store, limit, log, "ca custody", caCustodyForbidden) {
			return
		}
		if custodian == "" {
			if r.URL.Path == coreCACustodyPath {
				writeCoreJSON(w, http.StatusOK, caCustodyStatus{})
				return
			}
			writeCoreError(w, http.StatusNotFound, "innsegl core: this core keeps its CA key in a file; "+
				"custody is off ("+envCACustodianURL+" is unset)")
			return
		}
		base := strings.TrimSuffix(custodian, "/")
		switch r.URL.Path {
		case coreCACustodyPath:
			proxyCustodyStatus(r.Context(), w, client, base, log)
		case coreCACustodyMaterialPath:
			proxyCustody(r.Context(), w, client, http.MethodGet, base+cacustody.PathMaterial, nil, log)
		default:
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCoreUnlockBody))
			if err != nil {
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					writeCoreError(w, http.StatusRequestEntityTooLarge, "innsegl core: ca custody: the unlock is too large")
					return
				}
				writeCoreError(w, http.StatusBadRequest, "innsegl core: ca custody: the unlock could not be read")
				return
			}
			id, _ := gateway.InstallationFromContext(r.Context())
			log.info("ca custody: an unlock was forwarded", "installation_id", id)
			proxyCustody(r.Context(), w, client, http.MethodPost, base+cacustody.PathUnlock, body, log)
		}
	}
}

func proxyCustodyStatus(ctx context.Context, w http.ResponseWriter, client *http.Client, base string, log *serveLog) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+cacustody.PathStatus, http.NoBody) //nolint:gosec // G704: the deployment's own custodian, from INNSEGL_CA_CUSTODIAN_URL
	if err != nil {
		writeCoreError(w, http.StatusInternalServerError, "innsegl core: ca custody: "+err.Error())
		return
	}
	resp, err := client.Do(req) //nolint:gosec // G704: the deployment's own custodian
	if err != nil {
		log.warn("ca custody: the custodian is not answering", "err", err)
		writeCoreJSON(w, http.StatusOK, caCustodyStatus{Enabled: true, Sealed: true,
			Error: "the custodian is not answering"})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	var st cacustody.Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st); err != nil {
		writeCoreJSON(w, http.StatusOK, caCustodyStatus{Enabled: true, Sealed: true,
			Error: "the custodian answered something unreadable"})
		return
	}
	writeCoreJSON(w, http.StatusOK, caCustodyStatus{Enabled: true, Initialized: st.Initialized,
		Sealed: st.Sealed, TokenPresent: st.TokenPresent, Error: st.Error})
}

// proxyCustody forwards one request and hands back the custodian's status and
// body. The body is ciphertext, an empty success, or a refusal that the
// custodian has already made sure repeats nothing that was sent.
func proxyCustody(ctx context.Context, w http.ResponseWriter, client *http.Client, method, url string, body []byte, log *serveLog) {
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader) //nolint:gosec // G704: the deployment's own custodian, from INNSEGL_CA_CUSTODIAN_URL
	if err != nil {
		writeCoreError(w, http.StatusInternalServerError, "innsegl core: ca custody: "+err.Error())
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req) //nolint:gosec // G704: the deployment's own custodian
	if err != nil {
		log.warn("ca custody: the custodian is not answering", "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: ca custody: the custodian is not answering; retry")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, cerr := io.Copy(w, io.LimitReader(resp.Body, 1<<20))
	discardCoreWrite(cerr)
}

// admitOperatorMachine answers whether the request comes from an active
// workstation of the operator organisation, enrolled by its owner or an admin,
// within its rate. Refusing, it has already answered the request.
func admitOperatorMachine(w http.ResponseWriter, r *http.Request, store trustBackupStore, limit *backupLimiter,
	log *serveLog, what, forbidden string) bool {
	id, ok := gateway.InstallationFromContext(r.Context())
	if !ok {
		gateway.WriteClientRefusal(w)
		return false
	}
	inst, err := store.GetInstallation(r.Context(), id)
	if errors.Is(err, accounts.ErrNotFound) {
		gateway.WriteClientRefusal(w)
		return false
	}
	if err != nil {
		log.warn(what+": reading the installation", "installation_id", id, "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: "+what+" is unavailable; retry")
		return false
	}
	allowed, err := mayFetchTrustBackup(r.Context(), store, inst)
	if err != nil {
		log.warn(what+": reading memberships", "installation_id", id, "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: "+what+" is unavailable; retry")
		return false
	}
	if !allowed {
		log.warn(what+": refused", "installation_id", id)
		writeCoreError(w, http.StatusForbidden, forbidden)
		return false
	}
	if wait, ok := limit.allow(id); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeCoreError(w, http.StatusTooManyRequests, "innsegl core: "+what+": too many requests; retry later")
		return false
	}
	return true
}

// The custody routes' rate: the client service asks for the status once a
// minute, so a token comes back every custodyRefill and a burst covers a
// terminal's status-then-unlock on top of it.
const (
	custodyBurst  = 10
	custodyRefill = 20 * time.Second
)

func newCustodyLimiter(now func() time.Time) *backupLimiter {
	l := newBackupLimiter(now)
	l.burst, l.refill = custodyBurst, custodyRefill
	return l
}
