// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// ADR-0074: the core serves its encrypted trust-key backup to the operator's
// enrolled machine, which keeps copies off the host. The bundle is
// ciphertext, and the core holds no key that opens it.
const (
	coreTrustBackupPath       = trustbackup.CorePath
	coreTrustBackupLatestPath = trustbackup.CoreLatestPath
	headerTrustBackupName     = trustbackup.HeaderName
	headerTrustBackupSHA256   = trustbackup.HeaderSHA256

	// envTrustBackupDir is where the core reads the bundles from, read-only.
	// Unset, the core keeps none and says so.
	envTrustBackupDir = "INNSEGL_TRUST_BACKUP_DIR"

	// A machine may make backupBurst requests at once and one more every
	// backupRefill. The client asks once an hour.
	backupBurst  = 6
	backupRefill = 10 * time.Minute
)

type trustBackupListing = trustbackup.Listing

// trustBackupStore reads what decides whether a machine may fetch.
type trustBackupStore interface {
	GetInstallation(ctx context.Context, id string) (accounts.Installation, error)
	Memberships(ctx context.Context, userID string) ([]api.OrgMembership, error)
}

const trustBackupForbidden = "innsegl core: trust backup: only an active workstation of the operator's " +
	"organisation, enrolled by its owner or an admin, may fetch the trust-key backup"

// trustBackupHandler serves both routes behind the client guard. It admits an
// active workstation whose installation belongs to the operator organisation
// and whose enroller is still that organisation's owner or an admin. Every
// other enrolled machine is refused: the bundle is encrypted, but who holds
// copies of the keys is still the operator's decision.
func trustBackupHandler(dir string, store trustBackupStore, limit *backupLimiter, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != coreTrustBackupPath && r.URL.Path != coreTrustBackupLatestPath {
			writeCoreError(w, http.StatusNotFound, "innsegl core: trust backup: no such route")
			return
		}
		if r.Method != http.MethodGet {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: trust backup: only GET is accepted")
			return
		}
		if !admitOperatorMachine(w, r, store, limit, log, "trust backup", trustBackupForbidden) {
			return
		}
		if dir == "" {
			writeCoreError(w, http.StatusNotFound, "innsegl core: this core keeps no trust-key backup ("+
				envTrustBackupDir+" is unset)")
			return
		}
		bundles := &trustbackup.Store{Dir: dir}
		if r.URL.Path == coreTrustBackupPath {
			serveTrustBackupListing(w, bundles, log)
			return
		}
		serveLatestTrustBackup(w, bundles, log)
	}
}

func mayFetchTrustBackup(ctx context.Context, store trustBackupStore, inst accounts.Installation) (bool, error) {
	if inst.Status != accounts.StatusActive || inst.Kind != accounts.KindWorkstation {
		return false, nil
	}
	ms, err := store.Memberships(ctx, inst.CreatedBy)
	if err != nil {
		return false, err
	}
	for _, m := range ms {
		if m.AccountID == inst.AccountID && m.Operator &&
			(m.Role == accounts.RoleOwner || m.Role == accounts.RoleAdmin) {
			return true, nil
		}
	}
	return false, nil
}

func serveTrustBackupListing(w http.ResponseWriter, store *trustbackup.Store, log *serveLog) {
	list, err := store.List()
	if err != nil {
		log.warn("trust backup: listing", "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: trust backup is unavailable; retry")
		return
	}
	out := trustBackupListing{Bundles: list}
	if out.Bundles == nil {
		out.Bundles = []trustbackup.Entry{}
	}
	if st, serr := store.ReadStatus(); serr == nil {
		out.Status = &st
	}
	writeCoreJSON(w, http.StatusOK, out)
}

func serveLatestTrustBackup(w http.ResponseWriter, store *trustbackup.Store, log *serveLog) {
	e, err := store.Latest()
	if errors.Is(err, trustbackup.ErrNoBundle) {
		msg := "innsegl core: trust backup: no bundle has been written yet"
		if st, serr := store.ReadStatus(); serr == nil && st.Error != "" {
			msg += ": " + st.Error
		}
		writeCoreError(w, http.StatusNotFound, msg)
		return
	}
	if err != nil {
		log.warn("trust backup: finding the newest bundle", "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: trust backup is unavailable; retry")
		return
	}
	f, opened, err := store.Open(e.Name)
	if err != nil {
		log.warn("trust backup: opening the newest bundle", "name", e.Name, "err", err)
		writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: trust backup is unavailable; retry")
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(opened.Size, 10))
	w.Header().Set(headerTrustBackupName, opened.Name)
	w.Header().Set(headerTrustBackupSHA256, opened.SHA256)
	w.WriteHeader(http.StatusOK)
	// A failed copy means the caller has gone; its checksum check refuses
	// whatever part it got.
	_, cerr := io.Copy(w, f)
	discardCoreWrite(cerr)
}

// backupLimiter is a token bucket per installation: backupBurst tokens, one
// back every backupRefill.
type backupLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	burst   float64
	refill  time.Duration
	buckets map[string]*backupBucket
}

type backupBucket struct {
	tokens float64
	at     time.Time
}

func newBackupLimiter(now func() time.Time) *backupLimiter {
	if now == nil {
		now = time.Now
	}
	return &backupLimiter{now: now, burst: backupBurst, refill: backupRefill, buckets: map[string]*backupBucket{}}
}

// allow spends a token for id, or answers how long until one is back.
func (l *backupLimiter) allow(id string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[id]
	if b == nil {
		b = &backupBucket{tokens: l.burst, at: now}
		l.buckets[id] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+float64(now.Sub(b.at))/float64(l.refill))
	b.at = now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) * float64(l.refill)), false
	}
	b.tokens--
	return 0, true
}
