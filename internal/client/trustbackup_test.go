// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// coreBackups serves a store the way the core does, counting the bundle
// downloads. tamper, when set, changes what the latest route sends.
type coreBackups struct {
	store     *trustbackup.Store
	downloads atomic.Int32
	tamper    atomic.Bool
	missing   atomic.Bool
}

func write(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Error(err)
	}
}

func (c *coreBackups) mount(t *testing.T, core *clienttest.Core) {
	core.Mux.HandleFunc(trustbackup.CorePath, func(w http.ResponseWriter, _ *http.Request) {
		if c.missing.Load() {
			w.WriteHeader(http.StatusNotFound)
			write(t, w, `{"error":"innsegl core: this core keeps no trust-key backup"}`)
			return
		}
		list, err := c.store.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if list == nil {
			list = []trustbackup.Entry{}
		}
		if err := json.NewEncoder(w).Encode(trustbackup.Listing{Bundles: list}); err != nil {
			t.Error(err)
		}
	})
	core.Mux.HandleFunc(trustbackup.CoreLatestPath, func(w http.ResponseWriter, _ *http.Request) {
		c.downloads.Add(1)
		e, err := c.store.Latest()
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			write(t, w, `{"error":"innsegl core: trust backup: no bundle has been written yet"}`)
			return
		}
		f, _, err := c.store.Open(e.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set(trustbackup.HeaderName, e.Name)
		w.Header().Set(trustbackup.HeaderSHA256, e.SHA256)
		if c.tamper.Load() {
			write(t, w, "not the bundle")
			return
		}
		if _, err := io.Copy(w, f); err != nil {
			t.Error(err)
		}
	})
}

func newCoreBackups(t *testing.T) *coreBackups {
	t.Helper()
	start := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	n := 0
	return &coreBackups{store: &trustbackup.Store{Dir: t.TempDir(), Keep: 10, Now: func() time.Time {
		n++
		return start.Add(time.Duration(n) * time.Hour)
	}}}
}

func (c *coreBackups) add(t *testing.T) trustbackup.Entry {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e, _, err := c.store.Create([]age.Recipient{id.Recipient()},
		[]trustbackup.Source{trustbackup.ValueSource("a", "f", []byte("key"))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestTheClientKeepsTheCoresNewestTrustBackup(t *testing.T) {
	core, paths := enrolled(t)
	cb := newCoreBackups(t)
	cb.mount(t, core)
	e := cb.add(t)
	local := &trustbackup.Store{Dir: paths.TrustBackups, Keep: 2}

	got, fetched, err := FetchTrustBackup(t.Context(), paths, local)
	if err != nil || !fetched || got.Name != e.Name || got.SHA256 != e.SHA256 {
		t.Fatalf("FetchTrustBackup = %+v, %v, %v", got, fetched, err)
	}
	fi, err := os.Stat(filepath.Join(paths.TrustBackups, e.Name))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept bundle: %v, %v", fi, err)
	}
	if di := must(os.Stat(paths.TrustBackups))(t); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	// Asking again downloads nothing: the listing names what is already kept.
	if _, fetched, err := FetchTrustBackup(t.Context(), paths, local); err != nil || fetched {
		t.Fatalf("second fetch: fetched=%v, %v", fetched, err)
	}
	if n := cb.downloads.Load(); n != 1 {
		t.Fatalf("%d downloads, want 1", n)
	}
	// Newer bundles arrive, and only the newest two are kept.
	cb.add(t)
	last := cb.add(t)
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err != nil {
		t.Fatal(err)
	}
	cb.add(t)
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err != nil {
		t.Fatal(err)
	}
	list := must(local.List())(t)
	if len(list) != 2 || list[1].Name != last.Name {
		t.Fatalf("local = %+v", list)
	}
}

func TestTheClientRefusesABundleThatFailsItsChecksum(t *testing.T) {
	core, paths := enrolled(t)
	cb := newCoreBackups(t)
	cb.mount(t, core)
	cb.add(t)
	cb.tamper.Store(true)
	local := &trustbackup.Store{Dir: paths.TrustBackups, Keep: 2}
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err == nil {
		t.Fatal("a tampered bundle was kept")
	}
	if list := must(local.List())(t); len(list) != 0 {
		t.Fatalf("local = %+v", list)
	}
}

func TestTheClientSaysWhatTheCoreSaidWhenThereIsNoBackup(t *testing.T) {
	core, paths := enrolled(t)
	cb := newCoreBackups(t)
	cb.mount(t, core)
	local := &trustbackup.Store{Dir: paths.TrustBackups, Keep: 2}
	// The core keeps none at all.
	cb.missing.Store(true)
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err == nil ||
		!strings.Contains(err.Error(), "keeps no trust-key backup") {
		t.Fatalf("no backup dir: %v", err)
	}
	// The core keeps them, and has none yet.
	cb.missing.Store(false)
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err == nil ||
		!strings.Contains(err.Error(), "no bundle") {
		t.Fatalf("no bundle yet: %v", err)
	}
	// A core that does not answer.
	core.Stop()
	if _, _, err := FetchTrustBackup(t.Context(), paths, local); err == nil {
		t.Fatal("a stopped core answered")
	}
}

func TestTheClientServiceFetchesOnStartAndOnItsSchedule(t *testing.T) {
	core, paths := enrolled(t)
	cb := newCoreBackups(t)
	cb.mount(t, core)
	cb.add(t)
	srv, _, logs := startClient(t, paths)
	local := &trustbackup.Store{Dir: paths.TrustBackups, Keep: 3}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		srv.RunTrustBackupFetch(ctx, local, 20*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if list := must(local.List())(t); len(list) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing fetched on start; log: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cb.add(t)
	for {
		if list := must(local.List())(t); len(list) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing fetched on schedule; log: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cb.tamper.Store(true)
	cb.add(t)
	for !strings.Contains(logs.String(), "trust backup") {
		if time.Now().After(deadline) {
			t.Fatalf("a failed fetch was not logged; log: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// must answers v, and ends the test on err: must(f())(t).
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
