// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"os"
	"path/filepath"

	"innsegl.dev/innsegl/internal/clientjournal"
	"innsegl.dev/innsegl/internal/gateway"
)

// envClientJournalDir is where the hosted core keeps the client-journal
// entries it imported (ADR-0068). Unset, it is a directory beside the body
// store ($INNSEGL_MCP_LOG_DIR): the signed entries are recorded bodies.
const envClientJournalDir = "INNSEGL_CLIENT_JOURNAL_DIR"

// clientJournalSubdir is the default directory's name under the body store.
// The underscore keeps it apart from every run directory there: a run id
// never contains one (doc 02 §5).
const clientJournalSubdir = "_client-journal"

// clientJournalDir answers where imported entries are kept, or "" when
// neither variable is set.
func clientJournalDir(getenv func(string) string) string {
	if dir := getenv(envClientJournalDir); dir != "" {
		return dir
	}
	if body := getenv(envObserveBodyDir); body != "" {
		return filepath.Join(body, clientJournalSubdir)
	}
	return ""
}

// mountCoreJournal serves the client-journal import behind the
// client-certificate guard, in hosted mode only. Each entry is replayed
// through proxy: the same guards and recorders a live request passes.
// Without a directory to keep entries in, the route answers 503, so a
// client keeps its entries and retries.
func mountCoreJournal(mux *http.ServeMux, h *hostedCore, proxy *gateway.Proxy, log *serveLog) error {
	if h == nil {
		return nil
	}
	dir := clientJournalDir(os.Getenv)
	if dir == "" {
		log.warn("the client-journal import is not configured: set $" + envClientJournalDir + " or $" +
			envObserveBodyDir + "; clients keep their journals until it is")
		mux.HandleFunc(clientjournal.ImportPath, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "300")
			http.Error(w, `{"error":"innsegl core: the client-journal import is not configured"}`, http.StatusServiceUnavailable)
		})
		return nil
	}
	im, err := gateway.NewJournalImporter(gateway.JournalImporterConfig{
		Store: gateway.NewFileJournalStore(dir), Replayer: proxy,
		OnResult: func(installation string, r clientjournal.ImportResult) {
			switch r.Status {
			case clientjournal.ImportRejected:
				log.warn("finding: a client-journal entry was rejected", "installation_id", installation,
					"seq", r.Seq, "hash", r.Hash, "reason", r.Reason)
			case clientjournal.ImportStored:
				log.warn("finding: a client-journal entry was stored but not recorded", "installation_id", installation,
					"seq", r.Seq, "hash", r.Hash, "reason", r.Reason)
			case clientjournal.ImportRecorded:
				log.info("imported a client-journal entry", "installation_id", installation, "seq", r.Seq, "hash", r.Hash)
			}
		},
	})
	if err != nil {
		return err
	}
	mux.Handle(clientjournal.ImportPath, gateway.JournalImportHandler(im))
	return nil
}
