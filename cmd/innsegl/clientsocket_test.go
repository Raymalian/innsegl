// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"os"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// shortTempDir is a fresh folder short enough for a unix socket inside a
// home under it: t.TempDir() on macOS is longer than a socket path may be
// once a test's name is in it (#600).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "isg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveClientSocket serves h on the CLI socket at path, as `innsegl client
// serve` does, until the test ends.
func serveClientSocket(t *testing.T, path string, h http.Handler) {
	t.Helper()
	ln, err := client.ListenSocket(t.Context(), path, t.Logf)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	served := make(chan error, 1) // Serve ends with ErrServerClosed at cleanup
	go func() { served <- hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
}
