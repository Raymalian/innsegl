// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
)

// RM-311 (#493): the core writes the dashboard's certificate at boot and
// again when it is due, with no reload of the web server.
func TestRM311TheCoreRenewsTheDashboardCertificateWhenDue(t *testing.T) {
	// A clock a day behind makes the first certificate already due.
	past := time.Now().Add(-48 * time.Hour)
	ca, err := gateway.LoadOrCreateCA(gateway.CAConfig{
		KeyDir: filepath.Join(t.TempDir(), "key"), Now: func() time.Time { return past },
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d, err := openDashboardCert(ca, dir, newServeLog(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("openDashboardCert: %v", err)
	}
	path := filepath.Join(dir, gateway.DashboardTLSFileName)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no certificate at boot: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { d.run(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if now, err := os.ReadFile(path); err == nil && !bytes.Equal(now, first) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a certificate past its renewal point was not written again")
}

func TestRM311AnUnwritableDashboardDirIsRefusedAtBoot(t *testing.T) {
	ca, err := gateway.LoadOrCreateCA(gateway.CAConfig{KeyDir: filepath.Join(t.TempDir(), "key")})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDashboardCert(ca, file, newServeLog(&bytes.Buffer{})); err == nil {
		t.Fatal("a directory that is a file was accepted")
	}
}
