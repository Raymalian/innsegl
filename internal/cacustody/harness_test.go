// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// storeImage is the store the key-custody overlay runs. Pinned by the
// multi-architecture index digest, as the overlay pins it.
const storeImage = "openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"

// storeConfig is the overlay's own store config: file storage, no dev mode,
// so the store starts sealed and uninitialised exactly as it does there.
const storeConfig = `ui = false
storage "file" {
  path = "/openbao/data"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
`

// testStore is one real store in its own container.
type testStore struct {
	name string
	addr string
}

func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// startStore starts a sealed, uninitialised store, or ends the test the
// honest way: a skip when there is no Docker, a FAILURE when Docker is
// there and the store is not (#101).
func startStore(t *testing.T) *testStore {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("skipping: docker is not on PATH (%v); these tests need a real store", err)
	}
	if _, err := docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("skipping: no reachable docker daemon (%v); these tests need a real store", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "store.hcl"), []byte(storeConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("innsegl-cacustody-test-%d", time.Now().UnixNano())
	if _, err := docker(ctx, "run", "--detach", "--name", name, "--label", "dev.innsegl.test=1",
		"--publish", "127.0.0.1:"+port+":8200",
		"--volume", dir+":/openbao/config:ro",
		storeImage, "server", "-config=/openbao/config/store.hcl"); err != nil {
		t.Fatalf("the store did not start, and Docker is present and working: %v\n\n"+
			"This is a FAILURE and not a skip (#101).", err)
	}
	s := &testStore{name: name, addr: "http://127.0.0.1:" + port}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := docker(ctx, "rm", "--force", "--volumes", name); err != nil {
			t.Logf("removing the test store: %v", err)
		}
	})
	s.waitAnswering(t)
	return s
}

func (s *testStore) waitAnswering(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.addr + "/v1/sys/seal-status") //nolint:noctx // a probe loop
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	logs, err := docker(context.Background(), "logs", s.name)
	if err != nil {
		logs = err.Error()
	}
	t.Fatalf("the store at %s never answered:\n%s", s.addr, logs)
}

// restart restarts the store's container. A store reseals on every start;
// this is a VM reboot or a stack restart, as far as the store can tell.
func (s *testStore) restart(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := docker(ctx, "restart", s.name); err != nil {
		t.Fatal(err)
	}
	s.waitAnswering(t)
}

func freePort() (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}
