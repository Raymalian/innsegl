// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/dockertest"
	"innsegl.dev/innsegl/internal/signprobe"
)

// ---------------------------------------------------------------------------
// OPS-192 (PROPOSED for doc 07's TC-OPS) — the 10-11 incident, reproduced
// without touching any deployment (#588). A real store, a custodian, the
// CA's signing gateway, and the signing probe on a short interval:
//
//  1. custodians recreated faster than any scheduled renewal keep the token
//     alive (they renew at start);
//  2. on the old behaviour (custodians that never live to their first
//     renewal) the token dies, and the probe reports it within two intervals;
//  3. `innsegl doctor` repairs it with one unlock through a test age
//     identity, with no container restarted and no command run;
//  4. on the new behaviour a revoked token is the same story.
// ---------------------------------------------------------------------------

// incidentStoreImage is the store the key-custody overlay runs, pinned as
// the custody package's own tests pin it.
const incidentStoreImage = "openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"

const incidentStoreConfig = `ui = false
storage "raft" {
  path    = "/openbao/file"
  node_id = "innsegl-ca-store"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
`

// incidentPeriod is the role period: a token not renewed dies within it.
const incidentPeriod = 6 * time.Second

// incidentInterval is the probe's interval.
const incidentInterval = time.Second

// startIncidentStore starts a sealed, uninitialised store in its own
// container: a skip with no Docker, a FAILURE when Docker is there and the
// store is not (#101). It answers the store's address and container name.
func startIncidentStore(t *testing.T) (addr, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("skipping: docker is not on PATH (%v); OPS-192 needs a real store", err)
	}
	if _, err := dockertest.Docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("skipping: no reachable docker daemon (%v); OPS-192 needs a real store", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "store.hcl"), []byte(incidentStoreConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("innsegl-doctortest-%d", time.Now().UnixNano())
	if _, err := dockertest.Docker(ctx, "run", "--detach", "--name", name, "--label", "dev.innsegl.test=1",
		"--publish", "127.0.0.1:"+port+":8200", "--volume", dir+":/openbao/config:ro",
		incidentStoreImage, "server", "-config=/openbao/config/store.hcl"); err != nil {
		t.Fatalf("the store did not start, and Docker is present and working: %v\n\n"+
			"This is a FAILURE and not a skip (#101).", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := dockertest.Docker(ctx, "rm", "--force", "--volumes", name); err != nil {
			t.Logf("removing the test store: %v", err)
		}
	})
	addr = "http://127.0.0.1:" + port
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr + "/v1/sys/seal-status") //nolint:noctx // a probe loop
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return addr, name
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the store at %s never answered", addr)
	return "", ""
}

// gatewayProbe is the signing probe's question asked of the CA's own
// gateway: sign one digest with the CA key, as Fulcio does for every
// certificate, with the placeholder Fulcio sends.
type gatewayProbe struct {
	url string
	key string
}

func (p gatewayProbe) Probe(ctx context.Context) signprobe.Result {
	body := fmt.Sprintf(`{"input":%q}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url+"/v1/transit/sign/"+p.key+"/sha2-256",
		strings.NewReader(body))
	if err != nil {
		return signprobe.Result{Reason: err.Error()}
	}
	req.Header.Set("X-Vault-Token", cacustody.FulcioPlaceholderToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return signprobe.Result{Reason: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return signprobe.Result{Reason: err.Error()}
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "vault:v") {
		return signprobe.Result{Reason: fmt.Sprintf("the CA answered HTTP %d", resp.StatusCode)}
	}
	return signprobe.Result{OK: true}
}

func containerStartedAt(t *testing.T, name string) string {
	t.Helper()
	out, err := dockertest.Docker(t.Context(), "inspect", "-f", "{{.State.StartedAt}}", name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// waitFailing answers when the monitor first reports a failure, waiting at
// most limit.
func waitFailing(t *testing.T, m *signprobe.Monitor, limit time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if !m.State().OK {
			return time.Now()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the probe still passed %v after the token died: %+v", limit, m.State())
	return time.Time{}
}

// waitTokenDead answers when the store stops accepting tok.
func waitTokenDead(t *testing.T, s *cacustody.Store, tok string, limit time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		ttl, err := s.TTL(t.Context(), tok)
		if errors.Is(err, cacustody.ErrRefused) || (err == nil && ttl <= 0) {
			return time.Now()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the CA's token was still alive %v later", limit)
	return time.Time{}
}

func TestOPS192TheIncidentIsDetectedAndDoctorRepairsItWithNoRestart(t *testing.T) {
	addr, storeName := startIncidentStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "identity.txt")
	if err = os.WriteFile(identity, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logMu sync.Mutex
	logBuf := &bytes.Buffer{}
	logw := writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(p)
	})
	tokenPath := filepath.Join(t.TempDir(), ".vault-token")
	dir := t.TempDir()
	custodian := func() *cacustody.Custodian {
		return &cacustody.Custodian{Store: &cacustody.Store{Addr: addr, Period: incidentPeriod}, Dir: dir,
			TokenPath: tokenPath, Key: "innsegl-ca", Recipients: []age.Recipient{id.Recipient()}, Log: logw}
	}
	// The serving custodian: the core's custody routes and the CA's gateway.
	serving := custodian()
	if err = serving.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	gw := httptest.NewServer(serving.SigningGateway())
	t.Cleanup(gw.Close)
	routes := httptest.NewServer(serving.Handler())
	t.Cleanup(routes.Close)

	mon := signprobe.NewMonitor(gatewayProbe{url: gw.URL, key: "innsegl-ca"}, incidentInterval, nil)
	go mon.Run(ctx)

	f := newConnectFixture(t)
	f.connectServed(t, nil)
	// The core's real limit on custody calls (six per machine per ten
	// minutes): the two repairs below come back to back, as an operator's
	// would, and must both fit under it.
	h := caCustodyHandler(routes.URL, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	f.core.Mux.Handle(coreCACustodyPath, withInstallation("inst-1", h))
	f.core.Mux.Handle(coreCACustodyPath+"/", withInstallation("inst-1", h))
	f.core.Mux.HandleFunc(coreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		st := mon.State()
		writeCoreJSON(w, http.StatusOK, coreStatus{Version: "test-core", Components: []coreComponent{
			{Name: "spire", Up: true}, {Name: "ledger", Up: true}, {Name: "sigstore", Up: true},
			{Name: signprobe.ReportName, Up: st.OK, Detail: st.Detail()}},
			Installation: coreInstallation{ID: "inst-1", Repos: []string{"*"}}})
	})
	var calls [][]string
	runDoctorOnce := func() (int, string) {
		var out bytes.Buffer
		code := runDoctor(ctx, []string{"--identity", identity, "--wait", "20s"}, &out, &out, doctorDeps{
			home: f.home, goos: "darwin", uid: 501, cwd: t.TempDir(),
			run: func(_ context.Context, name string, args ...string) error {
				calls = append(calls, append([]string{name}, args...))
				return nil
			},
			poll: 100 * time.Millisecond, serviceWait: 5 * time.Second,
		})
		return code, out.String()
	}
	startedAt := containerStartedAt(t, storeName)

	// 1. New behaviour: custodians recreated every period/3 for two periods,
	// none living to a scheduled renewal, keep the token alive.
	tok, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(2 * incidentPeriod); time.Now().Before(end); {
		rctx, rcancel := context.WithCancel(ctx)
		go custodian().RunRenewer(rctx, time.Hour)
		time.Sleep(incidentPeriod / 3)
		rcancel()
	}
	if ttl, terr := serving.Store.TTL(ctx, string(tok)); terr != nil || ttl <= 0 {
		t.Fatalf("custodians that renew at start lost the token: ttl %v, %v", ttl, terr)
	}
	time.Sleep(incidentInterval + 200*time.Millisecond)
	if st := mon.State(); !st.OK {
		t.Fatalf("with the token alive the probe fails: %+v", st)
	}

	// 2. Old behaviour: custodians whose first renewal is one RenewEvery after
	// they start, recreated before it: nothing renews, and the token dies.
	for end := time.Now().Add(incidentPeriod + time.Second); time.Now().Before(end); {
		rctx, rcancel := context.WithCancel(ctx)
		go oldRenewer(rctx, custodian(), time.Hour)
		time.Sleep(incidentPeriod / 3)
		rcancel()
	}
	died := waitTokenDead(t, serving.Store, string(tok), incidentPeriod)
	detected := waitFailing(t, mon, 2*incidentInterval+time.Second)
	if lag := detected.Sub(died); lag > 2*incidentInterval {
		t.Fatalf("the probe reported the dead token %v after it died; want within two intervals (%v)",
			lag, 2*incidentInterval)
	}
	if st := mon.State(); st.OK || st.Reason == "" {
		t.Fatalf("the failing probe gives no reason: %+v", st)
	}

	// 3. Doctor repairs it: one unlock, nothing restarted.
	code, out := runDoctorOnce()
	if code != exitOK || !strings.Contains(out, "signing: OK (probe passed ") {
		t.Fatalf("doctor on the dead token: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "ca custody: CANNOT SIGN") {
		t.Errorf("doctor did not name the dead token:\n%s", out)
	}

	// 4. New behaviour, the token revoked: detected, repaired again.
	tok, err = os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = serving.Store.RevokeSelf(ctx, string(tok)); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	detected = waitFailing(t, mon, 2*incidentInterval+time.Second)
	if lag := detected.Sub(revoked); lag > 2*incidentInterval {
		t.Fatalf("the probe reported the revoked token %v later; want within two intervals", lag)
	}
	code, out = runDoctorOnce()
	if code != exitOK {
		t.Fatalf("doctor on the revoked token: exit %d\n%s", code, out)
	}

	if len(calls) != 0 {
		t.Fatalf("doctor ran %q; the repair is an unlock, not a command", calls)
	}
	if now := containerStartedAt(t, storeName); now != startedAt {
		t.Fatalf("the store's container was restarted (%s, then %s)", startedAt, now)
	}
	if st := serving.Status(ctx); !st.CanSign {
		t.Fatalf("after the repair the CA cannot sign: %+v", st)
	}
}

// oldRenewer is RunRenewer before #582: it waits one period before its
// first renewal, so a custodian recreated sooner never renews.
func oldRenewer(ctx context.Context, c *cacustody.Custodian, every time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		if err := c.Renew(ctx); err != nil {
			continue
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
