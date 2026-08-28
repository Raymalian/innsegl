// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A real Rekor, never a mock.
//
// SEG-003 is an integration case (doc 07, layer I) and doc 01 §2 is explicit:
// "a mocked Fulcio proves nothing about I5". The same holds for the
// transparency log. An anchor is only worth something because a third party
// operates the log and can be asked, independently, whether the entry is
// there — a fake that answers "yes" tests nothing but our own opinion.
//
// So this file stands a real Rekor up in containers, the way
// internal/ledger/pgharness_test.go stands Postgres up, and skips loudly when
// Docker is absent rather than passing quietly.
//
// # Why five containers
//
// Rekor is a front end over a Trillian log; Trillian is a log over MySQL, and
// its sequencer is a separate process without which nothing is ever
// integrated and no inclusion proof exists. Rekor's search index needs Redis.
// Doc 05 §1 anticipates exactly this: "Rekor's storage dependencies run as
// sidecars per upstream's own compose reference; pin versions." The shape and
// the flags below are upstream Rekor's own docker-compose, so RM-030 (#38) can
// lift this into deploy/compose/ rather than rediscovering it.
//
// # Why no TestMain
//
// A package gets one TestMain, and this package is shared with the WORM writer
// (RM-011), which has container needs of its own. A TestMain here would be a
// land grab. Instead the one test that needs the log starts the stack and tears
// it down through t.Cleanup, and its subtests share it.

const (
	// Pinned versions. Doc 05 §1: "pin versions". Rekor's REST shapes, the
	// hashedrekord type and the RFC 6962 proof format are what these tests
	// depend on; a floating tag would let any of them move underneath us.
	defaultRekorImage = "ghcr.io/sigstore/rekor/rekor-server:v1.3.10"
	// The Trillian pair ships from the Sigstore scaffolding repository, which
	// publishes multi-architecture images; the trillian-opensource-ci images
	// upstream's compose names are amd64-only.
	defaultTrillianLogServerImage = "ghcr.io/sigstore/scaffolding/trillian_log_server:v1.7.1"
	defaultTrillianLogSignerImage = "ghcr.io/sigstore/scaffolding/trillian_log_signer:v1.7.1"
	// db_server is MySQL with Trillian's storage schema already applied. It
	// is the image upstream's compose uses, and taking it whole avoids
	// vendoring a copy of Trillian's schema that could drift from the server
	// that reads it.
	defaultTrillianDBImage = "gcr.io/trillian-opensource-ci/db_server:v1.4.0"
	defaultRekorRedisImage = "redis:7-alpine"

	// Credentials for a throwaway database inside a throwaway container.
	trillianDBName     = "test"
	trillianDBUser     = "test"
	trillianDBPassword = "zaphod"

	// rekorOrigin is the checkpoint origin the log signs under. Fixed so the
	// checkpoint assertions have something stable to match.
	rekorOrigin = "rekor.innsegl.test"
)

var (
	errRekorDockerAbsent = errors.New("docker is not available")
	rekorStackSeq        atomic.Int64
)

func rekorEnvImage(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// rekorDocker runs one docker command and returns its trimmed stdout.
//
// Deliberately not shared with the WORM harness in this package: a test
// harness that another agent's file has to keep compiling is a coupling
// neither of us asked for, and this one has to stay liftable into
// deploy/compose on its own.
func rekorDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// rekorDockerUsable reports whether a docker daemon is reachable.
func rekorDockerUsable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", errRekorDockerAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: %w", errRekorDockerAbsent, err)
	}
	if _, err := rekorDocker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable daemon: %w", errRekorDockerAbsent, err)
	}
	return nil
}

// rekorFreeHostPort reserves an ephemeral port and hands it back.
func rekorFreeHostPort(ctx context.Context) (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if cerr := l.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return port, err
}

// rekorStack is one containerised Rekor and everything under it.
type rekorStack struct {
	network    string
	containers []string
	port       string
}

// BaseURL is the Rekor API root on the host.
func (s *rekorStack) BaseURL() string { return "http://127.0.0.1:" + s.port }

func (s *rekorStack) run(ctx context.Context, name string, args ...string) error {
	full := append([]string{"run", "--detach", "--name", name, "--network", s.network}, args...)
	id, err := rekorDocker(ctx, full...)
	if err != nil {
		return err
	}
	s.containers = append(s.containers, id)
	return nil
}

// stop removes every container and the network. Best effort: a leaked
// container is a nuisance, a failed teardown that masks a test failure is
// worse.
func (s *rekorStack) stop() []error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var errs []error
	for i := len(s.containers) - 1; i >= 0; i-- {
		if _, err := rekorDocker(ctx, "rm", "--force", "--volumes", s.containers[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if s.network != "" {
		if _, err := rekorDocker(ctx, "network", "rm", s.network); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// startRekorStack brings up MySQL, the Trillian log server and sequencer,
// Redis and Rekor, and waits until the log answers.
func startRekorStack(ctx context.Context) (*rekorStack, error) {
	port, err := rekorFreeHostPort(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a host port: %w", err)
	}

	suffix := fmt.Sprintf("%d-%d", os.Getpid(), rekorStackSeq.Add(1))
	s := &rekorStack{network: "innsegl-rekor-" + suffix, port: port}

	if _, err := rekorDocker(ctx, "network", "create", s.network); err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}

	db := "innsegl-rekor-db-" + suffix
	if err := s.run(ctx, db,
		"--env", "MYSQL_ROOT_PASSWORD="+trillianDBPassword,
		"--env", "MYSQL_DATABASE="+trillianDBName,
		"--env", "MYSQL_USER="+trillianDBUser,
		"--env", "MYSQL_PASSWORD="+trillianDBPassword,
		rekorEnvImage("INNSEGL_TEST_TRILLIAN_DB_IMAGE", defaultTrillianDBImage),
	); err != nil {
		return s, fmt.Errorf("start trillian database: %w", err)
	}
	if err := s.waitForSchema(ctx, db, 3*time.Minute); err != nil {
		return s, err
	}

	redis := "innsegl-rekor-redis-" + suffix
	if err := s.run(ctx, redis,
		rekorEnvImage("INNSEGL_TEST_REKOR_REDIS_IMAGE", defaultRekorRedisImage),
		"--bind", "0.0.0.0", "--appendonly", "no",
	); err != nil {
		return s, fmt.Errorf("start redis: %w", err)
	}

	mysqlURI := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s",
		trillianDBUser, trillianDBPassword, db, trillianDBName)

	logServer := "innsegl-rekor-tlog-" + suffix
	if err := s.run(ctx, logServer,
		// Upstream's compose sets `restart: always` on all three Go services,
		// and for a reason that bites here: whichever of them wins the race to
		// a dependency that is still opening its port simply exits, and a
		// restart is how it recovers rather than how the harness hangs.
		"--restart", "on-failure:30",
		rekorEnvImage("INNSEGL_TEST_TRILLIAN_LOG_SERVER_IMAGE", defaultTrillianLogServerImage),
		"--storage_system=mysql", "--mysql_uri="+mysqlURI,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
	); err != nil {
		return s, fmt.Errorf("start trillian log server: %w", err)
	}

	// Without the sequencer, leaves are queued and never integrated: the log
	// would accept an anchor and never be able to prove it. SEG-003 would
	// then hang rather than fail, which is the worst of the three outcomes.
	signer := "innsegl-rekor-tsign-" + suffix
	if err := s.run(ctx, signer,
		"--restart", "on-failure:30",
		rekorEnvImage("INNSEGL_TEST_TRILLIAN_LOG_SIGNER_IMAGE", defaultTrillianLogSignerImage),
		"--storage_system=mysql", "--mysql_uri="+mysqlURI,
		"--rpc_endpoint=0.0.0.0:8090", "--http_endpoint=0.0.0.0:8091",
		"--force_master",
	); err != nil {
		return s, fmt.Errorf("start trillian log signer: %w", err)
	}

	rekor := "innsegl-rekor-" + suffix
	if err := s.run(ctx, rekor,
		"--restart", "on-failure:30",
		"--publish", "127.0.0.1:"+port+":3000",
		rekorEnvImage("INNSEGL_TEST_REKOR_IMAGE", defaultRekorImage),
		"serve",
		"--trillian_log_server.address="+logServer, "--trillian_log_server.port=8090",
		"--redis_server.address="+redis, "--redis_server.port=6379",
		"--host=0.0.0.0", "--port=3000", "--rekor_server.address=0.0.0.0",
		// An in-memory signing key: the log's identity lasts as long as the
		// container, which is exactly as long as the test trusts it.
		"--rekor_server.signer=memory",
		"--rekor_server.hostname="+rekorOrigin,
		"--enable_attestation_storage=false",
		"--enable_stable_checkpoint=false",
	); err != nil {
		return s, fmt.Errorf("start rekor: %w", err)
	}

	if err := s.waitForRekor(ctx, 3*time.Minute); err != nil {
		return s, err
	}
	return s, nil
}

// waitForSchema polls until Trillian's tables are reachable over TCP.
//
// Over TCP, and that is the whole point of this function. The MySQL image
// boots twice: first a temporary server with networking disabled, against
// which it applies the schema, and then — after shutting that one down — the
// real one. A probe over the container's unix socket succeeds during the first
// boot, so "the schema is there" would be answered yes at a moment when
// nothing on the network can connect, and the Trillian pair would be started
// into the gap and exit. Asking the way Trillian will ask is the only question
// whose answer means anything.
func (s *rekorStack) waitForSchema(ctx context.Context, container string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := rekorDocker(attempt, "exec", container,
			"mysql", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
			"-u"+trillianDBUser, "-p"+trillianDBPassword,
			"-e", "SELECT 1 FROM "+trillianDBName+".Trees LIMIT 1")
		cancel()
		if err == nil {
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("trillian schema never became reachable over TCP in %s: %w", container, last)
}

// waitForRekor polls the log until it answers with a tree.
func (s *rekorStack) waitForRekor(ctx context.Context, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL()+"/api/v1/log", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("GET /api/v1/log: %s", resp.Status)
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("rekor never became ready: %w", last)
}

// requireRekor starts the stack for one test and tears it down after it.
//
// It skips, naming what went unproven, rather than letting an integration case
// pass without the thing it integrates with.
func requireRekor(t *testing.T) *rekorStack {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	if err := rekorDockerUsable(ctx); err != nil {
		t.Skipf("skipping: no real Rekor (%v). "+
			"SEG-003 proves nothing about I5 against a fake transparency log "+
			"(doc 01 §2); start Docker and re-run.", err)
	}

	stack, err := startRekorStack(ctx)
	if stack != nil {
		t.Cleanup(func() {
			for _, cerr := range stack.stop() {
				t.Logf("warning: tearing down the rekor stack: %v", cerr)
			}
		})
	}
	if err != nil {
		if stack != nil {
			for _, id := range stack.containers {
				state, sErr := rekorDocker(context.Background(), "inspect", "--format",
					"{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}", id)
				if sErr != nil {
					state = "(state unreadable: " + sErr.Error() + ")"
				}
				t.Logf("container %s: %s", id, state)
				logs, logErr := rekorDocker(context.Background(), "logs", "--tail", "40", id)
				if logErr != nil {
					logs = "(could not be read: " + logErr.Error() + ")"
				}
				t.Logf("container %s logs:\n%s", id, logs)
			}
		}
		t.Fatalf("could not start the rekor stack: %v", err)
	}
	return stack
}
