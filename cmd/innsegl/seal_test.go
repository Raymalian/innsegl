// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// SEG-013 (proposed, doc 07 layer U): the operator-facing surface of
// `innsegl seal`.
//
// The command's contract is its flags, its environment fallbacks and its exit
// status, because those are what a compose file, a Kubernetes CronJob and a
// human at 3am all consult. Nothing here needs a Postgres, an object store or
// a Rekor: the cycler is the seam, and the engine that satisfies it in
// production is what SEG-008..012 exercise.

// minimalSealArgs is a command line with every required flag and nothing else.
func minimalSealArgs(extra ...string) []string {
	return append([]string{
		"-dsn", "postgres://innsegl@ledger/innsegl",
		"-rekor-url", "http://rekor:3000",
		"-endpoint", "store:9000",
		"-bucket", "segments",
		"-access-key", "key",
		"-secret-key", "secret",
		"-once",
	}, extra...)
}

// stubCycler is a sealer whose cycles are scripted. The counter is atomic
// because the loop cases read it from the test goroutine while the loop runs.
type stubCycler struct {
	cycles []stubCycle
	count  atomic.Int64
}

type stubCycle struct {
	result sealCycle
	err    error
}

func (s *stubCycler) calls() int { return int(s.count.Load()) }

func (s *stubCycler) Cycle(context.Context) (sealCycle, error) {
	i := int(s.count.Add(1)) - 1
	if i >= len(s.cycles) {
		i = len(s.cycles) - 1
	}
	c := s.cycles[i]
	return c.result, c.err
}

func stubDeps(c *stubCycler) sealDeps {
	return sealDeps{
		open: func(context.Context, sealOptions) (sealCycler, func(), error) {
			return c, func() {}, nil
		},
	}
}

func cleanCycle() sealCycle {
	return sealCycle{
		Watermark: 12,
		Head:      12,
		Sealed: []sealedSegment{{
			SegmentID:  "sha256:" + strings.Repeat("a", 64),
			MerkleRoot: "sha256:" + strings.Repeat("b", 64),
			First:      9, Last: 12, Events: 4,
			Anchored: true, LogIndex: 7, EntryUUID: strings.Repeat("c", 64),
		}},
		Lag: segment.LagSnapshot{ObservedAt: time.Now(), Anchored: true},
	}
}

func unanchoredCycle() sealCycle {
	c := cleanCycle()
	c.Sealed[0].Anchored = false
	c.Sealed[0].Failure = "connection refused"
	c.Unanchored = []sealedSegment{c.Sealed[0]}
	c.Lag.Anchored = false
	c.Lag.PendingSegments = 1
	return c
}

func TestSEG013CleanCycleExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand(minimalSealArgs(), &stdout, &stderr, stubDeps(cycler))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr.String())
	}
	if cycler.calls() != 1 {
		t.Errorf("-once ran %d cycles, want 1", cycler.calls())
	}
	if !strings.Contains(stdout.String(), "sealed 1") {
		t.Errorf("stdout = %q, want a summary naming what was sealed", stdout.String())
	}
}

func TestSEG013UnanchoredSegmentExitsUnanchored(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: unanchoredCycle()}}}

	code := runSealCommand(minimalSealArgs(), &stdout, &stderr, stubDeps(cycler))

	if code != exitSealUnanchored {
		t.Fatalf("exit = %d, want %d (UNANCHORED)", code, exitSealUnanchored)
	}
	if !strings.Contains(stderr.String(), "UNANCHORED") {
		t.Errorf("stderr = %q, want it to say UNANCHORED", stderr.String())
	}
}

func TestSEG013ACycleThatCouldNotRunExitsInconclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{err: errors.New("ledger unavailable")}}}

	code := runSealCommand(minimalSealArgs(), &stdout, &stderr, stubDeps(cycler))

	if code != exitSealInconclusive {
		t.Fatalf("exit = %d, want %d (INCONCLUSIVE)", code, exitSealInconclusive)
	}
	if !strings.Contains(stderr.String(), "INCONCLUSIVE") {
		t.Errorf("stderr = %q, want it to say INCONCLUSIVE", stderr.String())
	}
}

func TestSEG013OpeningFailureIsInconclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := sealDeps{
		open: func(context.Context, sealOptions) (sealCycler, func(), error) {
			return nil, nil, errors.New("no route to the object store")
		},
	}

	code := runSealCommand(minimalSealArgs(), &stdout, &stderr, deps)

	if code != exitSealInconclusive {
		t.Fatalf("exit = %d, want %d (INCONCLUSIVE)", code, exitSealInconclusive)
	}
	if !strings.Contains(stderr.String(), "no route to the object store") {
		t.Errorf("stderr = %q, want the underlying reason", stderr.String())
	}
}

func TestSEG013RequiredFlagsAreRefusedByName(t *testing.T) {
	// Every required flag, dropped one at a time. The message must name the
	// flag and the environment variable, because the compose service that
	// forgets one has only stderr to go on.
	cases := []struct {
		drop string
		want string
	}{
		{"-dsn", envLedgerDSN},
		{"-rekor-url", envRekorURL},
		{"-endpoint", envEndpoint},
		{"-bucket", envBucket},
		{"-access-key", envAccessKey},
		{"-secret-key", envSecretKey},
	}
	for _, tc := range cases {
		t.Run(tc.drop, func(t *testing.T) {
			t.Setenv(tc.want, "")
			var stdout, stderr bytes.Buffer
			cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

			code := runSealCommand(withoutFlag(minimalSealArgs(), tc.drop),
				&stdout, &stderr, stubDeps(cycler))

			if code != exitUsage {
				t.Fatalf("exit = %d without %s, want %d (usage)", code, tc.drop, exitUsage)
			}
			if !strings.Contains(stderr.String(), tc.drop) ||
				!strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %s and $%s", stderr.String(), tc.drop, tc.want)
			}
			if cycler.calls() != 0 {
				t.Errorf("a refused command line still ran %d cycles", cycler.calls())
			}
		})
	}
}

// withoutFlag removes a flag and its value from a command line.
func withoutFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func TestSEG013EveryRequiredFlagHasAnEnvironmentFallback(t *testing.T) {
	// A scheduled job configured entirely by environment must not have to put
	// the ledger DSN or the object store secret on a command line the process
	// table can read.
	for name, value := range map[string]string{
		envLedgerDSN: "postgres://innsegl@ledger/innsegl",
		envRekorURL:  "http://rekor:3000",
		envEndpoint:  "store:9000",
		envBucket:    "segments",
		envAccessKey: "key",
		envSecretKey: "secret",
	} {
		t.Setenv(name, value)
	}

	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand([]string{"-once"}, &stdout, &stderr, stubDeps(cycler))

	if code != exitOK {
		t.Fatalf("exit = %d with everything in the environment, want %d. stderr: %s",
			code, exitOK, stderr.String())
	}
}

func TestSEG013RefusesANonPositiveSegmentSize(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand(minimalSealArgs("-segment-events", "0"), &stdout, &stderr, stubDeps(cycler))

	if code != exitUsage {
		t.Fatalf("exit = %d for -segment-events 0, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "-segment-events") {
		t.Errorf("stderr = %q, want it to name the flag", stderr.String())
	}
}

func TestSEG013RefusesANonPositiveIntervalWithoutOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	args := withoutFlag(minimalSealArgs(), "-once")
	code := runSealCommand(append(args, "-interval", "0"), &stdout, &stderr, stubDeps(cycler))

	if code != exitUsage {
		t.Fatalf("exit = %d for -interval 0 without -once, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "-once") {
		t.Errorf("stderr = %q, want it to point at -once", stderr.String())
	}
}

func TestSEG013RefusesATrailingArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand(minimalSealArgs("segments"), &stdout, &stderr, stubDeps(cycler))

	if code != exitUsage {
		t.Fatalf("exit = %d for a trailing argument, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), `"segments"`) {
		t.Errorf("stderr = %q, want it to quote the rejected argument", stderr.String())
	}
}

func TestSEG013HelpExitsZeroAndDocumentsTheExitStatuses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand([]string{"-h"}, &stdout, &stderr, stubDeps(cycler))

	if code != exitOK {
		t.Fatalf("exit = %d for -h, want %d", code, exitOK)
	}
	for _, want := range []string{"UNANCHORED", "INCONCLUSIVE", "-once", "-segment-events"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help does not mention %q: %s", want, stderr.String())
		}
	}
}

func TestSEG013JSONReportIsMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand(minimalSealArgs("-json"), &stdout, &stderr, stubDeps(cycler))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr.String())
	}
	var view sealReportJSON
	if err := json.Unmarshal(stdout.Bytes(), &view); err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, stdout.String())
	}
	if view.Watermark != 12 || len(view.Sealed) != 1 {
		t.Errorf("JSON report = %+v, want watermark 12 and one sealed segment", view)
	}
	if view.Sealed[0].EntryUUID == "" {
		t.Error("the JSON report drops the Rekor entry uuid, which is the anchor's whole point")
	}
}

func TestSEG013QuietPrintsNothingForACycleThatDidNothing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	idle := sealCycle{Watermark: 4, Head: 4, Pending: 0,
		Lag: segment.LagSnapshot{ObservedAt: time.Now(), Anchored: true}}
	cycler := &stubCycler{cycles: []stubCycle{{result: idle}}}

	code := runSealCommand(minimalSealArgs("-quiet"), &stdout, &stderr, stubDeps(cycler))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if stdout.Len() != 0 {
		t.Errorf("-quiet printed %q for a cycle that did nothing", stdout.String())
	}
}

func TestSEG013QuietStillReportsAFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: unanchoredCycle()}}}

	code := runSealCommand(minimalSealArgs("-quiet"), &stdout, &stderr, stubDeps(cycler))

	if code != exitSealUnanchored {
		t.Fatalf("exit = %d, want %d", code, exitSealUnanchored)
	}
	if !strings.Contains(stderr.String(), "UNANCHORED") {
		t.Errorf("-quiet suppressed a failure: stderr = %q", stderr.String())
	}
}

// The loop is the default shape, because doc 05 §1 lists innsegl-sealer as a
// component rather than a job. These two cases are what make that real.

func TestSEG013LoopRunsUntilTheContextIsCancelled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	ctx, cancel := context.WithCancel(context.Background())
	args := append(withoutFlag(minimalSealArgs(), "-once"), "-interval", "1ms")

	done := make(chan int, 1)
	go func() { done <- runSealLoop(ctx, args, &stdout, &stderr, stubDeps(cycler)) }()

	deadline := time.After(10 * time.Second)
	for cycler.calls() <= 2 {
		select {
		case <-deadline:
			t.Fatalf("the loop ran %d cycles in 10s; it is not looping", cycler.calls())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()

	select {
	case code := <-done:
		if code != exitOK {
			t.Errorf("a cancelled loop of clean cycles exited %d, want %d", code, exitOK)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not stop when its context was cancelled")
	}
}

func TestSEG013LoopExitsWithTheWorstVerdictItSaw(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{
		{result: unanchoredCycle()},
		{result: cleanCycle()},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	args := append(withoutFlag(minimalSealArgs(), "-once"), "-interval", "1ms")

	done := make(chan int, 1)
	go func() { done <- runSealLoop(ctx, args, &stdout, &stderr, stubDeps(cycler)) }()

	deadline := time.After(10 * time.Second)
	for cycler.calls() <= 2 {
		select {
		case <-deadline:
			t.Fatalf("the loop ran %d cycles in 10s", cycler.calls())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()

	select {
	case code := <-done:
		// A sealer that could not anchor for an hour must not exit 0 because
		// its last cycle happened to be clean.
		if code != exitSealUnanchored {
			t.Errorf("the loop exited %d, want %d: it saw an unanchored segment",
				code, exitSealUnanchored)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not stop when its context was cancelled")
	}
}

// ---------------------------------------------------------------------------
// The remaining refusals and the production wiring's own error paths. IP §2
// puts a 100% branch floor on segment sealing; a path that only exists in
// production is still a path, and each of these is a way an operator is told
// what is wrong instead of getting a panic or a silent zero.
// ---------------------------------------------------------------------------

func TestSEG013RefusesABadFlagValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

	code := runSealCommand(minimalSealArgs("-interval", "purple"), &stdout, &stderr, stubDeps(cycler))

	if code != exitUsage {
		t.Fatalf("exit = %d for an unparseable duration, want %d", code, exitUsage)
	}
}

func TestSEG013RefusesAWindowlessSurveyAndAnAttemptlessAnchor(t *testing.T) {
	for _, tc := range []struct{ flag, value string }{
		{"-scan-window", "0"},
		{"-anchor-attempts", "0"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cycler := &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}}

			code := runSealCommand(minimalSealArgs(tc.flag, tc.value), &stdout, &stderr, stubDeps(cycler))

			if code != exitUsage {
				t.Fatalf("exit = %d for %s %s, want %d", code, tc.flag, tc.value, exitUsage)
			}
			if !strings.Contains(stderr.String(), tc.flag) {
				t.Errorf("stderr = %q, want it to name %s", stderr.String(), tc.flag)
			}
		})
	}
}

func TestSEG013AnOpenerThatReturnsNothingIsInconclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := sealDeps{
		open: func(context.Context, sealOptions) (sealCycler, func(), error) {
			return nil, nil, nil
		},
	}

	code := runSealCommand(minimalSealArgs(), &stdout, &stderr, deps)

	if code != exitSealInconclusive {
		t.Fatalf("exit = %d, want %d", code, exitSealInconclusive)
	}
}

func TestSEG013ACancelledCycleIsNotAFailedCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	reporter := sealReporter{stdout: &stdout, stderr: &stderr}

	code := reporter.cycle(ctx, &stubCycler{cycles: []stubCycle{{err: context.Canceled}}})

	if code != exitOK {
		t.Errorf("a cycle cancelled by shutdown exited %d, want %d", code, exitOK)
	}
}

func TestSEG013HumanReportNamesEverySegmentItTouched(t *testing.T) {
	// The realistic shape of a bad cycle: one segment sealed this cycle that
	// the log would not take (so it is in both Sealed and Unanchored), and one
	// from an earlier cycle's backlog that this one recovered.
	c := unanchoredCycle()
	c.Sealed[0].Alerted = true
	c.Unanchored[0].Alerted = true
	c.Anchored = []sealedSegment{{
		SegmentID: "sha256:" + strings.Repeat("d", 64), First: 1, Last: 4,
		MerkleRoot: "sha256:" + strings.Repeat("e", 64),
		Anchored:   true, LogIndex: 2, EntryUUID: strings.Repeat("f", 64),
	}}
	c.Unanchored = []sealedSegment{{
		SegmentID: "sha256:" + strings.Repeat("9", 64), First: 5, Last: 8,
		MerkleRoot: "sha256:" + strings.Repeat("8", 64),
		Failure:    "connection refused", Alerted: true,
	}}
	c.Lag.OverBound = true

	out := renderSealCycle(c)

	for _, want := range []string{
		"sealed", "recovered", "unanchored", "connection refused",
		"OVER BOUND", "ledger_drift_detected appended", "NOT ANCHORED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

// failingWriter is a stdout that cannot be written to, which is what a closed
// pipe looks like to a scheduled job.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestSEG013AJSONReportThatCannotBeWrittenIsReported(t *testing.T) {
	var stderr bytes.Buffer
	reporter := sealReporter{stdout: failingWriter{}, stderr: &stderr, asJSON: true}

	code := reporter.cycle(context.Background(), &stubCycler{cycles: []stubCycle{{result: cleanCycle()}}})

	if code != exitOK {
		t.Errorf("exit = %d, want %d: a report that could not be written is not a failed cycle", code, exitOK)
	}
	if !strings.Contains(stderr.String(), "broken pipe") {
		t.Errorf("stderr = %q, want the write failure named", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// The anchoring key.
// ---------------------------------------------------------------------------

func TestAnchorSignerGeneratesAnEphemeralKeyByDefault(t *testing.T) {
	signer, err := anchorSigner("")
	if err != nil {
		t.Fatalf("anchorSigner(\"\"): %v", err)
	}
	if signer == nil {
		t.Fatal("anchorSigner(\"\") returned no signer and no error")
	}
}

func TestAnchorSignerReadsBothPEMEncodings(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling SEC 1: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling PKCS#8: %v", err)
	}

	for name, block := range map[string]*pem.Block{
		"sec1":  {Type: "EC PRIVATE KEY", Bytes: sec1},
		"pkcs8": {Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchor.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}
			signer, err := anchorSigner(path)
			if err != nil {
				t.Fatalf("anchorSigner(%s): %v", name, err)
			}
			if _, err := signer.PublicKeyPEM(); err != nil {
				t.Errorf("the signer has no public key: %v", err)
			}
		})
	}
}

func TestAnchorSignerRefusesAKeyItCannotUse(t *testing.T) {
	dir := t.TempDir()

	rsaBlock, err := x509.MarshalPKCS8PrivateKey(mustRSAKey(t))
	if err != nil {
		t.Fatalf("marshalling an RSA key: %v", err)
	}

	cases := map[string][]byte{
		"not-pem":       []byte("this is not a PEM file\n"),
		"pem-not-a-key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("nope")}),
		"wrong-algorithm": pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: rsaBlock}),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".pem")
			if werr := os.WriteFile(path, content, 0o600); werr != nil {
				t.Fatalf("writing %s: %v", path, werr)
			}
			if _, serr := anchorSigner(path); serr == nil {
				t.Fatalf("anchorSigner accepted %s", name)
			}
		})
	}

	if _, aerr := anchorSigner(filepath.Join(dir, "absent.pem")); aerr == nil {
		t.Error("anchorSigner accepted a path that does not exist")
	}

	// A well-formed EC key on the wrong curve. internal/segment refuses it
	// because a segment root is SHA-256 and Rekor pairs that with P-256, and
	// the refusal has to reach the operator with the path in it.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a P-384 key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(p384)
	if err != nil {
		t.Fatalf("marshalling the P-384 key: %v", err)
	}
	path := filepath.Join(dir, "p384.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	if _, err := anchorSigner(path); err == nil {
		t.Error("anchorSigner accepted a P-384 anchoring key")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the file the key came from", err)
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an RSA key: %v", err)
	}
	return key
}

func TestOpenSealerRefusesAnUnusableLedger(t *testing.T) {
	opts := defaultSealOptions()
	opts.dsn = "this is not a connection string"
	opts.rekorURL = "http://rekor:3000"
	opts.endpoint = "store:9000"
	opts.bucket = "segments"
	opts.accessKey, opts.secretKey = "key", "secret"

	engine, closeAll, err := openSealer(context.Background(), opts)
	if err == nil {
		if closeAll != nil {
			closeAll()
		}
		t.Fatalf("openSealer accepted %q and returned %v", opts.dsn, engine)
	}
	if !strings.Contains(err.Error(), "ledger") {
		t.Errorf("error = %v, want it to say which dependency failed", err)
	}
}

func TestSealDepsDefaultsToTheProductionOpener(t *testing.T) {
	deps := sealDeps{}
	if deps.opener() == nil {
		t.Fatal("the zero sealDeps has no opener, so `innsegl seal` would panic in production")
	}
}

func TestHumanReportSkipsAnUnanchoredSegmentWithNothingToSay(t *testing.T) {
	c := sealCycle{Unanchored: []sealedSegment{{SegmentID: "sha256:" + strings.Repeat("a", 64)}}}

	if strings.Contains(renderSealCycle(c), "unanchored sha256:") {
		t.Errorf("the report printed an empty reason line:\n%s", renderSealCycle(c))
	}
}
