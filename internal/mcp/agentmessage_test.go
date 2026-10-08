// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// agentmessage_test.go — RM-237 (#382), E16 (#358). Doc 07 TC-GREC:
//
//	GREC-005 (I) An agent's brief and its own text. One `agent_message`
//	(role brief) at start, one per assistant text turn (role assistant),
//	`payload_digest` in the keyed grammar under the core's key; the key
//	never appears in any event, log or file.
//
// WHAT IS REAL HERE AND WHAT IS NOT — the identical split observe_test.go's
// own header states, for the identical reasons: a real Postgres backs the
// ledger and the idempotency store, so "exactly one agent_message" and "a
// replay appends nothing" rest on the ledger's own UNIQUE idempotency_key
// (LED-008) and the store's leased claim (ADR-0017), never an in-memory
// stand-in that would assert both and prove neither. The body volume is a
// real directory on a real filesystem, for the identical reason "the body
// is on the operator's volume" is a claim about a file. The run directory
// is a fake (credRuns, shared with get_credential_test.go and
// observe_test.go): what it is about is this recorder's own decision
// procedure, doc 07's layer C.
//
// This recorder binds no sdk.Tool (see agentmessage.go's own doc comment),
// so these tests call RecordAgentMessageForGateway directly — there is no
// wire transport to cross and no session to build, unlike observe_test.go's
// otcServe.

const (
	amRunID   = "run-rm-237"
	amSecret  = "test-deployment-identity-secret-for-rm-237-agent-message"
	amKeyID   = "core-2026-09"
	amKeyID2  = "core-2026-10"
	amBrief   = "fix the login bug"
	amTurnOne = "Looked at the auth handler: the session cookie was never marked Secure. Fixed and added a regression test."
	amTurnTwo = "Ran the test suite. All green."
)

// ---------------------------------------------------------------------------
// Fixture — the same shape otcEnv (observe_test.go) already is.
// ---------------------------------------------------------------------------

type amEnv struct {
	runs    *credRuns
	ledger  *otcSpyLedger
	store   *ledger.Store
	idem    *IdempotencyStore
	bodyDir string
}

// amSetup installs the agent-message recorder for the test's duration.
// mutate, when non-nil, is the seam a test uses to swap a dependency out for
// a failing one, or to change the key id/secret under test.
func amSetup(t *testing.T, mutate func(*AgentMessageRecorderConfig)) *amEnv {
	t.Helper()
	idem, dsn := newStore(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	env := &amEnv{
		runs:    newCredRuns(credRun(amRunID)),
		ledger:  &otcSpyLedger{inner: lg},
		store:   lg,
		idem:    idem,
		bodyDir: t.TempDir(),
	}
	cfg := AgentMessageRecorderConfig{
		Runs: env.runs, Ledger: env.ledger, Idempotency: env.idem, BodyDir: env.bodyDir,
		IdentitySecret: amSecret, KeyID: amKeyID,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	restore, err := ConfigureAgentMessageRecorder(cfg)
	if err != nil {
		t.Fatalf("ConfigureAgentMessageRecorder: %v", err)
	}
	t.Cleanup(restore)
	return env
}

func (e *amEnv) events(t *testing.T) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.store.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	records, err := e.store.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	return records
}

// agentMessages returns every agent_message event in the chain, in position
// order.
func (e *amEnv) agentMessages(t *testing.T) []event.Fields {
	t.Helper()
	var out []event.Fields
	for _, r := range e.events(t) {
		if r[event.FieldEventType] == event.EventTypeAgentMessage {
			out = append(out, r)
		}
	}
	return out
}

func (e *amEnv) count(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := e.store.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	return n
}

// bodyPath is observe.go's ported layout, the same literal join
// otcEnv.bodyPath already uses, so a change to the production helper fails
// this test instead of moving the goalposts with it.
func (e *amEnv) bodyPath(runID, digest string) string {
	return filepath.Join(e.bodyDir, runID, strings.TrimPrefix(digest, event.HashPrefix)+".json")
}

func (e *amEnv) storedFiles(t *testing.T) []string {
	t.Helper()
	var found []string
	err := filepath.Walk(e.bodyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(e.bodyDir, path)
		if rerr != nil {
			return rerr
		}
		found = append(found, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the body volume: %v", err)
	}
	return found
}

func amCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// GREC-005 — the brief and each assistant text turn.
// ---------------------------------------------------------------------------

func TestGREC005OneAgentMessagePerBriefAndPerAssistantTurn(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	briefDigest, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if err != nil {
		t.Fatalf("recording the brief: %v", err)
	}
	turn1Digest, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnOne))
	if err != nil {
		t.Fatalf("recording the first assistant turn: %v", err)
	}
	turn2Digest, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnTwo))
	if err != nil {
		t.Fatalf("recording the second assistant turn: %v", err)
	}

	for _, d := range []string{briefDigest, turn1Digest, turn2Digest} {
		if err := event.ValidateKeyedDigest(d); err != nil {
			t.Errorf("payload_digest %q does not validate under internal/event's v4 keyed grammar: %v", d, err)
		}
	}
	if turn1Digest == turn2Digest {
		t.Fatal("two different assistant turns produced the same digest")
	}
	if briefDigest == turn1Digest {
		t.Fatal("the brief and an assistant turn produced the same digest")
	}

	msgs := env.agentMessages(t)
	if len(msgs) != 3 {
		t.Fatalf("the ledger holds %d agent_message events, want exactly 3: %+v", len(msgs), msgs)
	}

	byDigest := map[string]event.Fields{}
	for _, m := range msgs {
		d := fmt.Sprintf("%v", m[event.FieldPayloadDigest])
		byDigest[d] = m
	}
	brief, ok := byDigest[briefDigest]
	if !ok {
		t.Fatalf("no recorded event carries the brief's own digest %q", briefDigest)
	}
	if brief[event.FieldRole] != AgentMessageRoleBrief {
		t.Errorf("the brief's event has role %v, want %q", brief[event.FieldRole], AgentMessageRoleBrief)
	}
	if brief[event.FieldRunID] != amRunID {
		t.Errorf("the brief's event has run_id %v, want %q", brief[event.FieldRunID], amRunID)
	}
	if brief[event.FieldSpiffeID] != credSPIFFEID(amRunID) {
		t.Errorf("spiffe_id is %v, want %q", brief[event.FieldSpiffeID], credSPIFFEID(amRunID))
	}
	if brief[event.FieldSource] != event.SourceMCP {
		t.Errorf("source is %v, want %q", brief[event.FieldSource], event.SourceMCP)
	}
	if brief[event.FieldSchemaVersion] != event.SchemaVersion {
		t.Errorf("schema_version is %v, want %q", brief[event.FieldSchemaVersion], event.SchemaVersion)
	}

	for _, turnDigest := range []string{turn1Digest, turn2Digest} {
		rec, ok := byDigest[turnDigest]
		if !ok {
			t.Fatalf("no recorded event carries turn digest %q", turnDigest)
		}
		if rec[event.FieldRole] != AgentMessageRoleAssistant {
			t.Errorf("an assistant turn's event has role %v, want %q", rec[event.FieldRole], AgentMessageRoleAssistant)
		}
	}

	// The body is on the volume for each of the three, addressed by the
	// PLAIN digest — never the keyed one, which the file system layout has
	// no room for (agentmessage.go's own doc comment).
	for _, body := range []string{amBrief, amTurnOne, amTurnTwo} {
		plain := event.Digest([]byte(body))
		raw, err := os.ReadFile(env.bodyPath(amRunID, plain))
		if err != nil {
			t.Fatalf("reading the stored body for %q: %v (files: %v)", body, err, env.storedFiles(t))
		}
		if string(raw) != body {
			t.Errorf("the stored body is %q, want %q", raw, body)
		}
	}
}

// TestGREC005AReplayAppendsNothing. ADR-0017/IP §6.6: recording the
// identical brief or the identical assistant turn again for the same run
// appends nothing a second time — the property GREC-004 names as "a long
// conversation's repeated history produces no duplicate events," measured
// here at the recorder that would otherwise have to re-derive it.
func TestGREC005AReplayAppendsNothing(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	first, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnOne))
	if err != nil {
		t.Fatalf("first recording: %v", err)
	}
	if n := len(env.agentMessages(t)); n != 1 {
		t.Fatalf("after one call the ledger holds %d agent_message events, want 1", n)
	}

	second, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnOne))
	if err != nil {
		t.Fatalf("replayed recording: %v", err)
	}
	if first != second {
		t.Errorf("the replay returned digest %q, the original returned %q", second, first)
	}
	if n := len(env.agentMessages(t)); n != 1 {
		t.Errorf("after a replay the ledger holds %d agent_message events, want 1", n)
	}

	// A DIFFERENT turn is a different observation and gets its own event.
	third, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnTwo))
	if err != nil {
		t.Fatalf("recording the second turn: %v", err)
	}
	if third == first {
		t.Fatal("two different assistant turns produced one digest")
	}
	if n := len(env.agentMessages(t)); n != 2 {
		t.Errorf("the ledger holds %d agent_message events, want 2", n)
	}
}

// TestGREC005APlainSha256DigestIsNeverProduced. ADR-0061 decision 2:
// agent_message.payload_digest is ALWAYS the keyed grammar,
// hmac-sha256:<key-id>:<hex> — never doc 02 §1's plain envelope grammar
// every other type's payload_digest uses.
func TestGREC005APlainSha256DigestIsNeverProduced(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	bodies := []struct {
		role, body string
	}{
		{AgentMessageRoleBrief, amBrief},
		{AgentMessageRoleAssistant, amTurnOne},
		{AgentMessageRoleAssistant, amTurnTwo},
		{AgentMessageRoleAssistant, "a third, distinct turn of assistant text"},
	}
	for _, b := range bodies {
		if _, err := RecordAgentMessageForGateway(ctx, amRunID, b.role, []byte(b.body)); err != nil {
			t.Fatalf("recording role %q: %v", b.role, err)
		}
	}

	msgs := env.agentMessages(t)
	if len(msgs) != len(bodies) {
		t.Fatalf("the ledger holds %d agent_message events, want %d", len(msgs), len(bodies))
	}
	for _, m := range msgs {
		digest := fmt.Sprintf("%v", m[event.FieldPayloadDigest])
		if strings.HasPrefix(digest, event.HashPrefix) {
			t.Errorf("payload_digest %q is the plain %s grammar; ADR-0061 requires the keyed grammar for agent_message", digest, event.HashPrefix)
		}
		if !strings.HasPrefix(digest, "hmac-sha256:") {
			t.Errorf("payload_digest %q does not carry the hmac-sha256: tag", digest)
		}
		if err := event.ValidateDigest(digest); err == nil {
			t.Errorf("payload_digest %q validates as a PLAIN digest (event.ValidateDigest accepted it); it must not", digest)
		}
	}
}

// TestGREC005TheKeyNeverAppearsInAnyEventLogOrFile. ADR-0061 decision 2's
// whole point: a party holding the ledger and the body store but not the
// per-deployment secret cannot confirm a guessed brief or message by
// hashing it, and cannot even find the key itself lying around to do
// arithmetic with. This is a canary scan over every event's every field
// value and over every file the body volume holds.
func TestGREC005TheKeyNeverAppearsInAnyEventLogOrFile(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	derivedKey, err := DeriveAgentMessageKey(amSecret, amKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey: %v", err)
	}

	if _, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief)); err != nil {
		t.Fatalf("recording the brief: %v", err)
	}
	if _, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnOne)); err != nil {
		t.Fatalf("recording the first turn: %v", err)
	}

	canaries := []string{derivedKey, amSecret}

	// Every event's every field value, rendered as text.
	for _, rec := range env.events(t) {
		for field, v := range rec {
			s := fmt.Sprintf("%v", v)
			for _, c := range canaries {
				if strings.Contains(s, c) {
					t.Errorf("event field %q = %q contains the %s", field, s, canaryLabel(c, derivedKey))
				}
			}
		}
	}

	// Every file the body volume holds.
	for _, rel := range env.storedFiles(t) {
		raw, err := os.ReadFile(filepath.Join(env.bodyDir, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		for _, c := range canaries {
			if strings.Contains(string(raw), c) {
				t.Errorf("stored body file %q contains the %s", rel, canaryLabel(c, derivedKey))
			}
		}
	}
}

func canaryLabel(c, derivedKey string) string {
	if c == derivedKey {
		return "derived agent-message key"
	}
	return "identity secret"
}

// TestGREC005RotationVerifiesAnOldDigestAgainstItsOwnKeyID. GREC-006's
// property, measured at the recorder rather than at DeriveAgentMessageKey
// directly: a digest this recorder appended under one key id stays
// verifiable under that id after the deployment has moved its CURRENT key
// id on to something else.
func TestGREC005RotationVerifiesAnOldDigestAgainstItsOwnKeyID(t *testing.T) {
	env := amSetup(t, nil) // configured with amKeyID
	ctx := amCtx(t)

	oldDigest, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnOne))
	if err != nil {
		t.Fatalf("recording under the pre-rotation key id: %v", err)
	}
	wantKeyID := "hmac-sha256:" + amKeyID + ":"
	if !strings.HasPrefix(oldDigest, wantKeyID) {
		t.Fatalf("digest %q was not keyed under %q", oldDigest, amKeyID)
	}

	// Rotate: reconfigure with a NEW key id, same secret, same dependencies.
	amSetup(t, func(cfg *AgentMessageRecorderConfig) {
		cfg.Runs, cfg.Ledger, cfg.Idempotency, cfg.BodyDir = env.runs, env.ledger, env.idem, env.bodyDir
		cfg.KeyID = amKeyID2
	})
	newDigest, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, []byte(amTurnTwo))
	if err != nil {
		t.Fatalf("recording under the post-rotation key id: %v", err)
	}
	wantKeyID2 := "hmac-sha256:" + amKeyID2 + ":"
	if !strings.HasPrefix(newDigest, wantKeyID2) {
		t.Fatalf("digest %q was not keyed under the new id %q", newDigest, amKeyID2)
	}

	// A verifier holding the identity secret and the OLD event's own key id
	// re-derives the key that produced oldDigest, independent of amKeyID2
	// being current now, and recomputes the identical value.
	rederivedOldKey, err := DeriveAgentMessageKey(amSecret, amKeyID)
	if err != nil {
		t.Fatalf("re-deriving the old key id: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(rederivedOldKey))
	mac.Write([]byte(amTurnOne))
	wantOldDigest := "hmac-sha256:" + amKeyID + ":" + hex.EncodeToString(mac.Sum(nil))
	if wantOldDigest != oldDigest {
		t.Errorf("re-deriving the old key id gave a digest of %q, want the originally recorded %q", wantOldDigest, oldDigest)
	}
}

// ---------------------------------------------------------------------------
// Error paths — the run, the role, and the body.
// ---------------------------------------------------------------------------

func TestAgentMessageRefusesAMalformedRunID(t *testing.T) {
	amSetup(t, nil)
	ctx := amCtx(t)

	for name, runID := range map[string]string{
		"not an identifier": "Run With Spaces",
		"too long":          strings.Repeat("r", 64),
		"unknown":           "run-nobody-rm-237",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RecordAgentMessageForGateway(ctx, runID, AgentMessageRoleBrief, []byte(amBrief))
			if got := mcpError(t, err).Class; got != ClassRunNotFound {
				t.Errorf("class is %s, want %s (err: %v)", got, ClassRunNotFound, err)
			}
		})
	}
}

func TestAgentMessageRefusesARetiredRun(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	env.runs.retire(amRunID, time.Now())
	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassRunAlreadyRetired {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassRunAlreadyRetired, err)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events for a retired run", n)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v for a retired run", files)
	}
}

// TestAgentMessageRefusesADirectoryThatAnsweredForAnotherRun. The
// directory's answer is checked, not trusted (I2) — the same check
// observe_tool_call and get_credential already make, from the one
// implementation of it.
func TestAgentMessageRefusesADirectoryThatAnsweredForAnotherRun(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	env.runs.putAs(amRunID, credRun("run-somebody-else-rm-237"))
	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassInvariantViolation, err)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after a misattributed answer", n)
	}
}

func TestAgentMessageRefusesAnUnknownRole(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	for _, role := range []string{"", "user", "system", "Brief", "ASSISTANT"} {
		_, err := RecordAgentMessageForGateway(ctx, amRunID, role, []byte(amBrief))
		if got := mcpError(t, err).Class; got != ClassInvariantViolation {
			t.Errorf("role %q: class is %s, want %s (err: %v)", role, got, ClassInvariantViolation, err)
		}
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after every role was refused", n)
	}
	// The role gate runs before any dependency is touched (record's own doc
	// comment): a call refused for its role must not leave a body on the
	// volume that no event will ever point at.
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after every role was refused", files)
	}
}

func TestAgentMessageRefusesAnEmptyBody(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(""))
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassInvariantViolation, err)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v after an empty body was refused", files)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after an empty body was refused", n)
	}
}

func TestAgentMessageRefusesAnOversizedBody(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	oversized := []byte(strings.Repeat("x", MaxObservedBodyBytes+1))
	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, oversized)
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassInvariantViolation, err)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events after an oversized body was refused", n)
	}

	// POSITIVE CONTROL — a body of exactly the bound is stored.
	atBound := []byte(strings.Repeat("x", MaxObservedBodyBytes))
	if _, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleAssistant, atBound); err != nil {
		t.Fatalf("a body of exactly the bound was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error paths — the ledger, the run directory, and the body volume.
// ---------------------------------------------------------------------------

func TestAgentMessageReportsALedgerItCannotAppendTo(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	env.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassLedgerUnavailable, err)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although the append failed", n)
	}

	// The claim was released, so the retry that follows a retryable
	// refusal actually runs the recorder again rather than replaying a
	// failure.
	env.ledger.fail(nil)
	if _, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief)); err != nil {
		t.Fatalf("the retry after a retryable failure did not succeed: %v", err)
	}
	if n := len(env.agentMessages(t)); n != 1 {
		t.Errorf("the ledger holds %d agent_message events after one retry, want 1", n)
	}
}

func TestAgentMessageReportsARunDirectoryItCannotRead(t *testing.T) {
	env := amSetup(t, nil)
	ctx := amCtx(t)

	env.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "events", Retryable: true,
		Err: fmt.Errorf("connection refused"),
	})
	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassLedgerUnavailable, err)
	}
	if files := env.storedFiles(t); len(files) != 0 {
		t.Errorf("the volume holds %v although the run could not be resolved", files)
	}
}

func TestAgentMessageReportsAVolumeItCannotWriteInto(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("the volume is not mounted"), 0o600); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}

	env := amSetup(t, func(cfg *AgentMessageRecorderConfig) {
		cfg.BodyDir = filepath.Join(blocked, "bodies")
	})
	ctx := amCtx(t)

	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassLedgerUnavailable {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassLedgerUnavailable, err)
	}
	if n := env.count(t); n != 0 {
		t.Errorf("the ledger holds %d events although no body was stored (I3)", n)
	}
	if got := len(env.ledger.appended); got != 0 {
		t.Errorf("the ledger was asked to append %d times although no body was stored", got)
	}
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

func TestAgentMessageIsNotServedUntilItIsConfigured(t *testing.T) {
	t.Cleanup(install(&active.agentMessage, nil))

	_, err := RecordAgentMessageForGateway(amCtx(t), amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassInvariantViolation, err)
	}
}

func TestConfigureAgentMessageRecorderRefusesAnIncompleteConfiguration(t *testing.T) {
	idem, dsn := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lg, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(lg.Close)

	full := AgentMessageRecorderConfig{
		Runs: newCredRuns(), Ledger: lg, Idempotency: idem, BodyDir: t.TempDir(),
		IdentitySecret: amSecret, KeyID: amKeyID,
	}
	for name, mutate := range map[string]func(*AgentMessageRecorderConfig){
		"no run directory":     func(c *AgentMessageRecorderConfig) { c.Runs = nil },
		"no ledger":            func(c *AgentMessageRecorderConfig) { c.Ledger = nil },
		"no idempotency store": func(c *AgentMessageRecorderConfig) { c.Idempotency = nil },
		"no body volume":       func(c *AgentMessageRecorderConfig) { c.BodyDir = "" },
		"no identity secret":   func(c *AgentMessageRecorderConfig) { c.IdentitySecret = "" },
		"malformed key id":     func(c *AgentMessageRecorderConfig) { c.KeyID = "Not An Id" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			restore, cerr := ConfigureAgentMessageRecorder(cfg)
			if cerr == nil {
				restore()
				t.Fatalf("ConfigureAgentMessageRecorder accepted a configuration with %s", name)
			}
			if got := mcpError(t, cerr).Class; got != ClassInvariantViolation {
				t.Errorf("class is %s, want %s", got, ClassInvariantViolation)
			}
		})
	}

	restore, err := ConfigureAgentMessageRecorder(full)
	if err != nil {
		t.Fatalf("ConfigureAgentMessageRecorder refused a complete configuration: %v", err)
	}
	restore()
}

// TestAgentMessageRefusesAStoredReplyItCannotRead. ADR-0017 returns the
// recorded reply byte for byte; a row that is not an agent-message reply is
// a defect, not a result to decode leniently.
//
// The store is seeded under the SAME key the recorder computes, so the
// replay reaches the decode rather than being turned away as a different
// request.
func TestAgentMessageRefusesAStoredReplyItCannotRead(t *testing.T) {
	amSetup(t, nil)
	ctx := amCtx(t)

	plainDigest := event.Digest([]byte(amBrief))
	svc := installed(&active.agentMessage)
	keyedDigest := svc.keyedDigest([]byte(amBrief))

	key := agentMessageIdempotencyKey(amRunID, AgentMessageRoleBrief, plainDigest)
	if _, err := svc.idem.Do(ctx, Call{
		Tool: agentMessageIdempotencyTool,
		Key:  key,
		Params: map[string]any{
			"run_id": amRunID, "role": AgentMessageRoleBrief, "payload_digest": keyedDigest,
		},
	}, func(context.Context) (any, error) {
		// Canonicalizes cleanly, decodes into nothing agentMessageRecordOut
		// documents.
		return map[string]any{"digest": int64(7)}, nil
	}); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	_, err := RecordAgentMessageForGateway(ctx, amRunID, AgentMessageRoleBrief, []byte(amBrief))
	if got := mcpError(t, err).Class; got != ClassInvariantViolation {
		t.Errorf("class is %s, want %s (err: %v)", got, ClassInvariantViolation, err)
	}
}

// TestAgentMessageIdempotencyKeyKeepsADigestShorterThanTheBound holds the
// truncation's other direction: a digest already within the bound is used
// whole. A real SHA-256 always exceeds it, so without this case the
// condition's false branch is never taken (IP §2's 100% branch floor on MCP
// error-return paths, measured by scripts/branch-coverage.sh).
func TestAgentMessageIdempotencyKeyKeepsADigestShorterThanTheBound(t *testing.T) {
	short := "sha256:" + strings.Repeat("a", agentMessageKeyDigestChars-1)
	got := agentMessageIdempotencyKey(amRunID, AgentMessageRoleBrief, short)
	want := agentMessageKeyPrefix + amRunID + "-" + AgentMessageRoleBrief + "-" + strings.Repeat("a", agentMessageKeyDigestChars-1)
	if got != want {
		t.Fatalf("key = %q, want %q (a short digest must be used whole)", got, want)
	}
}
