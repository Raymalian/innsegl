// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/verify"
)

// The error paths.
//
// IP §2 puts a 100% branch floor on "every error-return path" of the MCP
// tools; this package is not one of them, but it is a public-facing proof
// surface and its error paths are the ones a reader meets when something has
// already gone wrong. A branch that has never been taken is a branch nobody
// has read.

func TestTheSmallReadersSurviveWhatTheyAreGiven(t *testing.T) {
	if got := stringOf(42); got != "" {
		t.Errorf("stringOf(42) = %q, want the empty string", got)
	}
	if got := stringOf("x"); got != "x" {
		t.Errorf("stringOf(%q) = %q", "x", got)
	}
	for _, tc := range []struct {
		in   any
		want int64
	}{{float64(7), 7}, {int64(9), 9}, {"eleven", 0}, {nil, 0}} {
		if got := int64Of(tc.in); got != tc.want {
			t.Errorf("int64Of(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if nullableTime(time.Time{}) != nil {
		t.Error("a zero time is not a bound")
	}
	if nullableTime(time.Unix(1, 0)) == nil {
		t.Error("a set time is a bound")
	}
	if likePattern("") != nil {
		t.Error("an empty search is not a pattern")
	}
	if got := *likePattern("a_b%c"); got != `%a\_b\%c%` {
		t.Errorf("likePattern escaped to %q; an unescaped wildcard makes a search "+
			"match things nobody asked for", got)
	}
	discardError(errors.New("swallowed on purpose"))
}

func TestQuoteLiteralSurvivesAQuoteAndABackslash(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "'plain'"},
		{"it's", "'it''s'"},
		{`back\slash`, `E'back\\slash'`},
	} {
		if got := quoteLiteral(tc.in); got != tc.want {
			t.Errorf("quoteLiteral(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestJoinURLRefusesWhatIsNotAnEndpoint(t *testing.T) {
	for _, base := range []string{"", "not a url", "://nope", "/relative"} {
		if _, err := joinURL(base, "/x"); err == nil {
			t.Errorf("joinURL accepted %q as an endpoint", base)
		} else if !errors.Is(err, ErrBadRequest) {
			t.Errorf("joinURL(%q) returned %v, want ErrBadRequest", base, err)
		}
	}
	got, err := joinURL("https://rekor.example/", "/api/v1/x")
	if err != nil || got != "https://rekor.example/api/v1/x" {
		t.Errorf("joinURL = %q, %v", got, err)
	}
}

func TestNewProverRefusesAConfigurationItCouldNotAnswerWith(t *testing.T) {
	if _, err := NewProver(ProofConfig{}); err == nil {
		t.Error("NewProver accepted a BFF that serves no repository")
	}
	if _, err := NewProver(ProofConfig{
		Repos: map[string]string{"r": "/tmp"}, RekorURL: "https://rekor.example",
	}); err == nil {
		t.Error("NewProver accepted a configuration with no Fulcio")
	}
	if _, err := NewProver(ProofConfig{
		Repos: map[string]string{"r": "/tmp"}, FulcioURL: "https://f.example", RekorURL: "not a url",
	}); err == nil {
		t.Error("NewProver accepted a Rekor URL it could not join a path onto")
	}
	// The defaults fill in, and the endpoints resolve.
	p, err := NewProver(ProofConfig{
		Repos:     map[string]string{"b": "/tmp/b", "a": "/tmp/a"},
		FulcioURL: "https://f.example", RekorURL: "https://r.example",
	})
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}
	if got := p.Repos(); len(got) != 2 || got[0] != "a" {
		t.Errorf("Repos() = %v, want them sorted", got)
	}
}

func TestProveRefusesARequestItCannotAct0n(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	prover := s.prover(t)
	if _, err := prover.Prove(t.Context(), "", ""); !errors.Is(err, ErrBadRequest) {
		t.Errorf("Prove with no commit returned %v, want ErrBadRequest", err)
	}
	// No repository named: every served repository is searched, and none holds
	// this revision.
	if _, err := prover.Prove(t.Context(), "", strings.Repeat("f", 40)); !errors.Is(err, ErrNotFound) {
		t.Errorf("Prove for an unheld commit returned %v, want ErrNotFound", err)
	}
	// Named repository, revision it does not hold.
	if _, err := prover.Prove(t.Context(), fixtureRepo, "refs/heads/no-such-branch"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Prove for an unknown revision returned %v, want ErrNotFound", err)
	}
	// No repository named, and the commit is found by search.
	if _, err := prover.Prove(t.Context(), "", s.commit); err != nil {
		t.Errorf("Prove could not find the commit by searching: %v", err)
	}
}

func TestTheEntryReaderRefusesEveryDocumentItCannotRead(t *testing.T) {
	good := func(t *testing.T) (json.RawMessage, string) {
		t.Helper()
		s := newProofScenario(t, proofOptions{})
		p, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
		if err != nil {
			t.Fatalf("Prove: %v", err)
		}
		return p.Material.RekorEntry, p.Entry.UUID
	}
	entry, uuid := good(t)

	for _, tc := range []struct {
		name string
		raw  json.RawMessage
		uuid string
	}{
		{"nothing at all", nil, uuid},
		{"not a Rekor entry map", json.RawMessage(`["a"]`), uuid},
		{"an entry the response does not name", entry, "not-this-uuid"},
		{"two entries and no uuid to choose by",
			json.RawMessage(`{"a":{"body":"","logIndex":1},"b":{"body":"","logIndex":2}}`), ""},
		{"a body that is not base64",
			json.RawMessage(`{"a":{"body":"!!!","logIndex":1}}`), "a"},
		{"a body that is not JSON",
			json.RawMessage(`{"a":{"body":"` +
				base64.StdEncoding.EncodeToString([]byte("nope")) + `","logIndex":1}}`), "a"},
		{"a public key that is not base64",
			json.RawMessage(`{"a":{"body":"` +
				base64.StdEncoding.EncodeToString([]byte(
					`{"kind":"hashedrekord","spec":{"signature":{"publicKey":{"content":"!!"}}}}`)) +
				`","logIndex":1}}`), "a"},
	} {
		if _, err := entryBody(tc.raw, tc.uuid); err == nil {
			t.Errorf("%s: entryBody accepted it", tc.name)
		}
	}

	// The uuid may be omitted when the document holds exactly one entry.
	if _, err := entryBody(entry, ""); err != nil {
		t.Errorf("entryBody could not read a one-entry document without a uuid: %v", err)
	}
	// A body whose public key is base64 but not a certificate is a gap, not a
	// certificate.
	notACert := json.RawMessage(`{"a":{"body":"` +
		base64.StdEncoding.EncodeToString([]byte(
			`{"kind":"hashedrekord","spec":{"signature":{"publicKey":{"content":"`+
				base64.StdEncoding.EncodeToString([]byte("not pem"))+`"}}}}`)) +
		`","logIndex":1}}`)
	if _, err := certificateFromEntry(notACert, "a"); err == nil {
		t.Error("certificateFromEntry accepted a public key that is not a certificate")
	}
	if _, err := certificateFromEntry(json.RawMessage(`{}`), "a"); err == nil {
		t.Error("certificateFromEntry accepted a document with no entry")
	}
	if _, err := parseCertificatePEM([]byte("not pem")); err == nil {
		t.Error("parseCertificatePEM accepted bytes that are not PEM")
	}
	if _, err := parseCertificatePEM([]byte(
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("parseCertificatePEM accepted a PEM block that is not a certificate")
	}
}

func TestTheObjectReadersHandleTheirEdges(t *testing.T) {
	if got := commitMessage([]byte("no blank line here")); got != "no blank line here" {
		t.Errorf("commitMessage of a headerless object = %q", got)
	}
	if got := commitMessage([]byte("tree x\n\nmessage")); got != "message" {
		t.Errorf("commitMessage = %q", got)
	}
	// A SHA-256 repository's object name is chosen by the width of the name
	// being checked against.
	object := []byte("tree x\n\nm")
	want := sha256.Sum256(append([]byte("commit 9\x00"), object...))
	if got := gitObjectName(object, strings.Repeat("a", 64)); got != hex.EncodeToString(want[:]) {
		t.Errorf("gitObjectName for a sha256 repository = %s", got)
	}
}

func TestRederiveIsUnderivableRatherThanWrongOnMaterialItDoesNotHave(t *testing.T) {
	empty := Proof{}
	for _, f := range Rederive(empty) {
		if f.Result == Contradicts {
			t.Errorf("an empty proof convicts on %q: %s", f.Name, f.Detail)
		}
		if f.Detail == "" {
			t.Errorf("%q gives no reason", f.Name)
		}
	}

	// A response that names a commit and carries no object.
	named := Proof{CommitSHA: strings.Repeat("a", 40)}
	if f := findingNamed(t, Rederive(named), FindingCommitObject); f.Result != Underivable {
		t.Errorf("%q is %q with no object to hash", FindingCommitObject, f.Result)
	}
	// An object with no commit named.
	object := Proof{Material: Material{CommitObject: "tree x\n\nm"}}
	if f := findingNamed(t, Rederive(object), FindingCommitObject); f.Result != Underivable {
		t.Errorf("%q is %q with no commit named", FindingCommitObject, f.Result)
	}
}

func TestTheTrailerRederivationConvictsOnlyWhenTheObjectSettlesIt(t *testing.T) {
	// Two Agent-Identity trailers: the object's claim does not resolve.
	twice := "tree x\n\nsubject\n\nAgent-Identity: spiffe://a/agent/b/c/d\n" +
		"Agent-Identity: spiffe://a/agent/b/c/e\n"

	// The response claims an identity anyway: a conviction.
	claimed := Proof{
		Material: Material{CommitObject: twice},
		Claim:    verify.Claim{Identity: "spiffe://a/agent/b/c/d"},
	}
	if f := findingNamed(t, Rederive(claimed), FindingTrailerClaim); f.Result != Contradicts {
		t.Errorf("%q is %q where the object's trailers do not resolve and the "+
			"response reports one anyway", FindingTrailerClaim, f.Result)
	}
	// The response claims nothing: honest, and not a conviction.
	silent := Proof{Material: Material{CommitObject: twice}}
	if f := findingNamed(t, Rederive(silent), FindingTrailerClaim); f.Result != Agrees {
		t.Errorf("%q is %q where neither the object nor the response resolves a claim",
			FindingTrailerClaim, f.Result)
	}
	// A rewritten Agent-Run is caught as surely as a rewritten Agent-Identity.
	object := "tree x\n\nsubject\n\nAgent-Identity: spiffe://a/agent/b/c/d\nAgent-Run: d\n"
	run := Proof{
		Material: Material{CommitObject: object},
		Claim:    verify.Claim{Identity: "spiffe://a/agent/b/c/d", Run: "somebody-else"},
	}
	if f := findingNamed(t, Rederive(run), FindingTrailerClaim); f.Result != Contradicts {
		t.Errorf("%q is %q with a rewritten Agent-Run", FindingTrailerClaim, f.Result)
	}
}

func TestTheCertificateAndIdentityRederivationsHandleUnreadableMaterial(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	honest, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Material that does not parse is a conviction: a server that serves
	// rubbish where a certificate should be has not served a certificate.
	bad := honest
	bad.Material.CertificatePEM = "not pem at all"
	if f := findingNamed(t, Rederive(bad), FindingCertificate); f.Result != Contradicts {
		t.Errorf("%q is %q on material that does not parse", FindingCertificate, f.Result)
	}

	// A rewritten fingerprint under an honest certificate.
	fingerprinted := honest
	fingerprinted.Certificate.Fingerprint = strings.Repeat("0", 64)
	if f := findingNamed(t, Rederive(fingerprinted), FindingCertificate); f.Result != Contradicts {
		t.Errorf("%q is %q with a rewritten fingerprint", FindingCertificate, f.Result)
	}

	// Check 3 reported verified over a commit that carries no trailer at all.
	untrailered := honest
	untrailered.Material.CommitObject = "tree x\n\njust a subject\n"
	if f := findingNamed(t, Rederive(untrailered), FindingIdentityCheck); f.Result != Contradicts {
		t.Errorf("%q is %q where the object carries no Agent-Identity and the "+
			"response reports the check verified", FindingIdentityCheck, f.Result)
	}

	// Check 3 reported failed where the two identities are identical: honest
	// or not, this re-derivation cannot settle it, and says so.
	failedAnyway := honest
	failedAnyway.Checks = append([]verify.Check(nil), honest.Checks...)
	for i := range failedAnyway.Checks {
		if failedAnyway.Checks[i].Name == verify.CheckTrailerIdentity {
			failedAnyway.Checks[i].Result = verify.Failed
		}
	}
	if f := findingNamed(t, Rederive(failedAnyway), FindingIdentityCheck); f.Result != Underivable {
		t.Errorf("%q is %q where the response reports failed and the identities "+
			"match; guessing here would be a false accusation", FindingIdentityCheck, f.Result)
	}

	// Check 3 reported unavailable.
	unavailable := honest
	unavailable.Checks = append([]verify.Check(nil), honest.Checks...)
	for i := range unavailable.Checks {
		if unavailable.Checks[i].Name == verify.CheckTrailerIdentity {
			unavailable.Checks[i].Result = verify.Unavailable
		}
	}
	if f := findingNamed(t, Rederive(unavailable), FindingIdentityCheck); f.Result != Underivable {
		t.Errorf("%q is %q where the response reports the check unavailable",
			FindingIdentityCheck, f.Result)
	}

	// No check 3 in the response at all.
	noCheck := honest
	noCheck.Checks = []verify.Check{{Name: verify.CheckRekorInclusion, Result: verify.Verified}}
	noCheck.Verdict = string(verify.VerdictVerified)
	if f := findingNamed(t, Rederive(noCheck), FindingIdentityCheck); f.Result != Underivable {
		t.Errorf("%q is %q where the response reports no such check",
			FindingIdentityCheck, f.Result)
	}

	// An unattributed response reports no checks, so there is no rollup.
	unattributed := honest
	unattributed.Checks = nil
	unattributed.Verdict = string(verify.VerdictUnattributed)
	if f := findingNamed(t, Rederive(unattributed), FindingRollup); f.Result != Underivable {
		t.Errorf("%q is %q on a response that reports no checks", FindingRollup, f.Result)
	}

	// The rollup catches an unavailable laundered into a verified.
	laundered := honest
	laundered.Checks = []verify.Check{
		{Name: verify.CheckCertificateChain, Result: verify.Unavailable},
		{Name: verify.CheckRekorInclusion, Result: verify.Verified},
		{Name: verify.CheckTrailerIdentity, Result: verify.Verified},
	}
	laundered.Verdict = string(verify.VerdictVerified)
	if f := findingNamed(t, Rederive(laundered), FindingRollup); f.Result != Contradicts {
		t.Errorf("%q is %q where a check errored and the badge says verified; that "+
			"is FD anti-pattern 1 exactly", FindingRollup, f.Result)
	}
}

func TestTheStoreRefusesAQueryItCannotMakeSenseOf(t *testing.T) {
	owner, ownerDSN, readerDSN := migrated(t)
	s, _ := readStore(t, readerDSN)
	ctx := t.Context()

	if _, err := s.ListRuns(ctx, RunFilter{Status: "retiredish"}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("ListRuns accepted an unknown status: %v", err)
	}
	if _, err := s.ListRuns(ctx, RunFilter{Cursor: "not-a-number"}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("ListRuns accepted a cursor it never issued: %v", err)
	}
	if _, err := s.ListRuns(ctx, RunFilter{Cursor: "-4"}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("ListRuns accepted a negative cursor: %v", err)
	}
	if _, err := s.Run(ctx, ""); !errors.Is(err, ErrBadRequest) {
		t.Errorf("Run accepted an empty run id: %v", err)
	}

	// A date window is applied, and one that excludes everything returns an
	// empty page rather than an error: "no runs match these filters" is FD
	// §4.6's empty state, not a failure.
	seed(t, owner, 2)
	page, err := s.ListRuns(ctx, RunFilter{From: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("ListRuns with a future window: %v", err)
	}
	if len(page.Runs) != 0 {
		t.Errorf("a window in the future matched %d runs", len(page.Runs))
	}
	page, err = s.ListRuns(ctx, RunFilter{From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("ListRuns with a window around now: %v", err)
	}
	if len(page.Runs) != 2 {
		t.Errorf("a window around now matched %d runs, 2 were seeded", len(page.Runs))
	}
	_ = ownerDSN
}

// The anchoring heartbeat, which FD §3.1 calls the system's public
// tamper-evidence pulse, reads the sealed segment out of the chain.
func TestTheAnchoringHeartbeatReadsTheNewestSealedSegment(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	s, _ := readStore(t, readerDSN)
	ctx := t.Context()

	before, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if before.Anchor.Present {
		t.Error("a heartbeat is reported before any segment was sealed; absent is " +
			"not \"anchored 0 minutes ago\"")
	}

	sealed := event.Fields{
		event.FieldEventType:            event.EventTypeSegmentSealed,
		event.FieldSource:               event.SourceSystem,
		event.FieldSegmentID:            "seg-000001",
		event.FieldSegmentMerkleRoot:    "sha256:" + strings.Repeat("c", 64),
		event.FieldFirstPosition:        int64(1),
		event.FieldLastPosition:         int64(1),
		event.FieldAnchorRekorLogIndex:  int64(82914),
		event.FieldAnchorRekorEntryUUID: strings.Repeat("d", 64),
	}
	appendOrFail(ctx, t, owner, sealed)

	after, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if !after.Anchor.Present || !after.Anchor.Anchored {
		t.Fatalf("the heartbeat reads %+v after a sealed and anchored segment", after.Anchor)
	}
	if after.Anchor.SegmentID != "seg-000001" || after.Anchor.RekorLogIndex != 82914 {
		t.Errorf("the heartbeat reads %+v", after.Anchor)
	}
	if after.Anchor.SealedAt.IsZero() {
		t.Error("the heartbeat carries no sealing time, so no lag can be computed")
	}
}

func TestEnsureReadOnlyRoleRefusesWhatItCannotProvision(t *testing.T) {
	_, ownerDSN, _ := migrated(t)
	ctx := t.Context()

	for _, role := range []string{"", "1bad", "has space", `"quoted"`, strings.Repeat("r", 64)} {
		if err := EnsureReadOnlyRole(ctx, ownerDSN, role, "pw"); err == nil {
			t.Errorf("EnsureReadOnlyRole accepted the role name %q", role)
		}
	}
	if err := EnsureReadOnlyRole(ctx, "postgres://nobody@127.0.0.1:1/none?sslmode=disable",
		ReadOnlyRole, "pw"); err == nil {
		t.Error("EnsureReadOnlyRole accepted a DSN it could not connect with")
	}
	// Re-running it on an existing role is what an operator does after a
	// migration adds a table, and it must not fail.
	if err := EnsureReadOnlyRole(ctx, ownerDSN, ReadOnlyRole, ""); err != nil {
		t.Errorf("EnsureReadOnlyRole is not idempotent: %v", err)
	}
}

func TestTheReadOnlyReportIsHonestAboutASuperuserAndANonPostgresError(t *testing.T) {
	// A superuser is writable however its probes came out: no ACL binds it, so
	// every refusal above it would have been a coincidence.
	if !(ReadOnlyReport{Superuser: true}).Writable() {
		t.Error("a superuser is reported as read-only; no ACL binds one")
	}
	if (ReadOnlyReport{}).Writable() {
		t.Error("a report with no allowed probe is reported as writable")
	}
	if got := sqlState(errors.New("not a Postgres error")); got != "" {
		t.Errorf("sqlState of a non-Postgres error = %q", got)
	}
	if isPrivilegeRefusal("IN001") {
		t.Error("an append-only trigger's refusal is not a privilege refusal: the " +
			"ACL let the statement through, which is what \"can write\" means here")
	}
}

// A probe that cannot be run at all is reported as ALLOWED, deliberately. An
// unrunnable probe establishes nothing, and reading "we could not ask" as "the
// credential is safe" is the exact shape of the failure this whole package
// exists to refuse.
func TestAProbeThatCannotRunIsNeverReadAsARefusal(t *testing.T) {
	_, _, readerDSN := migrated(t)
	ctx := t.Context()

	conn, err := pgx.Connect(ctx, readerDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if cerr := conn.Close(ctx); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}
	got := probeOnce(ctx, conn, Probe{Name: "unreachable", SQL: "SELECT 1"})
	if !got.Allowed {
		t.Errorf("a probe that could not run was recorded as a refusal: %+v", got)
	}
	if !strings.Contains(got.Detail, "could not be run") {
		t.Errorf("the result does not say the probe never ran: %+v", got)
	}
}

func TestOpenRefusesADSNItCannotParse(t *testing.T) {
	if _, err := Open(context.Background(), "postgres://%zz"); err == nil {
		t.Error("Open accepted a DSN it could not parse")
	}
}

func TestNewServerRefusesAHalfWiredAPI(t *testing.T) {
	if _, err := NewServer(ServerConfig{}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("NewServer accepted an API with no store: %v", err)
	}
	_, _, readerDSN := migrated(t)
	store, _ := readStore(t, readerDSN)
	if _, err := NewServer(ServerConfig{Store: store}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("NewServer accepted an API with no prover; it would have to answer "+
			"verification questions out of the database: %v", err)
	}
}

func TestTheHTTPSurfaceReportsWhatItCannotDo(t *testing.T) {
	srv, _ := testServer(t)

	// A malformed date window.
	for _, q := range []string{"?from=yesterday", "?to=soon"} {
		if a := get(t, srv.URL, "/api/v1/runs"+q); a.status != 400 {
			t.Errorf("GET /api/v1/runs%s returned %d, want 400", q, a.status)
		}
	}
	// An unrouted path.
	if a := get(t, srv.URL, "/api/v1/nothing"); a.status != 404 {
		t.Errorf("GET an unrouted path returned %d, want 404", a.status)
	}
	// OPTIONS is allowed and says so.
	a := do(t, "OPTIONS", srv.URL+"/api/v1/runs", "")
	if a.status != 204 || !strings.Contains(a.header.Get("Allow"), "GET") {
		t.Errorf("OPTIONS returned %d with Allow: %q", a.status, a.header.Get("Allow"))
	}
	// An internal failure is a 500 with a message rather than a blank page.
	rec := httptest.NewRecorder()
	writeProblem(rec, errors.New("something the API could not do"))
	if rec.Code != 500 {
		t.Errorf("an unclassified error produced %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), codeInternal) {
		t.Errorf("a 500 body carries no code: %s", rec.Body.String())
	}
}
