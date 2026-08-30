// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// TC-SIG's integration cases. Each one runs against the harness in
// sigstoreharness_test.go — real SPIRE, real Fulcio, real Rekor, the released
// gitsign binary — and skips loudly when any of those is missing.

// scriptedSource hands out pre-arranged credentials and counts the calls. It
// is not a fake Sigstore: every token it returns was minted by the real SPIRE
// server in the harness's stack. What it fakes is only the MCP's
// get_credential, which is RM-033's wiring and not under test here.
type scriptedSource struct {
	steps []func() (Credential, error)
	calls int
}

func (s *scriptedSource) Credential(context.Context) (Credential, error) {
	i := s.calls
	s.calls++
	if i >= len(s.steps) {
		return Credential{}, fmt.Errorf("scriptedSource: unexpected call %d", i+1)
	}
	return s.steps[i]()
}

func staticStep(c Credential) func() (Credential, error) {
	return func() (Credential, error) { return c, nil }
}

func errorStep(err error) func() (Credential, error) {
	return func() (Credential, error) { return Credential{}, err }
}

func harnessConfig(s *stack) Config {
	return Config{
		FulcioURL:   s.fulcioURL,
		RekorURL:    s.rekorURL,
		Issuer:      harnessIssuer,
		GitsignPath: s.gitsignPath,
		Author:      testAuthorPolicy(),
	}
}

func newHarnessSigner(t *testing.T, cfg Config, src CredentialSource) *Signer {
	t.Helper()
	signer, err := NewSigner(cfg, src)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	t.Cleanup(func() {
		if err := signer.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return signer
}

// rekorEntryJSON is what the harness reads back out of the log. It is a second
// reader on purpose: an assertion that the wrapper's Result agrees with the
// wrapper's own parser would prove nothing.
type rekorEntryJSON struct {
	Body           string `json:"body"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
	IntegratedTime int64  `json:"integratedTime"`
	Verification   struct {
		InclusionProof struct {
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
			Hashes     []string `json:"hashes"`
			Checkpoint string   `json:"checkpoint"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

// readRekorEntry fetches one entry by uuid and returns it with its raw body.
func readRekorEntry(t *testing.T, s *stack, uuid string) (rekorEntryJSON, []byte) {
	t.Helper()
	var entries map[string]rekorEntryJSON
	fetchJSON(t, s.rekorURL+"/api/v1/log/entries/"+uuid, &entries)
	entry, ok := entries[uuid]
	if !ok {
		t.Fatalf("Rekor returned no entry for uuid %s", uuid)
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		t.Fatalf("decoding the entry body: %v", err)
	}
	return entry, raw
}

// hashedRekordSpec is the part of the entry body the assertions read.
type hashedRekordSpec struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// assertEntryIsForCommit is the anti-vacuity check on the Rekor half of
// SIG-001. gitsign's online mode logs a hashedrekord whose artifact is the
// COMMIT SHA, so "this entry is this commit's" is a hash comparison and not an
// inference: the entry's data hash must be sha256 of the commit SHA, and the
// public key it was accepted under must be the certificate the commit is
// signed with.
func assertEntryIsForCommit(t *testing.T, body []byte, commitSHA, certFingerprint string) {
	t.Helper()
	var got hashedRekordSpec
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("the entry body is not a hashedrekord: %v: %s", err, body)
	}
	if got.Kind != "hashedrekord" {
		t.Errorf("entry kind = %q, want hashedrekord", got.Kind)
	}
	if want := sha256Hex(commitSHA); got.Spec.Data.Hash.Value != want {
		t.Errorf("the entry's artifact hash is %s; sha256 of commit %s is %s. "+
			"This entry is not this commit's.",
			got.Spec.Data.Hash.Value, commitSHA, want)
	}
	pemBytes, err := base64.StdEncoding.DecodeString(got.Spec.Signature.PublicKey.Content)
	if err != nil {
		t.Fatalf("decoding the entry's public key: %v", err)
	}
	fpr, err := fingerprintOfCertPEM(pemBytes)
	if err != nil {
		t.Fatalf("parsing the entry's public key as a certificate: %v", err)
	}
	if fpr != certFingerprint {
		t.Errorf("the entry was logged under certificate %s; the commit is signed "+
			"under %s. This entry is somebody else's.", fpr, certFingerprint)
	}
}

// assertInclusionProof verifies the log's proof from first principles, under
// the log's own published key, reusing internal/segment's verifier rather than
// writing a second Merkle implementation. Nothing Rekor asserts about the
// proof is taken on trust except the key.
func assertInclusionProof(t *testing.T, s *stack, entry rekorEntryJSON, uuid string, body []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pemBytes, err := s.rekorLogKeyPEM(ctx)
	if err != nil {
		t.Fatalf("fetching the log's public key: %v", err)
	}
	logKey, err := segment.ParseLogPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("parsing the log's public key: %v", err)
	}
	ip := entry.Verification.InclusionProof
	if ip.TreeSize == 0 || ip.Checkpoint == "" {
		t.Fatalf("the entry carries no inclusion proof. The leaf was accepted and "+
			"never integrated, which is what happens when trillian-log-signer is "+
			"not running (RM-012). entry=%+v", entry)
	}
	proof := segment.InclusionProof{
		EntryUUID:  uuid,
		Body:       body,
		LogIndex:   ip.LogIndex,
		TreeSize:   ip.TreeSize,
		RootHash:   ip.RootHash,
		Hashes:     ip.Hashes,
		Checkpoint: ip.Checkpoint,
	}
	if err := proof.Verify(logKey); err != nil {
		t.Errorf("the inclusion proof for %s does not verify: %v", uuid, err)
	}
}

// trailersOf reads the commit's trailers back with git's own parser. ADR-0028:
// a trailer git cannot find is a claim nothing can check, so the assertion is
// made against `%(trailers)` and not against our own bytes.
func trailersOf(t *testing.T, repo, rev string) []string {
	t.Helper()
	out := gitOut(t, repo, "log", "-1", "--format=%(trailers:only,unfold)", rev)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

// ---------------------------------------------------------------------------
// SIG-001 — happy path against local Fulcio + Rekor.
//
// doc 07: "Commit exists; `gitsign verify` passes; trailers present and
// correct; Rekor inclusion proof valid". Proves I2, I3, I5.
//
// The intent+recorded event ordering half of the row is the two-phase protocol
// and belongs to RM-033 (#41); this case proves the signing half it will wrap.
// ---------------------------------------------------------------------------

func TestSIG001HappyPathAgainstLocalFulcioAndRekor(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	claim := newRunClaim(t, "rm-032")
	cred, err := s.mintJWTSVID(ctx, claim.Identity, 10*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	src := &scriptedSource{steps: []func() (Credential, error){staticStep(cred)}}
	signer := newHarnessSigner(t, harnessConfig(s), src)
	repo := newRepo(t)

	before := time.Now().UTC()
	res, err := signer.Sign(ctx, Request{
		Repo:        repo,
		Message:     "SIG-001: the first signed commit",
		AuthorName:  testAuthorName,
		AuthorEmail: testAuthorEmail,
		Claim:       claim,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	after := time.Now().UTC()

	// 1. The commit exists, and it is the one the wrapper reported.
	if got := gitOut(t, repo, "cat-file", "-t", res.CommitSHA); got != "commit" {
		t.Fatalf("object %s is a %q, not a commit", res.CommitSHA, got)
	}
	if head := gitOut(t, repo, "rev-parse", "HEAD"); head != res.CommitSHA {
		t.Errorf("HEAD is %s, Sign reported %s", head, res.CommitSHA)
	}
	if raw := gitOut(t, repo, "cat-file", "commit", res.CommitSHA); !strings.Contains(raw, "gpgsig") {
		t.Fatalf("the commit object carries no gpgsig header:\n%s", raw)
	}

	// 2. The trailers are present and correct, read back with git's parser.
	want := []string{
		TrailerAgentIdentity + ": " + claim.Identity,
		TrailerAgentRun + ": " + claim.Run,
		TrailerAgentTask + ": " + claim.Task,
	}
	got := trailersOf(t, repo, res.CommitSHA)
	if len(got) != len(want) {
		t.Fatalf("git reports %d trailers %q, want %q", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("trailer %d = %q, want %q", i, got[i], want[i])
		}
	}
	if body := gitOut(t, repo, "log", "-1", "--format=%B", res.CommitSHA); strings.Contains(
		strings.ToLower(body), "co-authored-by") {
		t.Errorf("I6: the commit message carries a co-authorship trailer:\n%s", body)
	}

	// 3. The certificate is THIS RUN's — the SAN, not merely "a Fulcio cert".
	if res.Certificate.SPIFFEID != claim.Identity {
		t.Errorf("the certificate's URI SAN is %q, this run is %q",
			res.Certificate.SPIFFEID, claim.Identity)
	}
	if res.Certificate.Issuer != harnessIssuer {
		t.Errorf("the certificate's Fulcio issuer extension is %q, want %q",
			res.Certificate.Issuer, harnessIssuer)
	}
	// IP §6.2: the credential was live when it was used, and so is the
	// certificate it produced.
	if res.Certificate.NotBefore.After(after) || res.Certificate.NotAfter.Before(before) {
		t.Errorf("the certificate is valid %s..%s, which does not cover the signing "+
			"window %s..%s", res.Certificate.NotBefore, res.Certificate.NotAfter, before, after)
	}

	// 4. `gitsign verify` passes — the released upstream verifier, told which
	//    identity to expect.
	v, err := signer.Verify(ctx, repo, res.CommitSHA, claim.Identity)
	if err != nil {
		t.Fatalf("gitsign verify: %v", err)
	}
	for _, k := range []string{"Validated Git signature", "Validated Rekor entry", "Validated Certificate claims"} {
		if !v.Claims[k] {
			t.Errorf("gitsign verify reported %q = false; full output:\n%s", k, v.Output)
		}
	}

	// 4b. AND IT BITES. A verifier that passes for every identity proves
	//     nothing about attribution, so the same commit must FAIL against a
	//     different run's SPIFFE ID.
	other := claim.Identity + "-not-this-run"
	if _, err := signer.Verify(ctx, repo, res.CommitSHA, other); err == nil {
		t.Errorf("gitsign verify passed for %q, which is not the identity that "+
			"signed this commit. The identity check is not being applied.", other)
	}

	// 5. The Rekor entry is THIS COMMIT's, and its inclusion proof verifies
	//    under the log's own key.
	if res.Rekor.UUID == "" || res.Rekor.LogIndex < 0 {
		t.Fatalf("Sign reported no Rekor entry: %+v", res.Rekor)
	}
	entry, body := readRekorEntry(t, s, res.Rekor.UUID)
	if entry.LogIndex != res.Rekor.LogIndex {
		t.Errorf("the log says index %d, Sign reported %d", entry.LogIndex, res.Rekor.LogIndex)
	}
	assertEntryIsForCommit(t, body, res.CommitSHA, res.Certificate.Fingerprint)
	assertInclusionProof(t, s, entry, res.Rekor.UUID, body)

	// IP §2's verification methodology applied to the test itself: "measure
	// artifacts, never assert from memory". Run with -v and this case prints
	// the artifact it just proved, so a report quotes the run rather than the
	// author's recollection of it.
	t.Logf("SIG-001 artifact\n"+
		"  commit          %s\n"+
		"  trailers        %s\n"+
		"  cert URI SAN    %s\n"+
		"  cert issuer     %s\n"+
		"  cert serial     %s\n"+
		"  cert validity   %s .. %s\n"+
		"  cert sha256     %s\n"+
		"  rekor entry     %s\n"+
		"  rekor logIndex  %d  integrated %s\n"+
		"  inclusion proof treeSize=%d rootHash=%s hashes=%d\n"+
		"  checkpoint      %s\n"+
		"  gitsign verify:\n%s",
		res.CommitSHA, strings.Join(got, " | "),
		res.Certificate.SPIFFEID, res.Certificate.Issuer, res.Certificate.SerialNumber,
		res.Certificate.NotBefore.Format(time.RFC3339),
		res.Certificate.NotAfter.Format(time.RFC3339),
		res.Certificate.Fingerprint,
		res.Rekor.UUID, res.Rekor.LogIndex, res.Rekor.IntegratedAt.Format(time.RFC3339),
		entry.Verification.InclusionProof.TreeSize,
		entry.Verification.InclusionProof.RootHash,
		len(entry.Verification.InclusionProof.Hashes),
		strings.TrimSpace(entry.Verification.InclusionProof.Checkpoint),
		strings.TrimSpace(v.Output))
}

// ---------------------------------------------------------------------------
// SIG-005 — an expired SVID at signing time.
//
// doc 07: "Transparent re-fetch; if re-fetch blocked, signing fails — never
// signs with expired credential (assert cert validity window)". IP §6.2.
// ---------------------------------------------------------------------------

func TestSIG005ExpiredSVIDAtSigningTime(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// A short-lived credential, minted for real: SPIRE honours a 30s TTL, so
	// its expiry is a fact about a token rather than a field we set. The
	// wrapper's default refusal margin is longer than that, so the margin is
	// narrowed here — MinValidity is configuration, and narrowing it is the
	// only way to exercise expiry without spending ten minutes per case.
	shortTTL := 30 * time.Second
	shortConfig := func() Config {
		cfg := harnessConfig(s)
		cfg.MinValidity = 2 * time.Second
		return cfg
	}

	t.Run("re-fetch blocked: signing fails and no commit object is created", func(t *testing.T) {
		claim := newRunClaim(t, "rm-032")
		first, err := s.mintJWTSVID(ctx, claim.Identity, shortTTL)
		if err != nil {
			t.Fatalf("minting: %v", err)
		}
		blocked := errors.New("get_credential is unreachable")
		src := &scriptedSource{steps: []func() (Credential, error){
			staticStep(first),
			errorStep(blocked),
		}}

		// The clock, not a sleep: this arm's claim is that nothing reaches
		// Fulcio at all, so what has to be modelled is our own view of the
		// credential's expiry and nothing else. The arm below, whose claim IS
		// about Fulcio, waits for real.
		clock := &fakeClock{now: time.Now().UTC()}
		cfg := shortConfig()
		cfg.Now = clock.Now
		signer := newHarnessSigner(t, cfg, src)
		repo := newRepo(t)

		if _, serr := signer.Sign(ctx, Request{
			Repo: repo, Message: "SIG-005: the first commit",
			AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
		}); serr != nil {
			t.Fatalf("the first Sign, with a live credential: %v", serr)
		}
		head := gitOut(t, repo, "rev-parse", "HEAD")
		commitsBefore := countCommitObjects(t, repo)

		// The credential expires mid-run.
		clock.now = first.ExpiresAt.Add(time.Second)
		stageMore(t, repo, "second.txt", "second\n")

		_, err = signer.Sign(ctx, Request{
			Repo: repo, Message: "SIG-005: must never be signed",
			AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
		})
		if err == nil {
			t.Fatal("Sign succeeded with an expired credential and a blocked re-fetch")
		}
		if !errors.Is(err, ErrCredentialUnavailable) {
			t.Errorf("Sign error = %v, want it to wrap ErrCredentialUnavailable", err)
		}
		if !errors.Is(err, blocked) {
			t.Errorf("Sign error = %v, want it to wrap the source's own failure", err)
		}
		// The re-fetch was attempted — "transparent re-fetch", not "give up".
		if src.calls != 2 {
			t.Errorf("the source was called %d times, want 2: the expired credential "+
				"must trigger a re-fetch before signing blocks", src.calls)
		}
		// IP §6.3's shape, applied to §6.2's cause: no commit object at all.
		if got := countCommitObjects(t, repo); got != commitsBefore {
			t.Errorf("the repository holds %d commit objects, held %d before the "+
				"refused signature", got, commitsBefore)
		}
		if got := gitOut(t, repo, "rev-parse", "HEAD"); got != head {
			t.Errorf("HEAD moved to %s from %s", got, head)
		}
	})

	t.Run("re-fetch succeeds: the commit is signed under a fresh certificate", func(t *testing.T) {
		claim := newRunClaim(t, "rm-032")
		first, err := s.mintJWTSVID(ctx, claim.Identity, shortTTL)
		if err != nil {
			t.Fatalf("minting: %v", err)
		}
		second, err := s.mintJWTSVID(ctx, claim.Identity, 10*time.Minute)
		if err != nil {
			t.Fatalf("minting: %v", err)
		}
		src := &scriptedSource{steps: []func() (Credential, error){
			staticStep(first), staticStep(second),
		}}
		// REAL TIME, deliberately. This arm's assertion is that the second
		// certificate was issued after the first credential died, and that is
		// only a fact if the first credential really died — a fake clock would
		// let the case pass while gitsign happily reused a live token.
		signer := newHarnessSigner(t, shortConfig(), src)
		repo := newRepo(t)

		one, err := signer.Sign(ctx, Request{
			Repo: repo, Message: "SIG-005: before expiry",
			AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
		})
		if err != nil {
			t.Fatalf("the first Sign: %v", err)
		}

		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Until(first.ExpiresAt.Add(2 * time.Second))):
		}
		stageMore(t, repo, "second.txt", "second\n")

		two, err := signer.Sign(ctx, Request{
			Repo: repo, Message: "SIG-005: after a transparent re-fetch",
			AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
		})
		if err != nil {
			t.Fatalf("the second Sign, after the credential expired: %v", err)
		}
		if src.calls != 2 {
			t.Errorf("the source was called %d times, want 2", src.calls)
		}
		if one.Certificate.SerialNumber == two.Certificate.SerialNumber {
			t.Errorf("both commits carry certificate %s; the re-fetch produced no new one",
				one.Certificate.SerialNumber)
		}
		// The assertion doc 07 names: the certificate validity window. Fulcio
		// stamps NotBefore with its own clock at issuance, so a certificate
		// whose window opens after the first credential's expiry cannot have
		// been bought with that credential — the third case below shows what
		// happens when one tries.
		if !two.Certificate.NotBefore.After(first.ExpiresAt) {
			t.Errorf("the second certificate is valid from %s, and the first "+
				"credential expired at %s. That certificate could have been "+
				"issued to the expired credential.",
				two.Certificate.NotBefore, first.ExpiresAt)
		}
		if one.Certificate.NotAfter.Before(one.Certificate.NotBefore) {
			t.Errorf("the first certificate's window runs backwards: %s..%s",
				one.Certificate.NotBefore, one.Certificate.NotAfter)
		}
		if _, err := signer.Verify(ctx, repo, two.CommitSHA, claim.Identity); err != nil {
			t.Errorf("gitsign verify on the re-signed commit: %v", err)
		}
	})

	t.Run("the guard bites: a genuinely expired token is refused by Fulcio", func(t *testing.T) {
		// This is what makes the two cases above worth something. The guard
		// refuses before gitsign runs, so nothing above ever observes what an
		// expired credential would actually do. Here the guard is deliberately
		// fooled with a clock that lies, and the answer comes from Fulcio: an
		// expired JWT-SVID buys no certificate, and no commit object appears.
		claim := newRunClaim(t, "rm-032")
		cred, err := s.mintJWTSVID(ctx, claim.Identity, 5*time.Second)
		if err != nil {
			t.Fatalf("minting: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Until(cred.ExpiresAt.Add(2 * time.Second))):
		}

		lying := &fakeClock{now: cred.ExpiresAt.Add(-time.Hour)}
		cfg := shortConfig()
		cfg.Now = lying.Now
		signer := newHarnessSigner(t, cfg, &scriptedSource{
			steps: []func() (Credential, error){staticStep(cred)},
		})
		repo := newRepo(t)
		commitsBefore := countCommitObjects(t, repo)

		_, err = signer.Sign(ctx, Request{
			Repo: repo, Message: "SIG-005: signed with an expired token",
			AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
		})
		if err == nil {
			t.Fatal("Fulcio issued a certificate for an expired JWT-SVID")
		}
		// The refusal must come from FULCIO, not from our own guard — that is
		// the whole point of fooling the clock. MEASURED: Fulcio answers the
		// v1 signingCert endpoint with 400 and "There was an error processing
		// the identity token".
		if !errors.Is(err, ErrSigning) {
			t.Fatalf("Sign error = %v, want it to wrap ErrSigning: with the guard "+
				"fooled the attempt must reach Fulcio and be refused there", err)
		}
		if !strings.Contains(err.Error(), "error processing the identity token") {
			t.Errorf("Sign error = %v, want Fulcio's refusal of the expired token", err)
		}
		if got := countCommitObjects(t, repo); got != commitsBefore {
			t.Errorf("the repository holds %d commit objects, held %d before the "+
				"failed signature", got, commitsBefore)
		}
	})
}

// ---------------------------------------------------------------------------
// SIG-008 — the same credential, reused for a second commit within validity.
//
// doc 07: "Allowed; both commits verify independently". IP §6.2's replay rule:
// "same JWT-SVID used for a second sign_commit after the first succeeded ->
// allowed only within validity and same run".
// ---------------------------------------------------------------------------

func TestSIG008SameRunCredentialReusedForASecondCommit(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	claim := newRunClaim(t, "rm-032")
	cred, err := s.mintJWTSVID(ctx, claim.Identity, 10*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	// Exactly one credential is on offer. A second call is a failure, which is
	// how "reused" is proved rather than asserted.
	src := &scriptedSource{steps: []func() (Credential, error){staticStep(cred)}}
	signer := newHarnessSigner(t, harnessConfig(s), src)
	repo := newRepo(t)

	one, err := signer.Sign(ctx, Request{
		Repo: repo, Message: "SIG-008: the first commit",
		AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
	})
	if err != nil {
		t.Fatalf("the first Sign: %v", err)
	}
	stageMore(t, repo, "second.txt", "second\n")
	two, err := signer.Sign(ctx, Request{
		Repo: repo, Message: "SIG-008: the second commit, same credential",
		AuthorName: testAuthorName, AuthorEmail: testAuthorEmail, Claim: claim,
	})
	if err != nil {
		t.Fatalf("the second Sign, reusing the credential within validity: %v", err)
	}

	if src.calls != 1 {
		t.Errorf("the source was called %d times, want 1: a credential still "+
			"within validity must be reused, not re-minted", src.calls)
	}
	if one.CommitSHA == two.CommitSHA {
		t.Fatalf("both Signs reported commit %s", one.CommitSHA)
	}
	// E8: gitsign generates the key and discards it. A wrapper that cached one
	// would produce the same certificate twice.
	if one.Certificate.Fingerprint == two.Certificate.Fingerprint {
		t.Errorf("both commits are signed under certificate %s. gitsign mints a "+
			"fresh ephemeral key per signature; an identical certificate means "+
			"one was held (E8).", one.Certificate.Fingerprint)
	}

	// Both verify INDEPENDENTLY: each at its own revision, each against its own
	// Rekor entry, and neither entry is the other's.
	for _, c := range []Result{one, two} {
		if _, err := signer.Verify(ctx, repo, c.CommitSHA, claim.Identity); err != nil {
			t.Errorf("gitsign verify %s: %v", c.CommitSHA, err)
		}
		entry, body := readRekorEntry(t, s, c.Rekor.UUID)
		assertEntryIsForCommit(t, body, c.CommitSHA, c.Certificate.Fingerprint)
		assertInclusionProof(t, s, entry, c.Rekor.UUID, body)
	}
	if one.Rekor.UUID == two.Rekor.UUID {
		t.Errorf("both commits point at Rekor entry %s", one.Rekor.UUID)
	}
}

// fakeClock is an injectable time source. Real expiry is proved with real
// waiting in the third SIG-005 case; the clock exists so the other two do not
// have to spend a credential lifetime sleeping.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
