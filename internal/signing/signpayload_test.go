// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSIGPAYLOAD001ComputedSHAMatchesGit is the SHA proof RM-241 (#386)
// requires: real git, a real (fake) gpg.x509.program, and this package's own
// commitSHAOf/ParseCommitPayload run over the EXACT bytes git handed that
// program — never over a payload this test built by hand. Two commits are
// proven: a root commit (no parent header) and a child of it (one parent
// header), because the header-insertion point and the parsed field set both
// depend on that shape.
func TestSIGPAYLOAD001ComputedSHAMatchesGit(t *testing.T) {
	dir := newRepo(t)

	payloadPath := filepath.Join(dir, "captured-payload.raw")
	signaturePath := filepath.Join(dir, "captured-signature.raw")
	fakeProgram := filepath.Join(dir, "fake-gpg-x509-program.sh")
	script := "#!/bin/sh\n" +
		"set -e\n" +
		"cat > " + shellQuote(payloadPath) + "\n" +
		"STATUSFD=2\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in\n" +
		"    --status-fd=*) STATUSFD=\"${a#--status-fd=}\";;\n" +
		"  esac\n" +
		"done\n" +
		"echo '[GNUPG:] SIG_CREATED T 1 8 00 1234567890 TESTKEYID' >&\"$STATUSFD\"\n" +
		"SIG='-----BEGIN SIGNED MESSAGE-----\n" +
		"MIIFAKESIGNATUREFORSIGPAYLOAD001TEST\n" +
		"-----END SIGNED MESSAGE-----'\n" +
		"printf '%s\\n' \"$SIG\" | tee " + shellQuote(signaturePath) + "\n"
	if err := os.WriteFile(fakeProgram, []byte(script), 0o700); err != nil {
		t.Fatalf("writing the fake signing program: %v", err)
	}

	runAndCapture := func(t *testing.T, message string) (head string, payload, signature []byte) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", "-C", dir,
			"-c", "gpg.format=x509",
			"-c", "gpg.x509.program="+fakeProgram,
			"-c", "commit.gpgsign=true",
			"commit", "-m", message, "--cleanup=verbatim", "--no-edit")
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "nonexistent-gitconfig"),
			"GIT_AUTHOR_NAME="+testAuthorName, "GIT_AUTHOR_EMAIL="+testAuthorEmail,
			"GIT_COMMITTER_NAME="+testAuthorName, "GIT_COMMITTER_EMAIL="+testAuthorEmail,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git commit: %v: %s", err, out)
		}
		head = gitOut(t, dir, "rev-parse", "HEAD")
		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("reading the captured payload: %v", err)
		}
		signature, err = os.ReadFile(signaturePath)
		if err != nil {
			t.Fatalf("reading the captured signature: %v", err)
		}
		return head, payload, signature
	}

	verify := func(t *testing.T, head string, payload, signature []byte, wantParents int) {
		t.Helper()
		got, err := commitSHAOf(payload, signature)
		if err != nil {
			t.Fatalf("commitSHAOf: %v", err)
		}
		if got != head {
			t.Fatalf("commitSHAOf computed %s, git itself wrote %s", got, head)
		}
		parsed, err := ParseCommitPayload(payload)
		if err != nil {
			t.Fatalf("ParseCommitPayload: %v", err)
		}
		if parsed.AuthorEmail != testAuthorEmail {
			t.Errorf("parsed author email = %q, want %q", parsed.AuthorEmail, testAuthorEmail)
		}
		if parsed.CommitterEmail != testAuthorEmail {
			t.Errorf("parsed committer email = %q, want %q", parsed.CommitterEmail, testAuthorEmail)
		}
		if len(parsed.Parents) != wantParents {
			t.Errorf("parsed %d parents, want %d", len(parsed.Parents), wantParents)
		}
		wantTree := gitOut(t, dir, "rev-parse", head+"^{tree}")
		if parsed.Tree != wantTree {
			t.Errorf("parsed tree = %q, want %q", parsed.Tree, wantTree)
		}
	}

	t.Run("root commit, no parent header", func(t *testing.T) {
		head, payload, signature := runAndCapture(t, "SIG-PAYLOAD-001: root commit")
		verify(t, head, payload, signature, 0)
	})

	stageMore(t, dir, "second.txt", "more work\n")
	t.Run("child commit, one parent header", func(t *testing.T) {
		head, payload, signature := runAndCapture(t, "SIG-PAYLOAD-001: child commit")
		verify(t, head, payload, signature, 1)
	})
}

// shellQuote wraps a path in single quotes for the fake program's own POSIX
// sh, escaping any single quote the path might carry. Test temp directories
// on this OS do not carry one, but the escape costs nothing and removes the
// assumption.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// ParseCommitPayload — refusals, unit level, no subprocess.
// ---------------------------------------------------------------------------

func TestParseCommitPayloadRefusesWhatItCannotSign(t *testing.T) {
	validHeader := "tree " + strings.Repeat("a", 40) + "\n" +
		"author A <a@example.invalid> 1700000000 +0000\n" +
		"committer A <a@example.invalid> 1700000000 +0000"

	cases := []struct {
		name    string
		payload string
	}{
		{"no blank line", validHeader + "\nmessage, no separator"},
		{"no tree header", "author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"two tree headers", "tree " + strings.Repeat("a", 40) + "\n" +
			"tree " + strings.Repeat("b", 40) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"sha256 tree", "tree " + strings.Repeat("a", 64) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"tree not hex", "tree " + strings.Repeat("z", 40) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"parent not hex", "tree " + strings.Repeat("a", 40) + "\n" +
			"parent " + strings.Repeat("z", 40) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"no author", "tree " + strings.Repeat("a", 40) + "\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"author with no email", "tree " + strings.Repeat("a", 40) + "\n" +
			"author A NoEmail 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"author email unterminated", "tree " + strings.Repeat("a", 40) + "\n" +
			"author A <unterminated 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
		{"committer email unterminated", "tree " + strings.Repeat("a", 40) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <unterminated 1700000000 +0000\n\nmsg\n"},
		{"no committer", validHeader[:strings.LastIndex(validHeader, "\ncommitter")] + "\n\nmsg\n"},
		{"tree of a length that is neither sha1 nor sha256", "tree " + strings.Repeat("a", 39) + "\n" +
			"author A <a@example.invalid> 1700000000 +0000\n" +
			"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCommitPayload([]byte(tc.payload)); !errors.Is(err, ErrPayload) {
				t.Fatalf("ParseCommitPayload(%q) = %v, want an %v", tc.payload, err, ErrPayload)
			}
		})
	}
}

func TestParseCommitPayloadAcceptsAMinimalValidPayload(t *testing.T) {
	payload := "tree " + strings.Repeat("a", 40) + "\n" +
		"parent " + strings.Repeat("b", 40) + "\n" +
		"author Name <author@example.invalid> 1700000000 +0000\n" +
		// A header line this parser does not name at all — git allows more
		// than the four this type reads (encoding, mergetag, an already
		// present gpgsig on an amend). It falls through every case
		// unmatched, which is the branch nothing else in this file reaches.
		"encoding UTF-8\n" +
		"committer Name <committer@example.invalid> 1700000000 +0000\n" +
		"\n" +
		"the message\n"
	got, err := ParseCommitPayload([]byte(payload))
	if err != nil {
		t.Fatalf("ParseCommitPayload: %v", err)
	}
	if got.Tree != strings.Repeat("a", 40) {
		t.Errorf("Tree = %q", got.Tree)
	}
	if len(got.Parents) != 1 || got.Parents[0] != strings.Repeat("b", 40) {
		t.Errorf("Parents = %v", got.Parents)
	}
	if got.AuthorEmail != "author@example.invalid" {
		t.Errorf("AuthorEmail = %q", got.AuthorEmail)
	}
	if got.CommitterEmail != "committer@example.invalid" {
		t.Errorf("CommitterEmail = %q", got.CommitterEmail)
	}
	if got.Message != "the message\n" {
		t.Errorf("Message = %q", got.Message)
	}
}

// ---------------------------------------------------------------------------
// commitSHAOf — unit level.
// ---------------------------------------------------------------------------

func TestCommitSHAOfRefusesAnEmptySignature(t *testing.T) {
	payload := []byte("tree " + strings.Repeat("a", 40) + "\n" +
		"author A <a@example.invalid> 1700000000 +0000\n" +
		"committer A <a@example.invalid> 1700000000 +0000\n\nmsg\n")
	if _, err := commitSHAOf(payload, []byte("\n\n")); !errors.Is(err, ErrSignature) {
		t.Fatalf("commitSHAOf with a blank signature = %v, want %v", err, ErrSignature)
	}
}

func TestCommitSHAOfRefusesAPayloadWithNoHeaderSeparator(t *testing.T) {
	if _, err := commitSHAOf([]byte("no separator here"), []byte("sig")); !errors.Is(err, ErrPayload) {
		t.Fatalf("commitSHAOf with no separator = %v, want %v", err, ErrPayload)
	}
}

// ---------------------------------------------------------------------------
// statusFD — unit level.
// ---------------------------------------------------------------------------

func TestStatusFD(t *testing.T) {
	cases := []struct {
		args   []string
		wantFD int
		wantOK bool
	}{
		{[]string{"--status-fd=2", "-bsau", "x"}, 2, true},
		{[]string{"-bsau", "x"}, 0, false},
		{[]string{"--status-fd=17"}, 17, true},
		{[]string{"--status-fd=not-a-number"}, 0, false},
	}
	for _, tc := range cases {
		fd, ok := statusFD(tc.args)
		if fd != tc.wantFD || ok != tc.wantOK {
			t.Errorf("statusFD(%v) = (%d, %v), want (%d, %v)", tc.args, fd, ok, tc.wantFD, tc.wantOK)
		}
	}
}

// ---------------------------------------------------------------------------
// SignPayload — gate-level refusals that need no Sigstore at all: a
// misconfigured Signer, or a payload SignPayload must refuse before it ever
// touches gitsign or the network.
// ---------------------------------------------------------------------------

func TestSignPayloadRefusesAnEmptyPayload(t *testing.T) {
	s := &Signer{cfg: Config{
		Timeout: time.Second, MinValidity: time.Second, Now: time.Now,
	}, src: staticCredentialSource{}}
	_, err := s.SignPayload(context.Background(), PayloadRequest{})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("SignPayload with no payload = %v, want %v", err, ErrConfig)
	}
}

func TestSignPayloadRefusesAMalformedPayloadBeforeAnyCredentialFetch(t *testing.T) {
	calls := 0
	src := credentialSourceFunc(func(context.Context) (Credential, error) {
		calls++
		return Credential{}, errors.New("must not be called")
	})
	s := &Signer{cfg: Config{
		Timeout: time.Second, MinValidity: time.Second, Now: time.Now,
	}, src: src}
	_, err := s.SignPayload(context.Background(), PayloadRequest{Payload: []byte("not a commit object")})
	if !errors.Is(err, ErrPayload) {
		t.Fatalf("SignPayload with a malformed payload = %v, want %v", err, ErrPayload)
	}
	if calls != 0 {
		t.Fatalf("the credential source was called %d times before the payload was even parsed", calls)
	}
}

// staticCredentialSource and credentialSourceFunc are minimal
// CredentialSource fakes for the gate-level cases above, which never reach
// far enough to need a real one. gitsignintegration_test.go's scriptedSource
// is not reused here: it is built to script SEVERAL calls against a live
// Sigstore round trip, which these cases never make.
type staticCredentialSource struct{}

func (staticCredentialSource) Credential(context.Context) (Credential, error) {
	return Credential{}, errors.New("no credential source configured for this test")
}

type credentialSourceFunc func(context.Context) (Credential, error)

func (f credentialSourceFunc) Credential(ctx context.Context) (Credential, error) { return f(ctx) }

// ---------------------------------------------------------------------------
// CMT-010 (I) — a valid payload, against real SPIRE, real Fulcio, real Rekor,
// the released gitsign: Phase B runs in the core under ADR-0031's child
// environment, and the SHA and Rekor entry it reports are the ones a real
// verifier accepts.
// ---------------------------------------------------------------------------

// TestSIGPAYLOAD002HappyPathAgainstLocalFulcioAndRekor drives SignPayload
// exactly as ADR-0059 decision 4 Phase B would be driven: a payload this test
// builds the way git itself builds one (tree from a real `git write-tree`,
// trailers rendered by RM-031's own CommitMessage), signed with the argv git
// itself uses for a custom gpg.x509.program (measured in
// TestSIGPAYLOAD001ComputedSHAMatchesGit's sibling shell experiment: `git
// --status-fd=2 -bsau "<name> <email>"`). The result is checked three ways
// that do not trust SignPayload's own say-so: the certificate's SAN against
// the claim, the Rekor entry against the log directly (readRekorEntry, the
// same reader SIG-001 uses), and the computed commit SHA by writing the
// reconstructed signed object into the repository's own object database and
// asking the RELEASED gitsign to verify it.
func TestSIGPAYLOAD002HappyPathAgainstLocalFulcioAndRekor(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	claim := newRunClaim(t, "rm-241")
	cred, err := s.mintJWTSVID(ctx, claim.Identity, 10*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	src := &scriptedSource{steps: []func() (Credential, error){staticStep(cred)}}
	signer := newHarnessSigner(t, harnessConfig(s), src)
	repo := newRepo(t)

	tree := gitOut(t, repo, "write-tree")
	message, err := CommitMessage(testAuthorPolicy(), Commit{
		Message:     "CMT-010: a payload signed through the core",
		AuthorEmail: testAuthorEmail,
		Claim:       claim,
	})
	if err != nil {
		t.Fatalf("CommitMessage: %v", err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := "tree " + tree + "\n" +
		"author " + testAuthorName + " <" + testAuthorEmail + "> " +
		ts + " +0000\n" +
		"committer " + testAuthorName + " <" + testAuthorEmail + "> " +
		ts + " +0000\n" +
		"\n" + message
	args := []string{"--status-fd=2", "-bsau", testAuthorName + " <" + testAuthorEmail + ">"}

	before := time.Now().UTC()
	res, err := signer.SignPayload(ctx, PayloadRequest{
		Args:    args,
		Payload: []byte(payload),
		Claim:   claim,
	})
	if err != nil {
		t.Fatalf("SignPayload: %v", err)
	}
	after := time.Now().UTC()

	// 1. The certificate is THIS RUN's.
	if res.Certificate.SPIFFEID != claim.Identity {
		t.Errorf("the certificate's URI SAN is %q, this run is %q",
			res.Certificate.SPIFFEID, claim.Identity)
	}
	if res.Certificate.NotBefore.After(after) || res.Certificate.NotAfter.Before(before) {
		t.Errorf("the certificate is valid %s..%s, which does not cover the signing "+
			"window %s..%s", res.Certificate.NotBefore, res.Certificate.NotAfter, before, after)
	}
	if res.CredentialSPIFFEID != claim.Identity {
		t.Errorf("CredentialSPIFFEID = %q, want %q", res.CredentialSPIFFEID, claim.Identity)
	}

	// 2. The Rekor entry is THIS commit's, read back from the log directly.
	if res.Rekor.UUID == "" || res.Rekor.LogIndex < 0 {
		t.Fatalf("SignPayload reported no Rekor entry: %+v", res.Rekor)
	}
	entry, body := readRekorEntry(t, s, res.Rekor.UUID)
	if entry.LogIndex != res.Rekor.LogIndex {
		t.Errorf("the log says index %d, SignPayload reported %d", entry.LogIndex, res.Rekor.LogIndex)
	}
	assertEntryIsForCommit(t, body, res.CommitSHA, res.Certificate.Fingerprint)

	// 3. The computed SHA is the one a real repository and a real verifier
	//    agree is this signed commit: reconstruct the signed object exactly
	//    as commitSHAOf did, write it into the repository, and ask the
	//    released gitsign to verify it under this run's identity.
	written := writeSignedCommitObject(t, repo, []byte(payload), res.Signature)
	if written != res.CommitSHA {
		t.Fatalf("git assigned %s to the reconstructed object, SignPayload computed %s",
			written, res.CommitSHA)
	}
	if _, err := signer.Verify(ctx, repo, res.CommitSHA, claim.Identity); err != nil {
		t.Fatalf("gitsign verify on the reconstructed commit: %v", err)
	}

	t.Logf("CMT-010 artifact\n"+
		"  commit          %s\n"+
		"  cert URI SAN    %s\n"+
		"  cert validity   %s .. %s\n"+
		"  rekor entry     %s  index %d",
		res.CommitSHA, res.Certificate.SPIFFEID,
		res.Certificate.NotBefore.Format(time.RFC3339), res.Certificate.NotAfter.Format(time.RFC3339),
		res.Rekor.UUID, res.Rekor.LogIndex)
}

// writeSignedCommitObject reconstructs the signed commit object the way
// commitSHAOf computes its id, and writes it into repo's object database with
// `git hash-object -w`, returning the id GIT ITSELF assigned it — an
// independent confirmation of commitSHAOf's arithmetic, from the one program
// whose opinion of a git object id is authoritative.
func writeSignedCommitObject(t *testing.T, repo string, payload, signature []byte) string {
	t.Helper()
	idx := strings.Index(string(payload), "\n\n")
	if idx < 0 {
		t.Fatalf("payload carries no header/message separator")
	}
	header, message := payload[:idx], payload[idx+2:]
	sig := strings.TrimRight(string(signature), "\n")
	lines := strings.Split(sig, "\n")

	var body strings.Builder
	body.Write(header)
	body.WriteString("\ngpgsig " + lines[0] + "\n")
	for _, line := range lines[1:] {
		body.WriteString(" " + line + "\n")
	}
	body.WriteString("\n")
	body.Write(message)

	cmd := exec.CommandContext(t.Context(), "git", "-C", repo,
		"hash-object", "-w", "-t", "commit", "--stdin")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(repo, "nonexistent-gitconfig"))
	cmd.Stdin = strings.NewReader(body.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object -w -t commit: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// SignPayload's own read-back sequence, failure by failure — unit level,
// reusing gitsign_test.go's fixtures (newFakeSigstore, unitSigner, staticSource,
// unitClaim, liveCredential, fakeBinary, testCA.leaf, mustMarshalContentInfo):
// no Docker, no real gitsign, because what is under test is SignPayload's own
// decision at each step, not gitsign's or Fulcio's or Rekor's — the same
// division gitsign_test.go's own package comment draws for Sign.
// ---------------------------------------------------------------------------

// unitPayloadPayload is a minimal, well-formed commit payload: everything
// past ParseCommitPayload in every case below is faked, so its content
// beyond being PARSEABLE does not matter.
func unitPayloadPayload() []byte {
	return []byte("tree " + strings.Repeat("a", 40) + "\n" +
		"author A <a@example.invalid> 1700000000 +0000\n" +
		"committer A <a@example.invalid> 1700000000 +0000\n" +
		"\nmsg\n")
}

// fakeGitsignScript is a POSIX sh script standing in for gitsign: it
// CONSUMES stdin, exactly as a real gitsign does (a script that left the
// payload unread would leave `git commit`'s own pipe to gitsign blocked in
// production), then prints stdout and exits as told.
func fakeGitsignScript(exitCode int, stdout string) string {
	return "cat >/dev/null\n" +
		"printf '%s' " + shellQuote(stdout) + "\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
}

// derImplicitSet wraps content in a DER tag+length header — here always
// tag 0xA0, CMS's `[0] IMPLICIT CertificateSet` (RFC 5652 §5.1). content is
// the concatenated DER of one or more certificates, which is exactly what
// x509.ParseCertificates(sd.Certificates.Bytes) expects back out the other
// side (sigstore.go's certificatesFromSignature).
func derImplicitSet(tag byte, content []byte) []byte {
	n := len(content)
	var lenBytes []byte
	switch {
	case n < 0x80:
		lenBytes = []byte{byte(n)}
	case n < 0x100:
		lenBytes = []byte{0x81, byte(n)}
	default:
		lenBytes = []byte{0x82, byte(n >> 8), byte(n)}
	}
	out := make([]byte, 0, 1+len(lenBytes)+n)
	out = append(out, tag)
	out = append(out, lenBytes...)
	out = append(out, content...)
	return out
}

// armorCertAsSignature builds a minimal, well-formed CMS SIGNED MESSAGE
// carrying exactly one certificate — enough for certificatesFromSignature to
// read it back, whatever leafOf then decides about it. It carries no actual
// signature over anything; nothing downstream of certificatesFromSignature
// checks one (gitsign's business, per gitsign.go's own package comment).
func armorCertAsSignature(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	sd := cmsSignedData{
		Version: 1,
		// A zero-value asn1.RawValue marshals as tag 0, length 0 — a literal
		// End-of-Contents marker (0x00 0x00), which is not a valid DER SET or
		// SEQUENCE and confuses Go's asn1 decoder on the EXPLICITLY tagged
		// wrapper further out, even though some lenient BER readers tolerate
		// it. These two fields are given real, minimal, syntactically valid
		// encodings instead — an empty SET (digest algorithms) and an empty
		// SEQUENCE (encapsulated content info) — even though nothing in this
		// package ever reads either back out of a RawValue field.
		DigestAlgorithms: asn1.RawValue{FullBytes: []byte{0x31, 0x00}},
		EncapContentInfo: asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		Certificates:     asn1.RawValue{FullBytes: derImplicitSet(0xA0, cert.Raw)},
	}
	der, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: contentInfoDER(t, der)})
}

// contentInfoDER wraps a SignedData's DER in a CMS ContentInfo
// (pkcs7-signedData, then the SignedData EXPLICITLY tagged [0]) — the same
// shape gitsign_test.go's mustMarshalContentInfo produces, EXCEPT that
// helper hands content to an asn1.RawValue field annotated
// "explicit,tag:0" and relies on the struct tag to add the wrapper. It does
// not: encoding/asn1 writes a RawValue's FullBytes VERBATIM and ignores the
// field's own tag annotation when marshaling (confirmed against the
// standard library directly), so mustMarshalContentInfo's output has NO
// outer [0] tag at all, and every existing case that uses it only ever
// checks `errors.Is(err, ErrSignature)` — a class certificatesFromSignature
// also returns for the outer unmarshal failing this produces, so the gap is
// invisible to those assertions. It stops being invisible here, because
// TestSignPayloadFailsWhenTheLogHasNoEntryForTheCommit needs
// certificatesFromSignature to actually SUCCEED and hand back a real
// certificate. So the [0] wrapper is built by hand instead — the same
// technique this file already uses for Certificates' own IMPLICIT [0] tag
// (derImplicitSet) — and mustMarshalContentInfo is left exactly as it is:
// it is gitsign_test.go's, not this file's to change, and every case that
// uses it still passes for the class it asserts.
func contentInfoDER(t *testing.T, signedData []byte) []byte {
	t.Helper()
	ci := cmsContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // pkcs7-signedData
		Content:     asn1.RawValue{FullBytes: derImplicitSet(0xA0, signedData)},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return der
}

func TestSignPayloadFailsWhenTheCredentialSourceErrors(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	s.src = staticSource{err: errors.New("get_credential is unreachable")}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("error = %v, want ErrCredentialUnavailable", err)
	}
}

func TestSignPayloadFailsWhenSigstoreIsUnreachable(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	s.src = staticSource{cred: liveCredential()}
	f.server.Close()
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("error = %v, want ErrSigningUnavailable", err)
	}
}

func TestSignPayloadFailsWhenGitsignRefuses(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-refuse", fakeGitsignScript(1, "no signature for you"))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSigning) {
		t.Fatalf("error = %v, want ErrSigning", err)
	}
}

func TestSignPayloadFailsWhenGitsignProducesNoSignature(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-empty", fakeGitsignScript(0, ""))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("error = %v, want ErrSignature", err)
	}
}

func TestSignPayloadFailsWhenGitsignProducesAnUnreadableSignature(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-garbage", fakeGitsignScript(0, "not a signature at all\n"))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("error = %v, want ErrSignature", err)
	}
}

// TestSignPayloadFailsWhenTheSignatureCarriesNoLeafCertificate is leafOf's
// own refusal (TestCertificatesFromSignatureRefusesWhatItCannotRead's "a set
// with no leaf" subtest, gitsign_test.go), reached here through the full
// path a real gitsign's stdout would take: a CMS signature whose only
// certificate is a CA, never a leaf with a URI SAN.
func TestSignPayloadFailsWhenTheSignatureCarriesNoLeafCertificate(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-noleaf", fakeGitsignScript(0, string(armorCertAsSignature(t, ca.cert))))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("error = %v, want ErrSignature", err)
	}
}

// TestSignPayloadFailsWhenTheCertificateIsNotThisRuns mirrors
// TestSignFailsWhenTheCertificateIsNotThisRuns (gitsign_test.go) for
// SignPayload: the real captured signature in testdata carries an identity
// that is not unitClaim()'s, so checkCertificate's identity check refuses it
// — regardless of the fixture's own (long past) validity window, since the
// identity check runs before the expiry check.
func TestSignPayloadFailsWhenTheCertificateIsNotThisRuns(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	armored, err := os.ReadFile(filepath.Join("testdata", "signed-commit.sig.pem"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-otherrun", fakeGitsignScript(0, string(armored)))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err = s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("error = %v, want ErrIdentityMismatch", err)
	}
}

// TestSignPayloadFailsWhenTheLogHasNoEntryForTheCommit is IP §6.3's rule
// read through SignPayload: a certificate that DOES attest this run, over a
// commit the fake Rekor never logged an entry for, is refused rather than
// reported as signed. The leaf is minted fresh (testCA.leaf) with a validity
// window that covers "now", so this is genuinely the Rekor lookup failing
// and nothing about the certificate's own window.
func TestSignPayloadFailsWhenTheLogHasNoEntryForTheCommit(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca) // no entries registered
	leaf := ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-noentry", fakeGitsignScript(0, string(armorCertAsSignature(t, leaf))))
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })
	s.src = staticSource{cred: liveCredential()}
	_, err := s.SignPayload(t.Context(), PayloadRequest{
		Payload: unitPayloadPayload(), Args: []string{"--status-fd=2"}, Claim: unitClaim(),
	})
	if !errors.Is(err, ErrTransparencyUnavailable) {
		t.Fatalf("error = %v, want ErrTransparencyUnavailable", err)
	}
}

// ---------------------------------------------------------------------------
// runGitsign — status-fd handling, unit level, no Sigstore: what is under
// test is the file-descriptor plumbing itself, exercised the same way
// gitsign_test.go's own unit cases exercise git/gitsign plumbing — a fake
// binary and nothing else.
// ---------------------------------------------------------------------------

func TestRunGitsignRefusesStatusFD1(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	_, _, err := s.runGitsign(t.Context(), []string{"PATH=/usr/bin:/bin"},
		[]string{"--status-fd=1"}, []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("error = %v, want a refusal naming the collision with stdout", err)
	}
}

func TestRunGitsignRefusesAStatusFDBelow3ThatIsNot2(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	_, _, err := s.runGitsign(t.Context(), []string{"PATH=/usr/bin:/bin"},
		[]string{"--status-fd=0"}, []byte("payload"))
	if err == nil {
		t.Fatal("want an error for --status-fd=0")
	}
}

// TestRunGitsignServesAHigherStatusFDThroughAPaddedPipe is the general case
// runGitsign's own doc comment promises: MEASURED real git only ever asks
// for fd 2, but this wrapper's contract is with whatever argv it is given
// (PayloadRequest.Args), so a status-fd of 4 — one above the lowest this
// wrapper opens itself — has to work too, with descriptor 3 padded from
// /dev/null so the real pipe lands on exactly the number asked for.
func TestRunGitsignServesAHigherStatusFDThroughAPaddedPipe(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	dir := t.TempDir()
	fake := fakeBinary(t, dir, "gitsign-fd4", "cat >/dev/null\n"+
		"printf 'signature-on-stdout'\n"+
		"echo status-on-fd-4 >&4\n")
	s := unitSigner(t, f, func(c *Config) { c.GitsignPath = fake })

	sig, status, err := s.runGitsign(t.Context(), []string{"PATH=/usr/bin:/bin"},
		[]string{"--status-fd=4"}, []byte("payload"))
	if err != nil {
		t.Fatalf("runGitsign: %v", err)
	}
	if string(sig) != "signature-on-stdout" {
		t.Errorf("signature = %q", sig)
	}
	if !strings.Contains(string(status), "status-on-fd-4") {
		t.Errorf("status = %q, want it to carry what the child wrote to fd 4", status)
	}
}

// TestRunGitsignClosesThePipeWriteEndWhenTheProcessNeverStarts covers
// cmd.Start's own failure with a status-fd pipe already open (pipeWrite !=
// nil at that point) — a gitsign path that does not exist, so exec never
// gets as far as running anything. Without closing pipeWrite here, this
// process would leak the descriptor; the read side is never reached because
// runGitsign returns before attempting it.
func TestRunGitsignClosesThePipeWriteEndWhenTheProcessNeverStarts(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	// NewSigner resolves GitsignPath with exec.LookPath at construction, so
	// the only way to reach cmd.Start's own failure is to break the path
	// AFTER a valid Signer already exists.
	s.cfg.GitsignPath = filepath.Join(t.TempDir(), "no-such-gitsign-binary")
	_, _, err := s.runGitsign(t.Context(), []string{"PATH=/usr/bin:/bin"},
		[]string{"--status-fd=4"}, []byte("payload"))
	if err == nil {
		t.Fatal("want an error: the gitsign binary does not exist")
	}
}

// TestRunGitsignFailsToStartWithNoStatusPipeOpen is the same start failure
// with status on fd 2 (stderr) — no pipe was ever opened, so pipeWrite is
// nil at the point cmd.Start fails, and nothing needs closing.
func TestRunGitsignFailsToStartWithNoStatusPipeOpen(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeSigstore(t, ca)
	s := unitSigner(t, f, nil)
	s.cfg.GitsignPath = filepath.Join(t.TempDir(), "no-such-gitsign-binary")
	_, _, err := s.runGitsign(t.Context(), []string{"PATH=/usr/bin:/bin"},
		[]string{"--status-fd=2"}, []byte("payload"))
	if err == nil {
		t.Fatal("want an error: the gitsign binary does not exist")
	}
}
