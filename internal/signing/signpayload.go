// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: git's commit object id is SHA-1 by definition; this computes git's id, not a security digest
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// SignPayload — RM-241 (#386), ADR-0059 decision 4 Phase B.
//
// # What this is, and why it exists beside Sign
//
// Sign (gitsign.go) orchestrates gitsign THROUGH `git commit`: the caller's
// working tree is staged, git builds the commit object itself, and gitsign is
// invoked as git's own child. That is RM-032's whole premise (ADR-0031
// decision 1), and it requires the component doing the signing to be the
// component that ran `git commit`.
//
// ADR-0059 breaks that premise on purpose. The harness runs `git commit`
// itself, on the operator's machine; this deployment never does. What reaches
// the core instead is the UNSIGNED COMMIT OBJECT git already built — the exact
// bytes git hands its `gpg.x509.program` on stdin — plus the argv git invoked
// that program with. SignPayload signs THAT, and it is the one Phase B can be
// for a commit this process never created: gitsign runs once, directly, on the
// bytes it is given, and everything downstream (the commit SHA, the
// certificate, the Rekor entry) is read back from those same bytes rather
// than from a repository this process has no path to.
//
// # The discipline is Sign's, unchanged
//
// Trust material is fetched fresh for this call (trustMaterial — also the
// reachability probe, ADR-0031 decision 2). The child's environment is built
// from nothing, never inherited (baseEnv, decision 3, E8): PATH, HOME, the
// trust anchors, and SIGSTORE_ID_TOKEN, and nothing of this process's own
// environment. The credential is fetched and checked exactly as Sign checks
// it (s.credential, which calls checkCredential) — the same cache, the same
// re-fetch-before-drop ordering, the same IP §6.2 refusal of an unusable
// token. The certificate that comes back is held to the claim exactly as
// Sign holds it (checkCertificate), and the Rekor entry is FOUND, never read
// off a subprocess's prose (findRekorEntry, decision 6). Nothing here
// touches a private key: gitsign generates one, signs, and discards it,
// exactly as it does when git drives it.
//
// # What is different, and why
//
// There is no `git commit` to run, so there is no working tree, no message
// file, and no read-back through `git cat-file`. Two things replace it:
//
//  1. gitsign is invoked DIRECTLY, with git's own argv (PayloadRequest.Args)
//     and the payload on stdin — the same contract git itself uses with any
//     `gpg.x509.program` (see runGitsign). Its stdout is the signature and
//     its status-fd is read separately, because a caller of this file's own
//     caller (cmd/innsegl/commitsign.go) has to hand BOTH back to git,
//     exactly as git would have received them from gitsign directly.
//  2. The resulting commit SHA is COMPUTED, not read off a repository that
//     does not hold the object yet. Git's construction of a signed commit
//     from an unsigned one is fixed and public — insert a `gpgsig` header
//     built from the signature, immediately before the blank line that ends
//     the header block, and hash the result as a git object
//     ("commit <len>\0" + body). commitSHAOf does exactly that arithmetic
//     and nothing else; TestSIGPAYLOAD001ComputedSHAMatchesGit proves it
//     against a real `git commit` and a real gpg.x509.program, not against
//     this package's own idea of what git does.

// ErrPayload is a payload this wrapper will not sign: not a well-formed,
// SHA-1 git commit object, or a SHA-256 one (see ParseCommitPayload).
var ErrPayload = fmt.Errorf("signing: the payload is not a SHA-1 commit object this wrapper can sign")

// PayloadRequest is one payload to be signed — ADR-0059 decision 4 Phase B's
// argument.
type PayloadRequest struct {
	// Args is git's own `gpg.x509.program` argv, forwarded verbatim from the
	// signing client that received it (ADR-0059 decision 3). This wrapper
	// interprets only `--status-fd=<n>`, to know which descriptor gitsign's
	// structured status lines land on; every other argument is handed to
	// gitsign exactly as git supplied it.
	Args []string
	// Payload is the unsigned commit object git handed its signing program on
	// stdin: tree, parent(s), author, committer, a blank line, the message —
	// with its trailers already placed by ADR-0059 decision 2. This wrapper
	// stages nothing and builds nothing; it signs exactly these bytes.
	Payload []byte
	// Claim is what the trailers already IN Payload assert. It is not
	// rendered here — decision 4 gate 2 (internal/mcp) has already read the
	// trailers back out of Payload and required them to be this claim's own
	// before Phase B is ever reached — but it is what the credential and the
	// certificate are checked against, exactly as Sign checks them.
	Claim Claim
}

// PayloadResult is what Phase B produced.
type PayloadResult struct {
	// Signature is gitsign's stdout: the CMS signature, PEM-armored, exactly
	// as git itself would have received it from `gpg.x509.program`.
	Signature []byte
	// Status is whatever gitsign wrote to the status-fd PayloadRequest.Args
	// named — the structured "[GNUPG:] SIG_CREATED …" lines git itself reads
	// to decide the signing operation succeeded. A caller of this file's own
	// caller hands this back on the SAME descriptor git originally asked for,
	// so that from git's side this looks exactly like gitsign answered
	// directly.
	Status []byte
	// CommitSHA is the commit id git will compute once it inserts Signature
	// into Payload's header block — see commitSHAOf.
	CommitSHA string
	// Object is that signed commit object's bytes, whose id is CommitSHA.
	Object []byte
	// Certificate and Rekor are read back exactly as Sign reads them: the
	// certificate out of the signature itself (never asked of Fulcio a
	// second time), the Rekor entry FOUND by artifact hash and certificate
	// (never parsed from a subprocess's prose).
	Certificate Certificate
	Rekor       RekorEntry
	// CredentialSPIFFEID and CredentialExpires say which credential was
	// used. THE TOKEN IS DELIBERATELY ABSENT — see Result's identical
	// comment; the reasoning does not change because the caller changed.
	CredentialSPIFFEID string
	CredentialExpires  time.Time
}

// ParsedCommit is a git commit object's header fields, read without
// interpreting anything else about it: not a diff, not a signature, not a
// verification. It is intentionally exported so that ADR-0059 decision 4's
// gates (internal/mcp/signpayload.go) read the SAME parse this file computes
// the signed SHA from, rather than a second implementation of git's object
// grammar growing beside it — threat model §5.4's "one parser" rule, applied
// here as it is everywhere else in this codebase that reads a git object
// (internal/api's rederive, internal/reconciler's writes).
type ParsedCommit struct {
	// Tree is the object id the `tree` header names, unvalidated further than
	// "40 lowercase hex characters" — this deployment signs SHA-1
	// object-format repositories only; see ParseCommitPayload.
	Tree string
	// Parents is every `parent` header, in the order the payload carries
	// them. Empty for a root commit.
	Parents []string
	// AuthorEmail and CommitterEmail are read out of the bracketed <email> of
	// the `author` and `committer` header lines, and AuthorName and
	// CommitterName are the display names before them. ADR-0059 decision 4
	// gate 3 holds each pair to the I6 author policy: an operator address is
	// admitted only with the name pinned to it (GH-006).
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	// Message is everything after the header block's terminating blank line
	// — the commit message, trailers included, exactly as the payload
	// carries it.
	Message string
}

// sha256TreeHexLen is the length of a SHA-256 object id in hex. A `tree`
// header this long names a SHA-256 repository, which this wrapper refuses
// rather than mis-signs: the commit-SHA arithmetic below is SHA-1 only
// (git's object hash for a sha256-object-format repository is computed the
// same way over the same bytes, but with a different digest — mixing the two
// up would silently compute the wrong id for HALF of doc 02's deployments).
const sha256TreeHexLen = 64

// ParseCommitPayload parses the unsigned commit object git hands its signing
// program: everything up to the first blank line is the header block (tree,
// parent(s), author, committer — in whatever order and whatever other
// headers the payload carries; only these four kinds are read), and
// everything after it is the message, verbatim.
//
// A SHA-256 payload (a 64-character `tree`) is refused by name rather than
// silently mis-signed — see sha256TreeHexLen.
func ParseCommitPayload(payload []byte) (ParsedCommit, error) {
	s := string(payload)
	idx := strings.Index(s, "\n\n")
	if idx < 0 {
		return ParsedCommit{}, fmt.Errorf(
			"%w: no blank line separates the header block from the message", ErrPayload)
	}
	header, message := s[:idx], s[idx+2:]

	var p ParsedCommit
	for _, line := range strings.Split(header, "\n") {
		switch {
		case strings.HasPrefix(line, "tree "):
			if p.Tree != "" {
				return ParsedCommit{}, fmt.Errorf("%w: more than one tree header", ErrPayload)
			}
			p.Tree = strings.TrimPrefix(line, "tree ")
		case strings.HasPrefix(line, "parent "):
			p.Parents = append(p.Parents, strings.TrimPrefix(line, "parent "))
		case strings.HasPrefix(line, "author "):
			name, email, err := identityOfHeaderLine(line, "author ")
			if err != nil {
				return ParsedCommit{}, err
			}
			p.AuthorName, p.AuthorEmail = name, email
		case strings.HasPrefix(line, "committer "):
			name, email, err := identityOfHeaderLine(line, "committer ")
			if err != nil {
				return ParsedCommit{}, err
			}
			p.CommitterName, p.CommitterEmail = name, email
		}
	}

	switch {
	case p.Tree == "":
		return ParsedCommit{}, fmt.Errorf("%w: no tree header", ErrPayload)
	case len(p.Tree) == sha256TreeHexLen:
		return ParsedCommit{}, fmt.Errorf(
			"%w: the tree is %d hex characters, which names a SHA-256 object-format "+
				"repository; this wrapper computes a SHA-1 commit id only and refuses "+
				"rather than mis-signs one", ErrPayload, len(p.Tree))
	case !isHexObjectID(p.Tree, 40):
		return ParsedCommit{}, fmt.Errorf(
			"%w: the tree %q is not a 40-character lowercase hex object id", ErrPayload, p.Tree)
	}
	for _, parent := range p.Parents {
		if !isHexObjectID(parent, 40) {
			return ParsedCommit{}, fmt.Errorf(
				"%w: parent %q is not a 40-character lowercase hex object id", ErrPayload, parent)
		}
	}
	if p.AuthorEmail == "" {
		return ParsedCommit{}, fmt.Errorf("%w: no author header, or it carries no <email>", ErrPayload)
	}
	if p.CommitterEmail == "" {
		return ParsedCommit{}, fmt.Errorf("%w: no committer header, or it carries no <email>", ErrPayload)
	}

	p.Message = message
	return p, nil
}

// identityOfHeaderLine reads the display name and the bracketed <email> out
// of an `author` or `committer` header line. The name can contain almost
// anything, including a literal "<", so only the LAST bracket pair on the
// line is trusted — the pair git itself writes the address into — and the
// name is everything before it, trimmed. The name is compared, never parsed.
func identityOfHeaderLine(line, prefix string) (name, email string, err error) {
	rest := strings.TrimPrefix(line, prefix)
	open := strings.LastIndexByte(rest, '<')
	if open < 0 {
		return "", "", fmt.Errorf("%w: %q carries no <email>", ErrPayload, line)
	}
	closeIdx := strings.IndexByte(rest[open:], '>')
	if closeIdx < 0 {
		return "", "", fmt.Errorf("%w: %q carries an unterminated <email>", ErrPayload, line)
	}
	return strings.TrimSpace(rest[:open]), rest[open+1 : open+closeIdx], nil
}

func isHexObjectID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// SignPayload signs an already-built, unsigned commit object — ADR-0059
// decision 4 Phase B. See the package-level comment above for how this
// differs from Sign and what discipline the two share.
func (s *Signer) SignPayload(ctx context.Context, req PayloadRequest) (PayloadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(req.Payload) == 0 {
		return PayloadResult{}, fmt.Errorf("%w: no payload", ErrConfig)
	}
	if _, err := ParseCommitPayload(req.Payload); err != nil {
		return PayloadResult{}, err
	}

	// 1. A live credential for THIS run, re-fetched if the cached one died —
	//    the identical call Sign makes, checked the identical way.
	cred, err := s.credential(ctx, req.Claim)
	if err != nil {
		return PayloadResult{}, err
	}

	// 2. Sigstore's trust material, which is also the reachability probe.
	trust, err := s.trustMaterial(ctx)
	if err != nil {
		return PayloadResult{}, err
	}

	// 3. The signature. gitsign is invoked directly, on git's own argv, with
	//    the payload on stdin — see runGitsign.
	env := append(s.baseEnv(trust), "SIGSTORE_ID_TOKEN="+cred.Token)
	signature, status, err := s.runGitsign(ctx, env, req.Args, req.Payload)
	if err != nil {
		return PayloadResult{}, fmt.Errorf("%w: %w", ErrSigning, err)
	}

	// 4. The commit SHA git itself will compute once it inserts this
	//    signature into the payload's header block.
	object, commitSHA, err := signedCommitOf(req.Payload, signature)
	if err != nil {
		return PayloadResult{}, err
	}

	// 5. Read back what was produced. From here on a failure means a
	//    signature now exists that cannot be attributed, which is an
	//    invariant violation rather than a retryable outage — the identical
	//    reasoning Sign applies to its own read-back.
	certs, err := certificatesFromSignature(signature)
	if err != nil {
		return PayloadResult{}, err
	}
	cert, err := leafOf(certs)
	if err != nil {
		return PayloadResult{}, err
	}
	if cerr := s.checkCertificate(cert, req.Claim, cred); cerr != nil {
		return PayloadResult{}, cerr
	}
	entry, err := findRekorEntry(ctx, s.cfg.HTTPClient, s.cfg.RekorURL, commitSHA, cert)
	if err != nil {
		return PayloadResult{}, err
	}

	return PayloadResult{
		Signature:          signature,
		Status:             status,
		CommitSHA:          commitSHA,
		Object:             object,
		Certificate:        describeCertificate(cert),
		Rekor:              entry,
		CredentialSPIFFEID: cred.SPIFFEID,
		CredentialExpires:  cred.ExpiresAt,
	}, nil
}

// statusFD reads `--status-fd=<n>` out of git's own argv. gitsign, invoked as
// any gpg replacement, writes its structured "[GNUPG:] …" status lines to
// whichever descriptor this names; everything else in the argv is opaque to
// this wrapper and passed through untouched.
func statusFD(args []string) (int, bool) {
	for _, a := range args {
		v, ok := strings.CutPrefix(a, "--status-fd=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err == nil && n >= 0 {
			return n, true
		}
	}
	return 0, false
}

// runGitsign invokes gitsign directly — never through `git commit`, because
// there is no repository this process created the commit in — with the given
// argv and payload, and returns its stdout (the signature) and whatever it
// wrote to the status-fd its argv named, separately.
//
// MEASURED against real git 2.54: signing with a custom `gpg.x509.program`,
// git invokes it as `<program> --status-fd=2 -bsau <name> <email>`, so status
// lands on stderr in the shipped configuration. The general case is handled
// anyway — a status-fd of 3 or higher is served through a pipe passed as an
// extra file descriptor, with any descriptor in between padded from
// /dev/null so the pipe lands on the exact number git's argv named — because
// this wrapper's contract is with whatever argv git handed the signing
// client (PayloadRequest.Args), not with one observed git version's choice.
func (s *Signer) runGitsign(
	ctx context.Context, env []string, args []string, payload []byte,
) (signature, status []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	//nolint:gosec // G204: GitsignPath is resolved once via exec.LookPath at
	// construction (NewSigner), and args is git's own argv (PayloadRequest.Args),
	// forwarded verbatim as argv elements and never passed through a shell.
	cmd := exec.CommandContext(ctx, s.cfg.GitsignPath, args...)
	cmd.Dir = s.workDir
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(payload)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	fd, hasStatusFD := statusFD(args)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	var pipeRead, pipeWrite *os.File
	if hasStatusFD && fd != 2 {
		if fd == 1 {
			return nil, nil, fmt.Errorf(
				"--status-fd=1 would collide with the signature on stdout")
		}
		if fd < 3 {
			return nil, nil, fmt.Errorf("--status-fd=%d is not a descriptor this wrapper can open", fd)
		}
		r, w, perr := os.Pipe()
		if perr != nil {
			return nil, nil, fmt.Errorf("%w: opening a status pipe: %w", ErrConfig, perr)
		}
		pipeRead, pipeWrite = r, w
		defer func() { _ = r.Close() }()
		// Go assigns ExtraFiles[i] to the child's descriptor 3+i, so any
		// descriptor between 3 and fd-1 that git's argv did not ask for is
		// padded with /dev/null, keeping the real pipe at exactly fd.
		for n := 3; n < fd; n++ {
			devnull, oerr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if oerr != nil {
				_ = w.Close()
				return nil, nil, fmt.Errorf("%w: %w", ErrConfig, oerr)
			}
			defer func() { _ = devnull.Close() }()
			cmd.ExtraFiles = append(cmd.ExtraFiles, devnull)
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	}

	// Start, not Run: os/exec's own pipe gotcha, and the reason this is not
	// one call. cmd.Start dup()s pipeWrite into the child; THIS process
	// still holds its own copy of the write end afterward, and os/exec does
	// not close it for us. A read on pipeRead below would then block
	// forever once the child's own copy closes, because ours is still open
	// and EOF requires every writer gone — so our copy is closed explicitly,
	// right after Start, before the read that waits for EOF.
	if startErr := cmd.Start(); startErr != nil {
		if pipeWrite != nil {
			_ = pipeWrite.Close()
		}
		return nil, nil, fmt.Errorf("starting %s: %w", s.cfg.GitsignPath, startErr)
	}
	if pipeWrite != nil {
		_ = pipeWrite.Close()
	}

	var readErr error
	if pipeRead != nil {
		// gitsign's own copy of the write end closes when it exits (or
		// sooner, if it closes the descriptor itself); either way this
		// terminates on EOF rather than hanging on a process that is still
		// running, because ours is already closed above.
		status, readErr = io.ReadAll(pipeRead)
	}

	runErr := cmd.Wait()
	if pipeRead == nil {
		status = stderr.Bytes()
	}

	if runErr != nil {
		return nil, status, fmt.Errorf("%s: %w\n%s",
			strings.Join(append([]string{s.cfg.GitsignPath}, args...), " "),
			runErr, strings.TrimSpace(stderr.String()))
	}
	if readErr != nil {
		return nil, nil, fmt.Errorf("%w: reading the status-fd pipe: %w", ErrConfig, readErr)
	}
	return stdout.Bytes(), status, nil
}

// commitSHAOf computes the commit id git will assign once it inserts
// signature into payload's header block.
//
// Git's own construction, reproduced exactly and nothing more: the `gpgsig`
// header is inserted as the last header line, immediately before the blank
// line that separates the header block from the message — the same position
// gpgsigOf (gitsign.go) reads it back FROM, in the other direction. Its
// first line follows the `gpgsig ` token on the header line itself; every
// further line is indented by exactly one space, git's own continuation
// rule. The resulting bytes are hashed as any git object is:
// sha1("commit " + len(bytes) + NUL + bytes). TestSIGPAYLOAD001 proves this
// against a real `git commit` and a real (fake) gpg.x509.program rather than
// against this comment's say-so.
func commitSHAOf(payload, signature []byte) (string, error) {
	_, sha, err := signedCommitOf(payload, signature)
	return sha, err
}

// signedCommitOf is commitSHAOf's construction, answering the signed commit
// object's bytes as well as its id: the core writes those bytes into its
// mirror (ADR-0065), so the mirror holds the very commit git records.
func signedCommitOf(payload, signature []byte) ([]byte, string, error) {
	idx := bytes.Index(payload, []byte("\n\n"))
	if idx < 0 {
		return nil, "", fmt.Errorf(
			"%w: no blank line separates the header block from the message", ErrPayload)
	}
	header, message := payload[:idx], payload[idx+2:]

	sig := strings.TrimRight(string(signature), "\n")
	if sig == "" {
		return nil, "", fmt.Errorf("%w: gitsign produced no signature on stdout", ErrSignature)
	}
	lines := strings.Split(sig, "\n")

	var body bytes.Buffer
	body.Write(header)
	body.WriteString("\n")
	body.WriteString("gpgsig ")
	body.WriteString(lines[0])
	body.WriteString("\n")
	for _, line := range lines[1:] {
		body.WriteString(" ")
		body.WriteString(line)
		body.WriteString("\n")
	}
	body.WriteString("\n")
	body.Write(message)

	objHeader := "commit " + strconv.Itoa(body.Len()) + "\x00"
	sum := sha1.Sum(append([]byte(objHeader), body.Bytes()...)) //nolint:gosec // G401: git's commit object id is SHA-1 by definition
	return body.Bytes(), hex.EncodeToString(sum[:]), nil
}
