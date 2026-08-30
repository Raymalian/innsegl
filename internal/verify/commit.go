// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Reading a commit, and the certificate inside its signature.
//
// git is the reader, through `cat-file`. A verifier that parsed loose objects
// itself would be reimplementing the one component whose object format is not
// in question, and `git cat-file` is the same plumbing that produced the SHA
// this whole verification is keyed on.

// gitTimeout bounds one git invocation. Reading an object is local and fast;
// the bound exists so a repository on a wedged filesystem fails rather than
// hangs.
const gitTimeout = 30 * time.Second

// commit is the part of a commit object this package reads.
type commit struct {
	// SHA is the object name — the artifact the transparency log is keyed on.
	SHA string
	// Tree is the tree the commit points at. VER-003's recovery walks it.
	Tree string
	// Message is everything after the header block, trailers included.
	Message string
	// Signature is the PEM payload of the `gpgsig` header, unfolded. Empty
	// when the commit is not signed at all.
	Signature []byte
}

// runGit runs one read-only git command in repo.
//
// The environment is INHERITED, which is the opposite of what ADR-0028 decided
// for the signing side, and deliberately so. There the ambient configuration
// was a risk because it ends up in the bytes that get signed; here nothing is
// written and nothing is signed, and a verifier that scrubbed its environment
// could not be told that a bind-mounted repository is safe to read
// (`safe.directory`) — which is exactly how VER-001 runs it.
func runGit(ctx context.Context, gitPath, repo string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	// The binary is this verifier's own configuration and the arguments are
	// built here, never taken from the commit: the only caller-supplied value
	// that reaches git is a revision, and it is passed after --end-of-options
	// so it cannot become a flag.
	//nolint:gosec // G204: gitPath is configuration, the arguments are literals
	cmd := exec.CommandContext(ctx, gitPath, append([]string{"-C", repo}, args...)...)
	cmd.Env = os.Environ()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// readCommit resolves a revision and reads the object behind it.
func readCommit(ctx context.Context, gitPath, repo, revision string) (commit, error) {
	sha, err := runGit(ctx, gitPath, repo, "rev-parse", "--verify", "--end-of-options",
		revision+"^{commit}")
	if err != nil {
		return commit{}, fmt.Errorf("%w: %q in %s: %w", ErrRevision, revision, repo, err)
	}
	sha = strings.TrimSpace(sha)
	object, err := runGit(ctx, gitPath, repo, "cat-file", "commit", sha)
	if err != nil {
		return commit{}, fmt.Errorf("%w: reading %s: %w", ErrRevision, sha, err)
	}
	c := parseCommitObject(object)
	c.SHA = sha
	return c, nil
}

// parseCommitObject splits a raw commit object into its headers and message.
//
// A header's continuation lines are indented by exactly one space and the
// header block ends at the first empty line — git's own rule, and the only
// thing about the object this function interprets.
func parseCommitObject(object string) commit {
	var c commit
	lines := strings.Split(object, "\n")
	for i, line := range lines {
		if line == "" {
			c.Message = strings.Join(lines[i+1:], "\n")
			break
		}
		if strings.HasPrefix(line, " ") {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "tree":
			c.Tree = value
		case "gpgsig":
			c.Signature = []byte(unfold(value, lines[i+1:]))
		}
	}
	return c
}

// unfold rebuilds a folded header value: the first line, then every following
// line that begins with one space, with that space removed.
func unfold(first string, rest []string) string {
	var b strings.Builder
	b.WriteString(first)
	b.WriteString("\n")
	for _, line := range rest {
		if !strings.HasPrefix(line, " ") {
			break
		}
		b.WriteString(line[1:])
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The certificate inside the signature.
// ---------------------------------------------------------------------------

// cmsContentInfo is RFC 5652 §3's outer wrapper.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// cmsSignedData is RFC 5652 §5.1, read only as far as the certificates. Go's
// encoding/asn1 tolerates trailing elements in a SEQUENCE, so the crls and
// signerInfos after this are left alone: they are the signature's business,
// and this package does not verify signatures it did not have to.
type cmsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

// commitCertificate returns the signing certificate and the rest of the chain
// carried in the commit's `gpgsig` header.
//
// This is a STRUCTURE WALK and nothing more — it verifies no signature and
// trusts nothing it reads. Threat model §5.4 warns about hand-written ASN.1
// and this is the second such reader in the repository; ADR-0034 records why
// there was no way to have none, and what stands in for the CMS verification
// this deliberately does not do.
func commitCertificate(signature []byte) (*x509.Certificate, []*x509.Certificate, error) {
	if len(signature) == 0 {
		return nil, nil, fmt.Errorf("the commit object carries no gpgsig header, so it is " +
			"not signed: the trailers claim an identity that nothing proves")
	}
	block, _ := pem.Decode(signature)
	if block == nil {
		return nil, nil, fmt.Errorf("the commit's signature is not PEM")
	}
	if block.Type != "SIGNED MESSAGE" {
		return nil, nil, fmt.Errorf("the commit's signature is a %q block, not a CMS "+
			"SIGNED MESSAGE; this system signs with gitsign", block.Type)
	}
	var outer cmsContentInfo
	if _, err := asn1.Unmarshal(block.Bytes, &outer); err != nil {
		return nil, nil, fmt.Errorf("the signature is not a CMS ContentInfo: %w", err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil {
		return nil, nil, fmt.Errorf("the CMS content is not a SignedData: %w", err)
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("the CMS certificate set does not parse: %w", err)
	}
	for i, c := range certs {
		if !c.IsCA && len(c.URIs) > 0 {
			return c, append(append([]*x509.Certificate{}, certs[:i]...), certs[i+1:]...), nil
		}
	}
	return nil, nil, fmt.Errorf("none of the %d certificates in the signature is a leaf "+
		"with a URI SAN; a commit this system signed is attributed by that SAN", len(certs))
}

// describeCertificate renders the fields a report shows.
func describeCertificate(cert *x509.Certificate) CertificateInfo {
	return CertificateInfo{
		SPIFFEID:     uriSANOf(cert),
		Issuer:       fulcioIssuerOf(cert),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC(),
		NotAfter:     cert.NotAfter.UTC(),
		Fingerprint:  fingerprintOf(cert),
	}
}

func uriSANOf(cert *x509.Certificate) string {
	if len(cert.URIs) == 0 {
		return ""
	}
	return cert.URIs[0].String()
}

// Fulcio's OIDC-issuer extensions, from its oid-info.md. .8 is the current
// spelling (a DER UTF8String), .1 the deprecated raw one.
var (
	oidFulcioIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

func fulcioIssuerOf(cert *x509.Certificate) string {
	var deprecated string
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidFulcioIssuerV2):
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
				return s
			}
		case ext.Id.Equal(oidFulcioIssuerV1):
			deprecated = string(ext.Value)
		}
	}
	return deprecated
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
