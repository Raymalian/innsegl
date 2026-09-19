// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

// `innsegl admin-credential` — the issuing side of #264's repository-scoped
// credential.
//
// # What this is, and deliberately what it is not
//
// A key file and a mint command. No database, no sign-in, no accounts, no
// revocation list. The point of #264 is CLOSING the identity-lifecycle
// listener, which was published with six tools behind it and no caller
// authentication at all (doc 04 AB-13, AB-15); an account service is a
// separate thing that this must not turn into on the way.
//
// What that buys is that the whole issuing side is auditable in one file, and
// that nothing the server does depends on this command being available. What
// it costs is that a credential cannot be withdrawn before it expires, which
// is why the TTL is bounded at fifteen minutes and not configurable upwards.
//
// # Why the signing lives HERE and not in internal/mcp
//
// E8: the MCP holds no key material. `internal/mcp` verifies and cannot sign —
// it holds public keys and the FORMAT, and this command holds the private key
// and does the signing through that format. One definition of what gets signed,
// and a package that cannot be handed a private key because it has nowhere to
// put one.
//
// # Three verbs
//
//	keygen  mint a signing key and add its public half to the key set
//	mint    issue one credential for one repository
//	verify  say why a credential is not admissible (the server never will)

// Exit statuses for `innsegl admin-credential`, continuing cli.go's contract.
const (
	// exitCredentialRefused: a credential was read and is not admissible. The
	// verb `verify` returns it; it is a verdict and not a fault.
	exitCredentialRefused = 18
	// exitCredentialUnusable: the command could not do its job. A key file
	// that will not read, a directory that cannot be written.
	exitCredentialUnusable = 19
)

const (
	// adminCredentialKeyPEMType is the PEM block the key file carries. PKCS#8
	// rather than SEC1, so the file says which algorithm it holds and a reader
	// that is handed the wrong key says so instead of guessing.
	adminCredentialKeyPEMType = "PRIVATE KEY"
	// adminCredentialKeyMode is 0600. The one control on this file is the
	// filesystem, the same control the Fulcio CA key and the Rekor log key
	// have in this deployment.
	adminCredentialKeyMode = 0o600
	// adminCredentialJWKSMode is 0644: the key set is PUBLIC by construction,
	// and the process that reads it runs as a different user from the one that
	// writes it.
	adminCredentialJWKSMode = 0o644
	// adminCredentialTokenIDBytes is the width of `jti`. Sixteen random bytes
	// name an issuance without naming anything about who asked for one.
	adminCredentialTokenIDBytes = 16
)

// adminCredentialCommand dispatches the three verbs.
func adminCredentialCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		adminCredentialUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		adminCredentialUsage(stdout)
		return exitOK
	case "keygen":
		return adminCredentialKeygen(args[1:], stdout, stderr)
	case "mint":
		return adminCredentialMint(args[1:], stdout, stderr)
	case "verify":
		return adminCredentialVerify(args[1:], stdout, stderr)
	default:
		fprintf(stderr, "innsegl admin-credential: unknown verb %q\n\n", args[0])
		adminCredentialUsage(stderr)
		return exitUsage
	}
}

func adminCredentialUsage(w io.Writer) {
	fprintf(w, "innsegl admin-credential - issue the repository-scoped credential the "+
		"identity-lifecycle listener requires\n\n")
	fprintf(w, "Usage:\n  innsegl admin-credential <verb> [flags]\n\nVerbs:\n")
	fprintf(w, "  keygen  mint a signing key and add its public half to the key set\n")
	fprintf(w, "  mint    issue one credential for one repository, on stdout\n")
	fprintf(w, "  verify  report whether a credential is admissible, and why not\n\n")
	fprintf(w, "The key set holds PUBLIC keys and is what `innsegl serve -admin-jwks` reads.\n")
	fprintf(w, "The key file holds the private half and is read by nothing else, ever.\n\n")
	fprintf(w, "Exit status:\n")
	fprintf(w, "  %d  the command completed\n", exitOK)
	fprintf(w, "  %d  the command line was not understood\n", exitUsage)
	fprintf(w, "  %d  REFUSED - the credential is not admissible\n", exitCredentialRefused)
	fprintf(w, "  %d  UNUSABLE - the command could not do its job\n", exitCredentialUnusable)
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

func adminCredentialKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl admin-credential keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "file to write the PRIVATE signing key to, PKCS#8 PEM")
	jwksPath := fs.String("jwks", "", "key set to add this key's PUBLIC half to; created if absent")
	force := fs.Bool("force", false,
		"overwrite an existing key file. Without it an existing key is left alone, because "+
			"replacing one silently would strand every credential minted under it")
	fs.Usage = func() {
		fprintf(stderr, "innsegl admin-credential keygen - mint a signing key\n\n")
		fprintf(stderr, "Usage:\n  innsegl admin-credential keygen -key FILE -jwks FILE\n\n")
		fprintf(stderr, "ROTATION IS AN OVERLAP. The public half is ADDED to the key set "+
			"rather than replacing what is\nthere, so the outgoing key keeps verifying "+
			"until you remove its entry by hand. A rotation\nthat replaced the set would "+
			"refuse every credential already in flight.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if code, ok := adminCredentialParse(fs, args); !ok {
		return code
	}
	if *keyPath == "" || *jwksPath == "" {
		fprintf(stderr, "innsegl admin-credential keygen: -key and -jwks are both required\n")
		return exitUsage
	}

	if _, err := os.Stat(*keyPath); err == nil && !*force {
		fprintf(stderr, "innsegl admin-credential keygen: %s already holds a key. Every "+
			"credential minted under it verifies against the key set entry that key put "+
			"there; replacing it without saying so would strand them. Pass -force if that "+
			"is what you mean\n", *keyPath)
		return exitCredentialUnusable
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential keygen: generating a P-256 key: %v\n", err)
		return exitCredentialUnusable
	}
	jwk, err := mcp.AdminCredentialJWKOf(&key.PublicKey)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential keygen: %v\n", err)
		return exitCredentialUnusable
	}
	if err := adminCredentialWriteKey(*keyPath, key); err != nil {
		fprintf(stderr, "innsegl admin-credential keygen: %v\n", err)
		return exitCredentialUnusable
	}
	if err := adminCredentialAddToKeySet(*jwksPath, jwk); err != nil {
		fprintf(stderr, "innsegl admin-credential keygen: %v\n", err)
		return exitCredentialUnusable
	}

	// The key id, and nothing else. It names a PUBLIC verification key, which
	// is why it is printable at all; the private half is never rendered
	// anywhere but into the file above.
	fprintf(stdout, "%s\n", jwk.KID)
	fprintf(stderr, "innsegl admin-credential keygen: wrote %s (private) and added key %s to %s\n",
		*keyPath, jwk.KID, *jwksPath)
	return exitOK
}

// adminCredentialWriteKey writes the private key by rename, so a reader sees
// either no file or a complete one.
func adminCredentialWriteKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encoding the signing key: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: adminCredentialKeyPEMType, Bytes: der})
	if body == nil {
		return errors.New("encoding the signing key as PEM produced nothing")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, body, adminCredentialKeyMode); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, filepath.Base(path), err)
	}
	return nil
}

// adminCredentialAddToKeySet merges jwk into the key set at path.
//
// ADDED, never replaced: a rotation has to have a window in which BOTH keys
// verify, or every credential already in flight is refused the instant the new
// key lands. Removing the outgoing entry is a separate, deliberate edit.
func adminCredentialAddToKeySet(path string, jwk mcp.AdminCredentialJWK) error {
	var set mcp.AdminCredentialJWKSet
	// The operator's own key set, named on their own command line.
	body, err := os.ReadFile(path)
	switch {
	case err == nil:
		if parseErr := json.Unmarshal(body, &set); parseErr != nil {
			return fmt.Errorf("%s is not a JWK set: %w. Move it aside rather than letting "+
				"this overwrite something that may be another deployment's", path, parseErr)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("reading %s: %w", path, err)
	}

	for _, existing := range set.Keys {
		if existing.KID == jwk.KID {
			// The key id is RFC 7638's thumbprint of the key itself, so this
			// is the same key rather than a collision. Nothing to do.
			return nil
		}
	}
	set.Keys = append(set.Keys, jwk)

	rendered, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return fmt.Errorf("rendering the key set: %w", err)
	}
	rendered = append(rendered, '\n')
	if dir := filepath.Dir(path); dir != "" {
		// 0755: the key set is public, and the process that reads it runs as
		// a different user from the one that writes it.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, rendered, adminCredentialJWKSMode); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, filepath.Base(path), err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

func adminCredentialMint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl admin-credential mint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "the private signing key, as written by keygen")
	repo := fs.String("repo", "",
		"the repository this credential authorises, doc 02 §5's host/org/name. It is the "+
			"ONLY subject-bearing claim, and the whole authorization")
	ttl := fs.Duration("ttl", mcp.AdminCredentialMaxTTL,
		"how long the credential is valid for. Bounded by "+mcp.AdminCredentialMaxTTL.String()+
			": there is no revocation list, because a list is a dependency on the issuer "+
			"being reachable and this design does not have one")
	fs.Usage = func() {
		fprintf(stderr, "innsegl admin-credential mint - issue one credential\n\n")
		fprintf(stderr, "Usage:\n  innsegl admin-credential mint -key FILE -repo host/org/name\n\n")
		fprintf(stderr, "The credential is written to STDOUT and to nowhere else. It carries a "+
			"repository and\nnothing that identifies an account: no subject, no account id, "+
			"no email, no display name.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if code, ok := adminCredentialParse(fs, args); !ok {
		return code
	}
	switch {
	case *keyPath == "":
		fprintf(stderr, "innsegl admin-credential mint: -key is required\n")
		return exitUsage
	case *repo == "":
		fprintf(stderr, "innsegl admin-credential mint: -repo is required; a credential that "+
			"authorised no repository would authorise nothing\n")
		return exitUsage
	case *ttl <= 0 || *ttl > mcp.AdminCredentialMaxTTL:
		fprintf(stderr, "innsegl admin-credential mint: -ttl %s is outside (0, %s]\n",
			*ttl, mcp.AdminCredentialMaxTTL)
		return exitUsage
	}

	key, err := adminCredentialReadKey(*keyPath)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential mint: %v\n", err)
		return exitCredentialUnusable
	}
	jwk, err := mcp.AdminCredentialJWKOf(&key.PublicKey)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential mint: %v\n", err)
		return exitCredentialUnusable
	}

	now := time.Now().UTC()
	nonce := make([]byte, adminCredentialTokenIDBytes)
	if _, randErr := rand.Read(nonce); randErr != nil {
		fprintf(stderr, "innsegl admin-credential mint: no randomness for jti: %v\n", randErr)
		return exitCredentialUnusable
	}
	token, err := adminCredentialSign(key, jwk.KID, mcp.AdminCredentialClaims{
		Issuer:    mcp.AdminCredentialIssuer,
		Audience:  mcp.AdminCredentialAudience,
		Repo:      *repo,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expiry:    now.Add(*ttl).Unix(),
		TokenID:   hex.EncodeToString(nonce),
	})
	if err != nil {
		fprintf(stderr, "innsegl admin-credential mint: %v\n", err)
		return exitCredentialUnusable
	}

	// STDOUT and nothing else. The diagnostic below names the repository, the
	// key and the expiry, and never the credential: a value echoed onto a
	// second stream is a value in a second log.
	fprintf(stdout, "%s\n", token)
	fprintf(stderr, "innsegl admin-credential mint: issued for %s under key %s, valid until %s\n",
		*repo, jwk.KID, now.Add(*ttl).Format(time.RFC3339))
	return exitOK
}

// adminCredentialReadKey reads the PKCS#8 P-256 private key at path.
func adminCredentialReadKey(path string) (*ecdsa.PrivateKey, error) {
	// The operator's own key file, named on their own command line.
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the signing key %s: %w", path, err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != adminCredentialKeyPEMType {
		return nil, fmt.Errorf("%s holds no %q PEM block; `keygen` writes one", path,
			adminCredentialKeyPEMType)
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if parseErr != nil {
		return nil, fmt.Errorf("%s is not a PKCS#8 private key: %w", path, parseErr)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not an ECDSA P-256 key; %s is the only algorithm "+
			"the listener admits", path, mcp.AdminCredentialAlgorithm)
	}
	return key, nil
}

// adminCredentialSign renders and signs one credential.
//
// The bytes that are signed come from internal/mcp's own format function, so
// the minting side and the verifying side cannot drift into signing and
// checking different things.
func adminCredentialSign(key *ecdsa.PrivateKey, kid string, claims mcp.AdminCredentialClaims) (string, error) {
	input, err := mcp.AdminCredentialSigningInput(kid, claims)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("signing the credential: %w", err)
	}
	// JWS ES256 is the two coordinates fixed-width and concatenated, never
	// ASN.1: a DER signature here would be refused by every verifier including
	// this project's own.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func adminCredentialVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl admin-credential verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jwksPath := fs.String("jwks", "", "the key set to verify against — what the server reads")
	token := fs.String("token", "",
		"the credential. Empty reads it from stdin, which keeps it off a command line the "+
			"process table can read")
	fs.Usage = func() {
		fprintf(stderr, "innsegl admin-credential verify - say whether a credential is admissible\n\n")
		fprintf(stderr, "Usage:\n  innsegl admin-credential verify -jwks FILE [-token TOKEN]\n\n")
		fprintf(stderr, "THE SERVER WILL NEVER TELL YOU THIS. Every credential failure on the "+
			"listener is one\nbyte-identical refusal, because a distinguishable \"wrong "+
			"audience\" is an oracle over which\naudiences exist. This runs on your own "+
			"machine against your own token, where saying\nexactly what is wrong costs "+
			"nothing.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if code, ok := adminCredentialParse(fs, args); !ok {
		return code
	}
	if *jwksPath == "" {
		fprintf(stderr, "innsegl admin-credential verify: -jwks is required\n")
		return exitUsage
	}

	presented := *token
	if presented == "" {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			fprintf(stderr, "innsegl admin-credential verify: reading the credential from "+
				"stdin: %v\n", err)
			return exitCredentialUnusable
		}
		presented = strings.TrimSpace(string(body))
	}

	verifier, err := mcp.NewAdminCredentialVerifier(mcp.AdminCredentialConfig{KeySetFile: *jwksPath})
	if err != nil {
		fprintf(stderr, "innsegl admin-credential verify: %v\n", err)
		return exitCredentialUnusable
	}
	scope, err := verifier.Explain(presented)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential verify: REFUSED - %v\n", err)
		return exitCredentialRefused
	}
	fprintf(stdout, "%s\n", scope.Repo)
	fprintf(stderr, "innsegl admin-credential verify: admissible, and authorises %s\n", scope.Repo)
	return exitOK
}

// adminCredentialParse runs one verb's flag set, mapping -h and a bad flag
// onto cli.go's statuses.
func adminCredentialParse(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitUsage, false
	}
	return exitOK, true
}
