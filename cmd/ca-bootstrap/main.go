// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// Exit statuses, distinct because an operator acts differently on each.
const (
	exitOK       = 0
	exitUsage    = 2
	exitStore    = 3 // the store is unreachable, sealed, or refused the token
	exitMintFail = 4 // the store answered and the root could not be made
)

func main() { os.Exit(run()) }

func run() int {
	addr := firstSet("INNSEGL_CA_STORE_ADDR", "BAO_ADDR", "VAULT_ADDR")
	token := firstSet("INNSEGL_CA_STORE_TOKEN", "BAO_TOKEN", "VAULT_TOKEN")
	key := envOr("INNSEGL_CA_STORE_KEY", "innsegl-ca")
	trustDomain := envOr("INNSEGL_TRUST_DOMAIN", "innsegl.dev")
	out := envOr("INNSEGL_CA_CHAIN_PATH", "/etc/fulcio/chain.pem")

	if addr == "" || token == "" {
		fmt.Fprintln(os.Stderr, "ca-bootstrap: this mints the CA root whose private key stays in the")
		fmt.Fprintln(os.Stderr, "  secret store. It needs the store's address and a token that may use")
		fmt.Fprintln(os.Stderr, "  the transit key:")
		fmt.Fprintln(os.Stderr, "    INNSEGL_CA_STORE_ADDR   (or BAO_ADDR / VAULT_ADDR)")
		fmt.Fprintln(os.Stderr, "    INNSEGL_CA_STORE_TOKEN  (or BAO_TOKEN / VAULT_TOKEN)")
		fmt.Fprintln(os.Stderr, "  Neither is defaulted: a default address would point at nothing and a")
		fmt.Fprintln(os.Stderr, "  default token would be a shipped credential.")
		return exitUsage
	}

	// IDEMPOTENT, and it has to be: this runs on every bring-up of the profile,
	// and a second run that minted a SECOND key would leave Fulcio presenting a
	// root that no longer matches the key the store signs with.
	if err := ensureKey(addr, token, key); err != nil {
		fmt.Fprintf(os.Stderr, "ca-bootstrap: %v\n", err)
		return exitStore
	}

	signer, err := newTransitSigner(addr, token, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca-bootstrap: %v\n", err)
		return exitStore
	}

	// ALREADY DONE IS A NO-OP. The chain is derived from the key, so re-minting
	// it on every start would hand Fulcio a new root — same key, new serial —
	// and every certificate already issued would chain to a root nobody has.
	if existing, readErr := os.ReadFile(out); readErr == nil && len(existing) > 0 {
		fmt.Printf("ca-bootstrap: %s already holds a root; leaving it alone\n", out)
		fmt.Printf("ca-bootstrap: the private key is in the store under %q and is not here\n", key)
		return exitOK
	}

	der, err := mintRootCA(signer, trustDomain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca-bootstrap: %v\n", err)
		return exitMintFail
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "ca-bootstrap: creating %s: %v\n", filepath.Dir(out), err)
		return exitMintFail
	}
	// 0600 although a certificate is public by construction. The file is read by
	// one container running as this uid, so nothing needs the wider mode, and a
	// writer that widens permissions it does not need is the habit that later
	// writes a key 0644. The publicness of the CONTENT is not a reason to relax
	// the MODE.
	if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "ca-bootstrap: writing %s: %v\n", out, err)
		return exitMintFail
	}

	// THE CA'S DIRECTORY MUST CONTAIN NO KEY, which is the whole claim of rung 3
	// and is not automatic: the file CA's volume holds ca.key beside its config,
	// and a Fulcio that mounted it would be running kmsca with a private key
	// sitting next to it. So the issuer config is COPIED into this directory and
	// the CA mounts only this one. OPS-049 reads the container's filesystem.
	if src := os.Getenv("INNSEGL_CA_CONFIG_SRC"); src != "" {
		if err := copyConfig(src, filepath.Dir(out), "config.yaml"); err != nil {
			fmt.Fprintf(os.Stderr, "ca-bootstrap: %v\n", err)
			return exitMintFail
		}
	}

	fmt.Printf("ca-bootstrap: minted the root for %s into %s\n", trustDomain, out)
	fmt.Printf("ca-bootstrap: the private key is in the store under %q and was never in this process\n", key)
	return exitOK
}

// ensureKey mounts transit if it is not mounted and creates the key if it does
// not exist. Both calls are safe to repeat.
func ensureKey(addr, token, key string) error {
	s := &transitSigner{base: trimRight(addr), token: token, key: key, client: httpClient()}

	// A mount that already exists answers 400; that is success here, and the
	// distinction between "already mounted" and "cannot mount" is the next
	// call's job rather than a string match on this one's error. Explicitly
	// discarded so that the discard is a decision and not an oversight.
	if err := s.call(http.MethodPost, "/v1/sys/mounts/transit", []byte(`{"type":"transit"}`), nil); err != nil {
		_ = err
	}

	if err := s.call(http.MethodGet, "/v1/transit/keys/"+key, nil, nil); err == nil {
		return nil
	}
	body := []byte(`{"type":"ecdsa-p256"}`)
	if err := s.call(http.MethodPost, "/v1/transit/keys/"+key, body, nil); err != nil {
		return fmt.Errorf("creating the CA key %q in the store: %w", key, err)
	}
	return nil
}

func firstSet(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// copyConfig puts Fulcio's issuer configuration beside the certificate, so the
// CA can be given a directory holding a cert and a config and nothing else.
//
// It is a copy rather than a second mount for exactly one reason: the file the
// stack generates lives in the same directory as ca.key, and mounting that
// directory is what this is avoiding.
//
// THE WRITE GOES THROUGH os.Root, which confines it to the directory it was
// opened on. The destination is built from an operator-supplied path, and a
// write derived from one should not be able to leave the directory it names
// however the path is spelled — os.Root enforces that in the kernel calls
// rather than in a check a later edit can drift past.
func copyConfig(src, dstDir, name string) error {
	body, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("reading the issuer config at %s: %w", src, err)
	}
	if len(body) == 0 {
		return fmt.Errorf("the issuer config at %s is empty; Fulcio would start with no "+
			"issuer and refuse every token it was given", src)
	}
	root, err := os.OpenRoot(dstDir)
	if err != nil {
		return fmt.Errorf("opening %s to write the issuer config: %w", dstDir, err)
	}
	defer func() { _ = root.Close() }()

	f, err := root.Create(name)
	if err != nil {
		return fmt.Errorf("creating %s in %s: %w", name, dstDir, err)
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing the issuer config to %s: %w", name, err)
	}
	return f.Close()
}
