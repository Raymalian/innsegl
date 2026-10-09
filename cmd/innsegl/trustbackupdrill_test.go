// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// BAK-030 (PROPOSED for doc 07's TC-BAK) — the drill knows what a restorable
// bundle must hold (#533). Under CA custody (ADR-0076) the CA key lives only
// in the store: a bundle that says custody is on and lacks the store's
// snapshot or the sealed unlock material would lose the CA, and must fail the
// drill (exit 26, MISSING). And since ADR-0075 the CA's password is the file
// ca.pass beside its key, so a bundle holding that needs no separate
// password item.

func drillManifest(items map[string][]string) trustbackup.Manifest {
	var m trustbackup.Manifest
	for name, files := range items {
		it := trustbackup.Item{Name: name}
		for _, f := range files {
			it.Files = append(it.Files, trustbackup.File{Path: f, Size: 1, SHA256: strings.Repeat("a", 64)})
		}
		m.Items = append(m.Items, it)
	}
	return m
}

func fileCABundle() map[string][]string {
	return map[string][]string{
		"fulcio-pki":        {"ca.crt", "ca.key", "ca.pass", "serve.yaml", "config.yaml"},
		"rekor-key":         {"log.key"},
		"trillian-db":       {"trillian.sql"},
		"identity-secret":   {"secret"},
		"spire-upstream-ca": {"upstream-ca.key"},
		"gateway-ca-key":    {"gateway-ca-key.pem"},
		"trust-history":     {"trust-history.json"},
		// ADR-0078: every service credential, per project.
		"credentials":          {"ledger-owner", "objects-root"},
		"sigstore-credentials": {"logdb-trillian"},
	}
}

// A bundle written before ADR-0078 cannot restore a host made after it: a
// restored ledger or log database opens only with the passwords it had.
func TestBAK030ABundleWithoutTheCredentialsFailsTheDrill(t *testing.T) {
	for _, item := range []string{"credentials", "sigstore-credentials"} {
		b := fileCABundle()
		delete(b, item)
		if code, out := drill(t, b); code != exitTrustBackupFailed || !strings.Contains(out, item+" ") {
			t.Errorf("a bundle without %s passed the drill: exit %d\n%s", item, code, out)
		}
	}
}

func drill(t *testing.T, items map[string][]string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := printDrill(&out, trustbackup.Entry{Name: "trust-backup-x.tar.age"}, drillManifest(items), "")
	return code, out.String()
}

func TestBAK030AFileCABundleWithItsPasswordFileNeedsNoPasswordItem(t *testing.T) {
	if code, out := drill(t, fileCABundle()); code != exitOK || strings.Contains(out, "MISSING") {
		t.Fatalf("a complete ADR-0075 bundle failed the drill: exit %d\n%s", code, out)
	}
	b := fileCABundle()
	b["fulcio-pki"] = []string{"ca.crt", "ca.key", "config.yaml"}
	if code, out := drill(t, b); code != exitTrustBackupFailed || !strings.Contains(out, "fulcio-ca-password") {
		t.Fatalf("a bundle with the CA key and no password anywhere passed: exit %d\n%s", code, out)
	}
	b["fulcio-ca-password"] = []string{"value"}
	if code, out := drill(t, b); code != exitOK {
		t.Fatalf("a bundle from before ca.pass, with its password item, failed: exit %d\n%s", code, out)
	}
}

func TestBAK030ACustodyBundleMustHoldTheStoreAndTheMaterial(t *testing.T) {
	full := fileCABundle()
	full["custody"] = []string{"value"}
	full["ca-store"] = []string{"store.snap"}
	full["ca-custody"] = []string{"unlock.age"}
	if code, out := drill(t, full); code != exitOK {
		t.Fatalf("a complete custody bundle failed: exit %d\n%s", code, out)
	}
	for _, c := range []struct {
		name string
		drop func(map[string][]string)
		want string
	}{
		{"no store", func(b map[string][]string) { delete(b, "ca-store") }, "ca-store"},
		{"no material", func(b map[string][]string) { delete(b, "ca-custody") }, "ca-custody"},
		{"a store item without its snapshot", func(b map[string][]string) { b["ca-store"] = []string{"other"} }, "ca-store"},
		{"a material item without the material", func(b map[string][]string) { b["ca-custody"] = []string{"other"} }, "ca-custody"},
	} {
		b := map[string][]string{}
		for k, v := range full {
			b[k] = v
		}
		c.drop(b)
		code, out := drill(t, b)
		if code != exitTrustBackupFailed || !strings.Contains(out, "MISSING") || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d, want %d naming %s MISSING:\n%s", c.name, code, exitTrustBackupFailed, c.want, out)
		}
	}
}
