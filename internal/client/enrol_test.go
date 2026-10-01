// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client/clienttest"
)

func TestTokenShape(t *testing.T) {
	if !ValidToken(clienttest.Token) {
		t.Fatal("the contract's token shape was refused")
	}
	for _, bad := range []string{"", "ie_0123", "ie_0123456789ABCDEF_" + strings.Repeat("a", 64), "xx_0123456789abcdef_" + strings.Repeat("a", 64)} {
		if ValidToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFetchCAConfirmsTheFingerprint(t *testing.T) {
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	ca, err := FetchCA(context.Background(), core.URL(), core.Fingerprint())
	if err != nil {
		t.Fatalf("FetchCA: %v", err)
	}
	if !ca.Equal(core.CA) {
		t.Fatal("FetchCA returned a certificate other than the core's CA")
	}
	upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(core.Fingerprint(), "sha256:"))
	if _, err := FetchCA(context.Background(), core.URL(), upper); err != nil {
		t.Fatalf("an upper-case fingerprint was refused: %v", err)
	}
	wrong := "sha256:" + strings.Repeat("ab", 32)
	if _, err := FetchCA(context.Background(), core.URL(), wrong); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("a mismatched fingerprint: %v", err)
	}
	if _, err := FetchCA(context.Background(), core.URL(), "md5:abcd"); err == nil {
		t.Fatal("a non-sha256 fingerprint was accepted")
	}
}

func TestEnrolRefusedTokenIsErrUnauthorized(t *testing.T) {
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	bad := "ie_ffffffffffffffff_" + strings.Repeat("f", 64)
	_, err = Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: bad, Name: "n", CA: core.CA})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestEnrolRefusesACoreItDoesNotTrust(t *testing.T) {
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	other, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_, err = Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: clienttest.Token, Name: "n", CA: other.CA})
	if err == nil {
		t.Fatal("enrolment against an untrusted core succeeded")
	}
	if n, _ := core.Counts(); n != 0 {
		t.Fatal("the token reached a core the client does not trust")
	}
}

func TestWriteEnrolmentModes(t *testing.T) {
	core, paths := enrolled(t)
	for path, mode := range map[string]os.FileMode{
		paths.Dir: 0o700, paths.Key: 0o600, paths.Cert: 0o644, paths.Bundle: 0o644, paths.CA: 0o644, paths.Core: 0o644,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode %o, want %o", path, st.Mode().Perm(), mode)
		}
	}
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstallationID != core.EnrolledID() || !strings.HasPrefix(cfg.CoreURL, "https://") || cfg.Listen != "127.0.0.1:28195" {
		t.Fatalf("core.json = %+v", cfg)
	}
}
