// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
)

// OPS-175 (ADR-0080 decisions 2 and 5): the repository-mode setting on
// `innsegl serve`. Default literal; pseudonymous needs the key; the switch is
// one-way.

const testRepoKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOPS175RepoModeSettings(t *testing.T) {
	base := serveOptions{
		dsn: "postgres://x", spireAddress: "h:1", trustDomain: "innsegl.dev",
		parentID: "spiffe://innsegl.dev/spire/agent/x", fulcioURL: "http://f", rekorURL: "http://r",
		listen: "127.0.0.1:0", healthListen: "127.0.0.1:0",
		rateCalls: 1, rateWindow: 60_000_000_000,
		identityMode: string(identity.ModePseudonymous), identitySecret: testIdentitySecret,
	}

	t.Run("no mode set is literal", func(t *testing.T) {
		if problem := base.validate(); problem != "" {
			t.Fatalf("refused: %s", problem)
		}
		r, err := base.repositories()
		if err != nil || r.Mode() != identity.ModeLiteral {
			t.Errorf("repositories() = %v, %v; want literal", r, err)
		}
	})
	for _, tc := range []struct {
		name, mode, key string
	}{
		{"pseudonymous with no key", "pseudonymous", ""},
		{"pseudonymous with a short key", "pseudonymous", "short"},
		{"a mode that is neither", "hashed", testRepoKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			o.repoMode, o.repoKey = tc.mode, tc.key
			problem := o.validate()
			if !strings.Contains(problem, "-repo-mode") || !strings.Contains(problem, envRepoMode) {
				t.Errorf("refusal %q does not name -repo-mode and $%s", problem, envRepoMode)
			}
		})
	}
	t.Run("pseudonymous with a key starts", func(t *testing.T) {
		o := base
		o.repoMode, o.repoKey = "pseudonymous", testRepoKey
		if problem := o.validate(); problem != "" {
			t.Errorf("refused: %s", problem)
		}
	})
}

func TestOPS175RepoKeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	o := serveOptions{repoMode: "pseudonymous", repoKeyFile: write("key", testRepoKey+"\n")}
	if problem := o.resolveRepoKey(); problem != "" || o.repoKey != testRepoKey {
		t.Errorf("the key file read as %q (%s); a trailing newline is not part of the key", o.repoKey, problem)
	}

	o = serveOptions{repoMode: "pseudonymous", repoKeyFile: filepath.Join(dir, "absent")}
	if problem := o.resolveRepoKey(); !strings.Contains(problem, "-repo-key-file") {
		t.Errorf("a missing key file in pseudonymous mode: %q", problem)
	}

	o = serveOptions{repoMode: "pseudonymous", repoKeyFile: write("empty", "\n")}
	if problem := o.resolveRepoKey(); !strings.Contains(problem, "holds no key") {
		t.Errorf("an empty key file in pseudonymous mode: %q", problem)
	}

	// Literal mode never needs the key: a missing file is not a reason to
	// refuse a deployment that has not switched.
	o = serveOptions{repoMode: "literal", repoKeyFile: filepath.Join(dir, "absent")}
	if problem := o.resolveRepoKey(); problem != "" || o.repoKey != "" {
		t.Errorf("a missing key file in literal mode: %q, key %q", problem, o.repoKey)
	}
	o = serveOptions{repoKeyFile: write("key2", testRepoKey)}
	if problem := o.resolveRepoKey(); problem != "" || o.repoKey != "" {
		t.Errorf("literal mode read the key: %q, key %q", problem, o.repoKey)
	}
}

type fakeRepoModeStore struct {
	recorded  bool
	readErr   error
	recordErr error
	keyID     string
	used      *identity.Repositories
}

func (f *fakeRepoModeStore) RecordedPseudonymous(context.Context) (bool, error) {
	return f.recorded, f.readErr
}

func (f *fakeRepoModeStore) RecordPseudonymous(_ context.Context, keyID string) error {
	f.keyID = keyID
	return f.recordErr
}

func (f *fakeRepoModeStore) UseRepositories(r *identity.Repositories) { f.used = r }

func TestOPS175TheSwitchIsOneWay(t *testing.T) {
	ctx := context.Background()
	literal, _ := identity.NewRepositories(identity.ModeLiteral, "")
	pseudo, _ := identity.NewRepositories(identity.ModePseudonymous, testRepoKey)

	t.Run("literal on a ledger that switched is refused, naming the setting", func(t *testing.T) {
		f := &fakeRepoModeStore{recorded: true}
		err := applyRepoMode(ctx, f, literal)
		if err == nil || !strings.Contains(err.Error(), envRepoMode) || !strings.Contains(err.Error(), "ADR-0080") {
			t.Errorf("err = %v", err)
		}
		if f.used != nil {
			t.Error("a refused mode was still applied")
		}
	})
	t.Run("literal on a literal ledger writes literal", func(t *testing.T) {
		f := &fakeRepoModeStore{}
		if err := applyRepoMode(ctx, f, literal); err != nil || f.used != literal || f.keyID != "" {
			t.Errorf("err = %v, used = %v, recorded %q", err, f.used, f.keyID)
		}
	})
	t.Run("pseudonymous records the switch with its key id, every start", func(t *testing.T) {
		for _, recorded := range []bool{false, true} {
			f := &fakeRepoModeStore{recorded: recorded}
			if err := applyRepoMode(ctx, f, pseudo); err != nil || f.keyID != pseudo.KeyID() || f.used != pseudo {
				t.Errorf("recorded=%v: err = %v, key id %q, used %v", recorded, err, f.keyID, f.used)
			}
		}
	})
	t.Run("the ledger's failures are the start's failures", func(t *testing.T) {
		boom := errors.New("ledger down")
		if err := applyRepoMode(ctx, &fakeRepoModeStore{readErr: boom}, literal); !errors.Is(err, boom) {
			t.Errorf("read failure: %v", err)
		}
		if err := applyRepoMode(ctx, &fakeRepoModeStore{recordErr: boom}, pseudo); !errors.Is(err, boom) {
			t.Errorf("record failure: %v", err)
		}
	})
}

// OPS-175: `innsegl status` shows the repository mode the core reports, as a
// component that is never down.
func TestOPS175StatusShowsTheRepositoryMode(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ready":true,"repo_mode":"pseudonymous",` +
			`"dependencies":[{"dependency":"ledger","reachable":true}]}`))
	}))
	t.Cleanup(ready.Close)
	t.Setenv(envMCPHealthListen, strings.TrimPrefix(ready.URL, "http://"))
	components := coreReadiness(t.Context())
	var found bool
	for _, c := range components {
		if c.Name == repoModeComponent {
			found = true
			if !c.Up || c.Detail != "pseudonymous" {
				t.Errorf("component = %+v", c)
			}
		}
	}
	if !found {
		t.Errorf("no %q component in %+v", repoModeComponent, components)
	}
}
