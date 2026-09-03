// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// INIT-005 (proposed, doc 07 layer U): the deployment config `innsegl init`
// writes (#117 point 3) — the environment `innsegl serve`, `seal`, `reap` and
// `reconcile` already read, so a repository that ran `init` can run any of
// them by sourcing one file. Never a repository-tracked secret: the identity
// secret goes in its own file under .git/, exactly the shape
// $INNSEGL_IDENTITY_SECRET_FILE already supports (serve.go), and is never
// written into the tracked deploy.env.

func TestINIT005WriteDeployConfigWritesTheExpectedEnvironmentNames(t *testing.T) {
	repo := initTestRepo(t)
	cfg := deployConfig{
		FulcioURL:    "https://fulcio.example",
		RekorURL:     "https://rekor.example",
		OIDCIssuer:   "http://spire-oidc:8080",
		IdentityMode: "pseudonymous",
	}

	paths, err := writeDeployConfig(repo, cfg, "a-generated-secret-thats-long-enough")
	if err != nil {
		t.Fatalf("writeDeployConfig: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("writeDeployConfig reported no paths written")
	}

	body, err := os.ReadFile(deployConfigPath(repo))
	if err != nil {
		t.Fatalf("reading deploy config: %v", err)
	}
	for _, want := range []string{
		"INNSEGL_FULCIO_URL=https://fulcio.example",
		"INNSEGL_REKOR_URL=https://rekor.example",
		"INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"INNSEGL_IDENTITY_MODE=pseudonymous",
		"INNSEGL_IDENTITY_SECRET_FILE=",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("deploy config does not contain %q:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "a-generated-secret-thats-long-enough") {
		t.Error("the raw secret must never be written into the tracked deploy config")
	}

	secretPath := identitySecretPath(repo)
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("reading identity secret file: %v", err)
	}
	if strings.TrimSpace(string(secret)) != "a-generated-secret-thats-long-enough" {
		t.Errorf("identity secret file = %q, want the secret verbatim", secret)
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("identity secret file mode = %v, want no group/other permission bits", info.Mode())
	}
	if !strings.HasPrefix(secretPath, filepath.Join(repo, ".git")) {
		t.Errorf("identity secret path %q is not under .git — it must never be tracked by git", secretPath)
	}
}

func TestINIT005WriteDeployConfigWithNoSecretWritesNoSecretFile(t *testing.T) {
	repo := initTestRepo(t)
	cfg := deployConfig{FulcioURL: "https://f", RekorURL: "https://r", OIDCIssuer: "https://i"}

	if _, err := writeDeployConfig(repo, cfg, ""); err != nil {
		t.Fatalf("writeDeployConfig: %v", err)
	}
	if _, err := os.Stat(identitySecretPath(repo)); !os.IsNotExist(err) {
		t.Fatalf("identity secret file exists with no secret given: %v", err)
	}
}

func TestINIT005SecondWriteIsIdempotentOverItsOwnFile(t *testing.T) {
	repo := initTestRepo(t)
	cfg := deployConfig{FulcioURL: "https://f", RekorURL: "https://r", OIDCIssuer: "https://i", IdentityMode: "literal"}

	if _, err := writeDeployConfig(repo, cfg, "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := writeDeployConfig(repo, cfg, "s"); err != nil {
		t.Fatalf("second writeDeployConfig over its own managed file: %v", err)
	}
}

func TestINIT005RefusesToOverwriteAnUnmanagedFile(t *testing.T) {
	repo := initTestRepo(t)
	if err := os.MkdirAll(filepath.Dir(deployConfigPath(repo)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deployConfigPath(repo), []byte("SOME_OTHER_TOOL=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := deployConfig{FulcioURL: "https://f", RekorURL: "https://r", OIDCIssuer: "https://i"}
	_, err := writeDeployConfig(repo, cfg, "")
	if err == nil {
		t.Fatal("writeDeployConfig over a file it did not create: want a refusal, got nil")
	}

	got, rerr := os.ReadFile(deployConfigPath(repo))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != "SOME_OTHER_TOOL=1\n" {
		t.Errorf("the unmanaged file was modified: %s", got)
	}
}

func TestINIT005RemoveDeployConfigDeletesOnlyManagedFiles(t *testing.T) {
	repo := initTestRepo(t)
	cfg := deployConfig{FulcioURL: "https://f", RekorURL: "https://r", OIDCIssuer: "https://i"}
	paths, err := writeDeployConfig(repo, cfg, "s")
	if err != nil {
		t.Fatal(err)
	}

	if err := removeDeployConfig(repo, paths); err != nil {
		t.Fatalf("removeDeployConfig: %v", err)
	}
	if _, err := os.Stat(deployConfigPath(repo)); !os.IsNotExist(err) {
		t.Error("deploy config still exists after removeDeployConfig")
	}
	if _, err := os.Stat(identitySecretPath(repo)); !os.IsNotExist(err) {
		t.Error("identity secret file still exists after removeDeployConfig")
	}
}

func TestINIT005RemoveDeployConfigLeavesAFileThatLostItsMarker(t *testing.T) {
	repo := initTestRepo(t)
	cfg := deployConfig{FulcioURL: "https://f", RekorURL: "https://r", OIDCIssuer: "https://i"}
	paths, err := writeDeployConfig(repo, cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	// The operator edited the file by hand after init wrote it, and it no
	// longer carries the marker. --undo must not delete something it can no
	// longer prove it owns.
	if err := os.WriteFile(deployConfigPath(repo), []byte("EDITED_BY_HAND=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := removeDeployConfig(repo, paths); err != nil {
		t.Fatalf("removeDeployConfig: %v", err)
	}
	if _, err := os.Stat(deployConfigPath(repo)); err != nil {
		t.Errorf("removeDeployConfig deleted a file that had lost its marker: %v", err)
	}
}
