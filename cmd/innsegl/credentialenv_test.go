// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OPS-130 (ADR-0078): -h never prints a credential. Every flag whose default
// is read from a credential variable showed that value: `innsegl accounts -h`
// printed the auth-writer's password inside its DSN.
func TestOPS130HelpNeverPrintsACredential(t *testing.T) {
	const secret = "s3cr3t-in-the-environment"
	dsn := "postgres://role:" + secret + "@postgres:5432/innsegl?sslmode=disable"
	for _, k := range []string{envLedgerDSN, envAPIDSN, envAuthWriterDSN, envAPIResolverDSN, envGatewayAccountsDSN} {
		t.Setenv(k, dsn)
	}
	t.Setenv(envSecretKey, secret)
	for _, cmd := range [][]string{
		{"accounts", "list", "-h"}, {"seal", "-h"}, {"canary", "-h"}, {"reap", "-h"},
		{"retire", "-h"}, {"migrate-schema", "-h"}, {"gateway", "-h"}, {"serve", "-h"},
		{"api", "-h"}, {"admin-credential", "enrol-code", "-h"},
	} {
		var out, errOut bytes.Buffer
		run(cmd, &out, &errOut)
		all := out.String() + errOut.String()
		if strings.Contains(all, secret) {
			t.Errorf("innsegl %s prints the credential from the environment", strings.Join(cmd, " "))
		}
		if !strings.Contains(all, "Flags") && !strings.Contains(all, "Usage") && !strings.Contains(all, "usage") {
			t.Errorf("innsegl %s printed no usage; the case did not reach the flags:\n%s", strings.Join(cmd, " "), all)
		}
	}
}

func TestRedactDSNKeepsEverythingButThePassword(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://u:pw@h:5432/db?sslmode=disable":     "postgres://u:xxxxx@h:5432/db?sslmode=disable",
		"postgres://u@h/db?passfile=/run/x/pgpass":      "postgres://u@h/db?passfile=/run/x/pgpass",
		"host=h user=u password=pw dbname=db":           "host=h user=u password=xxxxx dbname=db",
		"postgres://u@h/db?password=pw&sslmode=disable": "postgres://u@h/db?password=xxxxx&sslmode=disable",
	} {
		if got := redactDSN(in); got != want {
			t.Errorf("redactDSN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnvSecretReadsTheFileAndRefusesTwoSources(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("from-file\nignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"X_FILE": f}
	get := func(k string) string { return env[k] }
	if v, err := envSecret(get, "X"); err != nil || v != "from-file" {
		t.Errorf("file: %q, %v", v, err)
	}
	env["X"] = "value"
	if _, err := envSecret(get, "X"); err == nil {
		t.Error("both set was accepted")
	}
	delete(env, "X_FILE")
	if v, err := envSecret(get, "X"); err != nil || v != "value" {
		t.Errorf("value: %q, %v", v, err)
	}
	env = map[string]string{"X_FILE": filepath.Join(t.TempDir(), "absent")}
	if _, err := envSecret(get, "X"); err == nil {
		t.Error("a missing file was accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env = map[string]string{"X_FILE": empty}
	if _, err := envSecret(get, "X"); err == nil {
		t.Error("an empty file was accepted")
	}
}
