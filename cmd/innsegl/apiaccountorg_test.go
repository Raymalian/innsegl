// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
)

// RM-333 (#511): `innsegl api` serves the account page's organisation routes
// from the accounts spine, opened with the auth-writer credential it already
// holds. Through the real command, against a real Postgres.
func TestRM333TheCommandServesTheOrganisationRoutes(t *testing.T) {
	ownerDSN, readerDSN, authDSN := freshLedgerDB(t)
	repoDir, _ := newProofRepo(t)
	fulcio, rekor := closedAddress(t), closedAddress(t)
	addr, _ := startAPICommand(t,
		apiArgsFor(readerDSN, authDSN, "github.com/innsegl/demo", repoDir, fulcio, rekor)...)
	base := "http://" + addr
	cookie := enrolAndSignIn(t, base, authDSN)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err = conn.Exec(ctx, `
		INSERT INTO innsegl_auth.accounts (account_id, name) VALUES ('0123456789abcdef0123456789abcdef', 'example-org');
		INSERT INTO innsegl_auth.memberships (user_id, account_id, role)
		     SELECT user_id, '0123456789abcdef0123456789abcdef', 'owner' FROM innsegl_auth.users`); err != nil {
		t.Fatalf("seed the organisation: %v", err)
	}

	status, body := getJSON(t, base+"/api/v1/account", cookie)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/account = %d: %s", status, body)
	}
	var acc struct {
		Organisations []struct {
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"organisations"`
	}
	if err := json.Unmarshal(body, &acc); err != nil {
		t.Fatal(err)
	}
	// The first user owns the deployment's own organisation, founded at
	// enrolment (accounts.FoundOperator), and the one seeded above.
	if len(acc.Organisations) != 2 || acc.Organisations[0].Role != "owner" ||
		acc.Organisations[1].Name != "example-org" || acc.Organisations[1].Role != "owner" {
		t.Errorf("organisations = %+v", acc.Organisations)
	}
	for _, path := range []string{"/api/v1/account/machines", "/api/v1/account/repositories",
		"/api/v1/account/agents", "/api/v1/account/sessions"} {
		if status, body := getJSON(t, base+path, cookie); status != http.StatusOK {
			t.Errorf("GET %s = %d: %s", path, status, body)
		}
	}
}
