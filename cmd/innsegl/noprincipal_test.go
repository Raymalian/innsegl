// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
)

// ACC-012 (#482; plan, Principals: a human and an organisation have no
// SPIFFE identity, ever): no principal in the signing path. An invited
// member of a second organisation enrols a machine and runs through the real
// hosted gateway; then every place the run's identity and evidence live is
// scanned for the organisation's and the people's identifiers, and (#485)
// what the organisation's identity provider calls them: the machine's
// certificate (DER), the SPIRE entries the run registered, the trailers the
// core would write into its commit, every row of every table in the ledger
// schema, and the gateway's log. The installation id may appear: it names a
// machine, not a person.
//
// Not in process, and so not here: the Fulcio certificate and the Rekor entry
// of a signed commit. The Fulcio certificate carries only the run's SPIFFE ID
// (the JWT-SVID's subject, ADR-0053), scanned here as the SPIRE entry; the
// rehearsal on a development stack scans the real ones.
func TestACC012NoPrincipalReachesTheSigningPath(t *testing.T) {
	f := newEnFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool := gwIdentityPool(t, f.ownerDSN)

	// The principals, each with an identifier distinctive enough to find.
	const (
		ownerID     = "u0wnerq7c4e1acc012"
		ownerName   = "Ottoline Vandersnoot"
		memberID    = "u7f3a9membacc012"
		memberName  = "Zelda Quartermaine"
		orgName     = "Zephyrine Analytics"
		repo        = "example.test/acc012/app"
		sessionID   = "12121212-1212-4121-8121-121212121212"
		ledgerTable = "innsegl"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO innsegl.repo_mode (mode, key_id) VALUES ('pseudonymous', 'rk-test0001')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ($1, $2), ($3, $4)`,
		ownerID, ownerName, memberID, memberName); err != nil {
		t.Fatal(err)
	}
	org, err := f.writer.CreateAccount(ctx, accounts.CreateAccountParams{Name: orgName, Owner: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := f.writer.CreateInvitation(ctx, org.ID, accounts.RoleMember, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.writer.AcceptInvitation(ctx, code, memberID); err != nil {
		t.Fatal(err)
	}
	// #485: the organisation signs in through its own identity provider, and
	// the member's identity there is linked, with a session it opened. None
	// of what the provider calls them may reach the signing path either.
	const (
		ssoName     = "zephyrine-acc012"
		ssoIssuer   = "https://idp.zephyrine-acc012.example"
		ssoClient   = "zephyrine-client-acc012"
		ssoSubject  = "idp-subject-acc012-zq7"
		ssoSessHash = "acc012acc012acc012acc012acc012acc012acc012acc012acc012acc012acc0"
	)
	conn, err := f.writer.SetSSOConnection(ctx, org.ID, api.SSOConnectionParams{SignInName: ssoName,
		Issuer: ssoIssuer, ClientID: ssoClient, ClientSecret: "zephyrine-secret-acc012"}, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO innsegl_auth.oidc_identities (issuer, subject, user_id, connection_id)
		VALUES ($1, $2, $3, $4)`, ssoIssuer, ssoSubject, memberID, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at, sso_connection_id)
		VALUES ($1, $2, now() + interval '1 hour', $3)`, ssoSessHash, memberID, conn.ID); err != nil {
		t.Fatal(err)
	}
	token, _, err := f.writer.CreateEnrolmentToken(ctx, accounts.TokenParams{
		AccountID: org.ID, CreatedBy: memberID, Repos: []string{accounts.AllRepos}})
	if err != nil {
		t.Fatal(err)
	}

	g := startHostedGateway(t, f)
	c := newEnClient(t)
	status, body := g.post(t, g.client(t, nil), coreEnrolPath, enrolBody(t, token, c.ownCSR(t), "member laptop"), nil)
	if status != http.StatusOK {
		t.Fatalf("enrol: %d %s", status, body)
	}
	issued := parseIssued(t, body)
	cl := g.client(t, c.tlsCert(issued))
	if status, body = g.post(t, cl, gatewaySessionWorkspacePath, statement(t, sessionID, repo), nil); status != http.StatusNoContent {
		t.Fatalf("statement: %d %s", status, body)
	}
	if status, body = g.post(t, cl, "/v1/messages", enMessage, messageHeaders(sessionID)); status != http.StatusOK {
		t.Fatalf("message: %d %s", status, body)
	}
	var runID string
	if err = pool.QueryRow(ctx, `SELECT run_id FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND client_id = $2`,
		sessionID, c.id).Scan(&runID); err != nil {
		t.Fatalf("the member's run was not recorded: %v", err)
	}

	// The trailers the core writes into this run's commit.
	store, err := ledger.Open(ctx, f.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatal(err)
	}
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatal(err)
	}
	restore, err := mcp.ConfigureCommitClaim(mcp.CommitClaimConfig{Runs: dir, Pseudonyms: literal})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	claim, err := mcp.CommitClaimForRun(ctx, runID)
	if err != nil {
		t.Fatalf("the run's commit claim: %v", err)
	}
	trailers, err := claim.Trailers()
	if err != nil {
		t.Fatal(err)
	}

	surfaces := map[string][]byte{
		"the machine's certificate (DER)": issued.chain[0].Raw,
		"the commit trailers":             []byte(fmt.Sprint(trailers)),
		"the SPIRE entries":               []byte(spireEntries(f)),
		"the gateway's log":               []byte(g.log.String()),
	}
	rows, err := pool.Query(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY table_name`, ledgerTable)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if serr := rows.Scan(&name); serr != nil {
			t.Fatal(serr)
		}
		tables = append(tables, name)
	}
	rows.Close()
	for _, table := range tables {
		var dump string
		if qerr := pool.QueryRow(ctx, `SELECT coalesce(string_agg(row_to_json(t)::text, E'\n'), '')
			FROM `+ledgerTable+`.`+table+` t`).Scan(&dump); qerr != nil {
			t.Fatalf("dump %s: %v", table, qerr)
		}
		// The canonical bytes are stored as bytea; row_to_json shows them
		// hex-escaped, so the readable form is scanned too.
		surfaces["ledger table "+table] = []byte(dump)
	}
	var canonical []byte
	if err = pool.QueryRow(ctx, `SELECT coalesce(string_agg(convert_from(canonical, 'UTF8'), E'\n'), '')::bytea
		FROM innsegl.events`).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	surfaces["the chain's canonical events"] = canonical
	if !bytes.Contains(canonical, []byte(runID)) || !strings.Contains(string(surfaces["the SPIRE entries"]), runID) {
		t.Fatalf("the scan did not see the member's run %s: the surfaces are not the run's", runID)
	}

	principals := map[string]string{
		"organisation id": org.ID, "organisation name": orgName,
		"member id": memberID, "member name": memberName,
		"owner id": ownerID, "owner name": ownerName,
		"invitation code": strings.TrimPrefix(code, "iv_"),
		"sign-in name":    ssoName, "identity provider": strings.TrimPrefix(ssoIssuer, "https://"),
		"provider client id": ssoClient, "provider subject": ssoSubject,
		"provider session": ssoSessHash, "provider connection": conn.ID,
	}
	// The control: the same scan finds every identifier where it is meant to
	// be, in the accounts schema. A scan that could not find them would
	// prove nothing by finding nothing.
	var control string
	if err = pool.QueryRow(ctx, `SELECT (SELECT string_agg(row_to_json(u)::text, '') FROM innsegl_auth.users u) ||
		(SELECT string_agg(row_to_json(a)::text, '') FROM innsegl_auth.accounts a) ||
		(SELECT string_agg(row_to_json(c)::text, '') FROM innsegl_auth.sso_connections c) ||
		(SELECT string_agg(row_to_json(i)::text, '') FROM innsegl_auth.oidc_identities i) ||
		(SELECT string_agg(row_to_json(s)::text, '') FROM innsegl_auth.sessions s)`).Scan(&control); err != nil {
		t.Fatal(err)
	}
	for what, value := range principals {
		if what != "invitation code" && !strings.Contains(strings.ToLower(control), strings.ToLower(value)) {
			t.Fatalf("the control scan did not find the %s", what)
		}
	}
	if g.log.String() == "" {
		t.Fatal("the gateway wrote no log: that surface would be scanned empty")
	}

	for surface, raw := range surfaces {
		lower := bytes.ToLower(raw)
		for what, value := range principals {
			if bytes.Contains(lower, bytes.ToLower([]byte(value))) {
				t.Errorf("%s holds the %s %q", surface, what, value)
			}
		}
	}
	t.Logf("scanned %d surfaces (%d ledger tables) for run %s on installation %s", len(surfaces), len(tables), runID, c.id)
}

// spireEntries renders every entry the fake SPIRE server holds.
func spireEntries(f *enFixture) string {
	f.ids.mu.Lock()
	defer f.ids.mu.Unlock()
	var b strings.Builder
	for id, e := range f.ids.entries {
		fmt.Fprintf(&b, "%s %+v\n", id, e)
	}
	return b.String()
}
