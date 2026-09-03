// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// OPS-011, OPS-012, OPS-013 (PROPOSED for doc 07's TC-OPS) — the READ-ONLY half
// of doc 05 §1's ledger: the role `innsegl api` connects as, and the service
// that holds it.
//
// #109 shipped `innsegl-dashboard` as the UI half alone and said why: nothing
// in this module constructed an `api.Server`, so there was nothing to put in a
// container, and the stack provisioned no read-only role for one to hold. #121
// landed `innsegl api`. What was still missing is the other end of the wire —
// deploy/compose/innsegl/db-init.sh provisioned ONLY the append-only role, so
// `innsegl api` in the reference stack would have exited 11 (no such role) or,
// handed the appender by a copied line, 13 (WRITABLE).
//
// THE MEASUREMENT THE WHOLE CHECK RESTS ON, and the reason OPS-011 probes two
// credentials rather than one. On postgres:16, against the shipped migrations:
//
//	role      statement                     SQLSTATE
//	reader    UPDATE innsegl.events         42501  permission denied (the ACL)
//	reader    DELETE FROM innsegl.events    42501  permission denied (the ACL)
//	reader    INSERT INTO innsegl.events    42501  permission denied (the ACL)
//	owner     UPDATE innsegl.events         IN001  the append-only trigger
//	owner     DELETE FROM innsegl.events    IN001  the append-only trigger
//	owner     INSERT INTO innsegl.events    IN002  the chain-link trigger
//
// BOTH are refused. Only one is refused BY PRIVILEGE. A check that asked "did
// the write fail?" would pass the database OWNER — the exact credential the
// gate exists to catch — because migration 0001's triggers refuse it too. So
// this file asserts BOTH halves: the reader must be refused by 42501, and the
// owner must NOT be, so the case fails loudly if the distinction ever
// collapses into "it errored, therefore it is read-only".
// ---------------------------------------------------------------------------

// probeOutcome is one attempted write, as evidence rather than as a verdict.
//
// `allowed` is true when the ACL did NOT stop the statement — including when
// the statement got past the ACL and was then refused by one of the ledger's
// own triggers. internal/api/readonly.go's rule, and the reason it is the right
// one is the table above.
type probeOutcome struct {
	allowed  bool
	sqlstate string
	detail   string
}

// probe attempts one statement in a transaction it always rolls back.
//
// `SET TRANSACTION READ WRITE` runs first so that a refusal below is the ACL's
// and not `default_transaction_read_only`'s — a setting the reader's role
// carries by default and that any session can turn off for itself, and
// therefore not a boundary.
func probe(ctx context.Context, t *testing.T, conn *pgx.Conn, sql string) probeOutcome {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return probeOutcome{allowed: true, detail: "the probe could not be run: " + err.Error()}
	}
	defer func() { discardRollback(tx.Rollback(ctx)) }()

	if _, err := tx.Exec(ctx, "SET TRANSACTION READ WRITE"); err != nil {
		state := sqlState(err)
		return probeOutcome{
			allowed:  !isPrivilegeRefusal(state),
			sqlstate: state,
			detail:   "refused before the statement ran (" + state + ")",
		}
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		state := sqlState(err)
		if isPrivilegeRefusal(state) {
			return probeOutcome{sqlstate: state, detail: "refused by privilege (" + state + ")"}
		}
		return probeOutcome{allowed: true, sqlstate: state,
			detail: "the ACL allowed the statement; it failed for another reason (" +
				state + "): " + firstLine(err.Error())}
	}
	return probeOutcome{allowed: true, detail: "the statement succeeded and was rolled back"}
}

// readOnlyExpectations is what the query API's credential must and must not be
// able to do. `allowed` is about the ACL and nothing else.
//
// The eight refusals are internal/api/readonly.go's own `writeProbes()`, in its
// order, because those are the eight `api.Open` runs before it will serve a
// single request: if the deployment provisions a role that fails any of them,
// `innsegl api` exits 13 and the dashboard has no backend. The four after them
// are the I4 verbs the append-only role is also refused, kept so that the two
// roles are measured against a comparable list.
var readOnlyExpectations = []struct {
	name    string
	sql     string
	allowed bool
	why     string
}{
	{"read the chain", `SELECT count(*) FROM innsegl.events`, true,
		"internal/api/query.go reads innsegl.events and no other table; a reader " +
			"that cannot SELECT it serves an empty dashboard rather than a read-only one"},

	{"lock innsegl.events for update", `SELECT chain_position FROM innsegl.events FOR UPDATE`, false,
		"the privilege UPDATE needs, taken without an UPDATE statement. readonly.go " +
			"probes this rather than UPDATE because migration 0001's statement trigger " +
			"refuses an UPDATE for EVERY role, the owner included"},
	{"insert into innsegl.events", probeInsertEvent, false,
		"FD §7: the dashboard holds no credential capable of writing anywhere"},
	{"lock innsegl.chain for update", `SELECT chain_id FROM innsegl.chain FOR UPDATE`, false,
		"the chain's own identity is written once, by migration 0001"},
	{"insert into innsegl.idempotency", `INSERT INTO innsegl.idempotency
		(idempotency_key, tool, request_digest, status, lease_expires_at)
	 VALUES ('api-write-probe', 'probe',
		 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
		 'in_progress', now())`, false,
		"the replay record is the MCP's, not the query API's"},
	{"delete from innsegl.idempotency",
		`DELETE FROM innsegl.idempotency WHERE idempotency_key = 'api-write-probe'`, false,
		"I4: no deletion, from a credential that faces the public internet least of all"},
	{"create a table in schema innsegl", `CREATE TABLE innsegl.api_write_probe (x int)`, false,
		"a role with CREATE anywhere is a role that can write; \"it has no INSERT on " +
			"innsegl.events\" would be a comforting half of the answer"},
	{"create a table in schema public", `CREATE TABLE public.api_write_probe (x int)`, false,
		"CREATE on public was granted to PUBLIC before Postgres 15 and is still granted " +
			"on the DATABASE, so it has to be revoked rather than assumed"},
	{"create a schema of its own", `CREATE SCHEMA api_write_probe`, false,
		"somewhere to put a table in"},

	{"update the chain", `UPDATE innsegl.events SET run_id = 'x'`, false,
		"I4: no mutation. This is the probe the owner is refused too — by IN001 and " +
			"not by 42501 — and telling those two apart is the whole check"},
	{"delete from the chain", `DELETE FROM innsegl.events WHERE false`, false, "I4: no deletion"},
	{"truncate the chain", `TRUNCATE innsegl.events`, false, "I4: no deletion"},
	{"update an idempotency claim",
		`UPDATE innsegl.idempotency SET status = 'completed' WHERE idempotency_key = 'api-write-probe'`,
		false, "the append-only role settles claims; the reader has no business in that table"},
}

func TestOPS011TheReadOnlyRoleIsProvisionedAndProven(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "OPS-011", "doc 05 §1's read-only role is a security "+
		"control: FD §7 requires a dashboard that holds no credential capable of "+
		"writing anywhere, and reporting a broken dependency as a skip exits zero "+
		"while nothing measured it")
	provision(ctx, t, pg)

	// ---- who the reader is -------------------------------------------------
	reader, err := pgx.Connect(ctx, pg.readerDSN())
	if err != nil {
		t.Fatalf("the read-only credential could not connect at all: %v\n\n"+
			"deploy/compose/innsegl/db-init.sh must provision %s with the grants in "+
			"internal/api/readonly.sql — the same file api.EnsureReadOnlyRole embeds. "+
			"Without it, `innsegl api` in the reference stack exits 11 and the "+
			"dashboard has no backend (#121).", err, readerRole)
	}
	defer func() { discardRollback(reader.Close(ctx)) }()

	var role, superuser, defaultReadOnly string
	if idErr := reader.QueryRow(ctx,
		`SELECT current_user, current_setting('is_superuser'),
		        current_setting('default_transaction_read_only')`,
	).Scan(&role, &superuser, &defaultReadOnly); idErr != nil {
		t.Fatalf("reading the session's own identity: %v", idErr)
	}
	if role != readerRole {
		t.Errorf("connected as %q, wanted %q", role, readerRole)
	}
	if superuser != "off" {
		t.Errorf("the read-only role is a SUPERUSER, which no ACL binds, so every probe "+
			"below would pass it and mean nothing. is_superuser = %q", superuser)
	}
	if defaultReadOnly != "on" {
		t.Errorf("default_transaction_read_only is %q for %s. readonly.sql sets it as "+
			"belt as well as braces — the GRANTs are the enforcement — but its absence "+
			"means the shipped grants were not the ones applied", defaultReadOnly, readerRole)
	}

	// ---- the owner, for contrast -------------------------------------------
	owner, ownerErr := pgx.Connect(ctx, pg.ownerDSN())
	if ownerErr != nil {
		t.Fatalf("connecting as the schema owner: %v", ownerErr)
	}
	defer func() { discardRollback(owner.Close(ctx)) }()

	t.Logf("OPS-011 %-34s %-8s %-8s %-8s %-8s", "probe",
		"reader", "sqlstate", "owner", "sqlstate")
	for _, tc := range readOnlyExpectations {
		got := probe(ctx, t, reader, tc.sql)

		if tc.allowed {
			if !got.allowed {
				t.Errorf("the read-only role cannot %s, and it must: %s.\n  %s",
					tc.name, tc.why, got.detail)
			}
			t.Logf("OPS-011 %-34s allowed  %-8s %-8s %-8s", tc.name, got.sqlstate, "-", "-")
			continue
		}

		if got.allowed {
			t.Errorf("the read-only role is allowed to %s.\nFD §7 requires a credential "+
				"incapable of writing anywhere; %s.\n  %s", tc.name, tc.why, got.detail)
		}
		if got.sqlstate != sqlStateInsufficientPrivilege {
			t.Errorf("%s was refused for %s with SQLSTATE %q, not %s.\nA refusal that is "+
				"not the ACL's is one ALTER TABLE ... DISABLE TRIGGER away from no "+
				"refusal at all: %s.\n  %s",
				tc.name, readerRole, got.sqlstate, sqlStateInsufficientPrivilege,
				tc.why, got.detail)
		}

		// The other half, and the reason this test connects twice. If the owner
		// were ALSO refused by privilege, every probe above would be satisfied
		// by a credential that owns the schema — and "read-only" would mean
		// "the triggers happened to say no".
		asOwner := probe(ctx, t, owner, tc.sql)
		if isPrivilegeRefusal(asOwner.sqlstate) {
			t.Errorf("%s was refused for the OWNER by privilege (%s) as well as for %s.\n"+
				"The whole check rests on those two being different: a gate that could "+
				"not tell them apart would pass the database owner, which is the "+
				"credential it exists to catch.\n  %s",
				tc.name, asOwner.sqlstate, readerRole, asOwner.detail)
		}
		t.Logf("OPS-011 %-34s REFUSED  %-8s %-8s %-8s", tc.name, got.sqlstate,
			allowedWord(asOwner.allowed), dash(asOwner.sqlstate))
	}
}

// ---------------------------------------------------------------------------
// OPS-012 — the reader's gate bites, and the compose stack hands `innsegl api`
// the reader rather than the appender.
//
// Two halves, both about not trusting a claim.
//
// FIRST: a checker that never fails is not a check. The role is widened by one
// GRANT — the exact "just fix one thing" an operator does, invisible to any
// amount of code review — and deploy/compose/innsegl/verify-reader-role.sh has
// to catch it and NAME it.
//
// SECOND: the DSN. cmd/innsegl/api.go names the query API's variable
// $INNSEGL_API_DSN and says why in the source: "$INNSEGL_LEDGER_DSN is the
// APPENDING credential every other subcommand takes; this process must not be
// given it [...] One name for two different roles is a deployment that can hand
// the dashboard the writer by copying a line." This asserts the compose file
// did not copy that line.
// ---------------------------------------------------------------------------

func TestOPS012TheReaderGateBitesAndTheStackHandsItTheReader(t *testing.T) {
	root := repoRoot(t)
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "innsegl.yml"))

	// ---- the service exists ------------------------------------------------
	services := composeServices(t, filepath.Join(root, "deploy", "compose", "innsegl.yml"))
	if !contains(services, "innsegl-api") {
		t.Fatalf("deploy/compose/innsegl.yml declares no `innsegl-api` service.\n"+
			"doc 05 §1's innsegl-dashboard row is \"Read-only UI + BFF proof checks\"; "+
			"#109 shipped the UI half because no `main` constructed an api.Server and "+
			"the stack provisioned no read-only role. #121 landed `innsegl api`. "+
			"Declared services: %v", services)
	}

	// ---- and it holds the READER, never the appender -----------------------
	//
	// Measured on the SETTINGS and not on the prose: this file argues at length
	// about why the appending credential must not appear here, and a check that
	// grepped the comments would be satisfied by the argument rather than by
	// the configuration — or, worse, refuse the argument for making it.
	block := stripComments(composeServiceBlock(t, stack, "innsegl-api"))
	for _, want := range []struct{ needle, why string }{
		{"INNSEGL_API_DSN",
			"cmd/innsegl/api.go reads the query API's DSN from this variable and no other"},
		{readerRole,
			"the DSN has to name doc 05 §1's read-only role; `innsegl api` handed the " +
				"appender exits 13 WRITABLE and publishes no address"},
		{`command: ["api"]`,
			"the image has no default subcommand: five rows differ only by `command:`"},
	} {
		if !strings.Contains(block, want.needle) {
			t.Errorf("the innsegl-api service never mentions %q: %s\n\n%s",
				want.needle, want.why, block)
		}
	}
	if strings.Contains(block, "INNSEGL_LEDGER_DSN") {
		t.Errorf("the innsegl-api service sets $INNSEGL_LEDGER_DSN, which is the APPENDING "+
			"credential.\ncmd/innsegl/api.go named the query API's variable "+
			"$INNSEGL_API_DSN precisely so a compose file cannot hand the dashboard the "+
			"writer by copying a line, and `innsegl api` would exit 13 rather than "+
			"serve.\n\n%s", block)
	}
	if strings.Contains(block, appenderRole) {
		t.Errorf("the innsegl-api service names %s. The query API must connect as %s.\n\n%s",
			appenderRole, readerRole, block)
	}

	// ---- the provisioning and its proof both ship --------------------------
	for _, rel := range []struct{ path, why string }{
		{filepath.Join("deploy", "compose", "innsegl", "verify-reader-role.sh"),
			"internal/api/readonly.sql is the model, and its lesson is that the " +
				"provisioning and the assertion are two things: a role that is granted " +
				"and never probed is a role somebody's later GRANT silently widens"},
	} {
		if _, err := os.Stat(filepath.Join(root, rel.path)); err != nil {
			t.Errorf("%s must ship: %s: %v", rel.path, rel.why, err)
		}
	}

	// A SECOND COPY OF THE GRANTS WOULD BE THE WRONG ANSWER, and this is what
	// keeps it from being written by accident: readonly.sql reaches the
	// container by mount, exactly as migrations/ does, and the compose file has
	// to say so.
	if !strings.Contains(stack, "internal/api/readonly.sql") {
		t.Errorf("deploy/compose/innsegl.yml never mounts internal/api/readonly.sql.\n" +
			"The read-only grants must reach the container as THE file " +
			"api.EnsureReadOnlyRole embeds — a second copy under deploy/ is a " +
			"read-only posture that can drift from the one the API's own start-up " +
			"assertion measures against, which is the reason migrations/ is mounted " +
			"rather than copied.")
	}

	// ---- the gate ----------------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "OPS-012", "a gate that cannot be made to fail is not a gate")
	provision(ctx, t, pg)

	if out, gateErr := pg.runInit(ctx, "verify-reader-role.sh"); gateErr != nil {
		t.Fatalf("verify-reader-role.sh rejected the role db-init.sh had just "+
			"provisioned: %v\n%s", gateErr, out)
	} else {
		t.Logf("--- verify-reader-role.sh, as provisioned ---\n%s", out)
	}

	if grantErr := pg.psqlAsOwner(ctx,
		`GRANT INSERT ON innsegl.events TO `+readerRole); grantErr != nil {
		t.Fatalf("widening the role for the negative case: %v", grantErr)
	}
	out, wideErr := pg.runInit(ctx, "verify-reader-role.sh")
	if wideErr == nil {
		t.Errorf("verify-reader-role.sh passed a role holding INSERT on innsegl.events.\n"+
			"That is the credential `innsegl api` refuses to hold, and the single GRANT "+
			"#109 is about — caught only by asking the server.\n%s", out)
	}
	if !strings.Contains(out, "insert into innsegl.events") {
		t.Errorf("verify-reader-role.sh refused but never named the insert; an operator "+
			"has to be told which privilege to revoke.\n%s", out)
	}
	t.Logf("--- verify-reader-role.sh, one GRANT later ---\n%s", out)
	if revokeErr := pg.psqlAsOwner(ctx,
		`REVOKE INSERT ON innsegl.events FROM `+readerRole); revokeErr != nil {
		t.Fatalf("restoring the role: %v", revokeErr)
	}
}

// ---------------------------------------------------------------------------
// OPS-013 — the SHIPPED binary, on the role the SHIPPED deployment provisioned:
// `innsegl api` binds, `GET /api/v1/health` reports the reader, and the same
// binary handed the appending credential exits 13 rather than serving.
//
// This is the case that makes the other two matter. OPS-011 measures the ACL
// and OPS-012 measures the compose file; neither would notice a role that is
// perfectly read-only and that `api.Open`'s own probe set still rejects — or a
// deployment whose reader exists but whose API cannot bind behind it.
//
// It runs the binary directly against the container's published loopback port
// rather than raising the compose stack: #100 caps this machine at roughly
// twenty-nine docker networks, and what is under test here is the credential
// and the process, neither of which needs a bridge to be true.
// ---------------------------------------------------------------------------

func TestOPS013TheShippedAPIBindsOnTheReaderAndRefusesTheAppender(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "OPS-013", "the dashboard's backend is measured against a "+
		"real server or not at all: a mocked ACL proves nothing about what a GRANT permits")
	provision(ctx, t, pg)

	bin := buildInnsegl(ctx, t)

	// ---- the reader: it binds, and /health says so -------------------------
	addr, stop := startAPI(ctx, t, bin, pg.readerDSN())
	defer stop()

	health := fetchHealth(ctx, t, addr)
	if health.Database.Role != readerRole {
		t.Errorf("GET /api/v1/health reports role %q, wanted %q.\nThe health surface is "+
			"where doc 05 §1's \"no write credentials mounted\" stops being a claim and "+
			"becomes something an operator can read back.", health.Database.Role, readerRole)
	}
	if health.Database.Superuser {
		t.Errorf("GET /api/v1/health reports a SUPERUSER credential, which no ACL binds")
	}
	if len(health.Database.Probes) == 0 {
		t.Errorf("GET /api/v1/health carries no write probes; the report IS the evidence")
	}
	for _, p := range health.Database.Probes {
		if p.Allowed {
			t.Errorf("the API is serving on a credential allowed to %q — api.Open should "+
				"have refused it: %s", p.Name, p.Detail)
		}
		if p.SQLState != sqlStateInsufficientPrivilege {
			t.Errorf("probe %q was refused with SQLSTATE %q, not %s; only the ACL's "+
				"refusal is a privilege boundary", p.Name, p.SQLState,
				sqlStateInsufficientPrivilege)
		}
	}
	t.Logf("OPS-013 bound on %s; /api/v1/health role=%s superuser=%v "+
		"default_transaction_read_only=%v writes_refused=%d",
		addr, health.Database.Role, health.Database.Superuser,
		health.Database.DefaultTransactionReadOnly, len(health.Database.Probes))
	stop()

	// ---- the appender: 13, and nothing served ------------------------------
	for _, tc := range []struct{ name, dsn string }{
		{"the appending credential", pg.appenderDSN()},
		{"the schema owner", pg.ownerDSN()},
	} {
		code, out := runAPIOnce(ctx, t, bin, tc.dsn)
		if code != 13 {
			t.Errorf("`innsegl api` handed %s exited %d, wanted 13 (WRITABLE).\n"+
				"cmd/innsegl/api.go: \"Retrying will NEVER help; a human must fix the "+
				"role.\" An API that came up on this credential would be a dashboard "+
				"whose read-only property is a claim about its source code rather than "+
				"about its deployment (FD §7, doc 06 P6).\n%s", tc.name, code, out)
		}
		if !strings.Contains(out, "WRITABLE") {
			t.Errorf("`innsegl api` refused %s without saying WRITABLE:\n%s", tc.name, out)
		}
		t.Logf("OPS-013 %s -> exit %d", tc.name, code)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// healthBody mirrors internal/api's Health, read off the wire rather than
// imported: what an operator and a reverse proxy see is the JSON.
type healthBody struct {
	Database struct {
		Role                       string `json:"role"`
		Superuser                  bool   `json:"superuser"`
		DefaultTransactionReadOnly bool   `json:"default_transaction_read_only"`
		Probes                     []struct {
			Name     string `json:"name"`
			Allowed  bool   `json:"allowed"`
			SQLState string `json:"sqlstate"`
			Detail   string `json:"detail"`
		} `json:"probes"`
	} `json:"database"`
	Repos []string `json:"repos"`
}

// ledgerForTest is the #101 outcome shape, once, for the three cases above.
func ledgerForTest(ctx context.Context, t *testing.T, id, why string) *ledgerContainer {
	t.Helper()
	pg, err := startLedger(ctx, t)
	skip, failure := startupOutcome(err)
	if pg != nil {
		t.Cleanup(pg.stop)
	}
	switch containerRequirement(pg != nil, skip, failure) {
	case failTest:
		t.Fatalf("the ledger's Postgres did not start on a machine that has Docker: %s\n\n"+
			"This is a FAILURE and not a skip (#101). %s.", failure, why)
	case skipTest:
		t.Skipf("skipping %s: %s. %s. Start Docker and re-run.", id, skip, why)
	case proceed:
	}
	return pg
}

// provision runs the SHIPPED bootstrap and nothing else.
func provision(ctx context.Context, t *testing.T, pg *ledgerContainer) {
	t.Helper()
	if err := pg.copyDeployScripts(ctx, repoRoot(t)); err != nil {
		t.Fatalf("staging the shipped deploy scripts: %v", err)
	}
	out, err := pg.runInit(ctx, "db-init.sh")
	t.Logf("--- deploy/compose/innsegl/db-init.sh ---\n%s", out)
	if err != nil {
		t.Fatalf("db-init.sh failed: %v", err)
	}
}

// buildInnsegl compiles the binary this repository ships. Not `go run`: the
// command's exit status is the thing under test, and `go run` reports its own.
func buildInnsegl(ctx context.Context, t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "innsegl")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/innsegl")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the shipped binary: %v\n%s", err, out)
	}
	return bin
}

// apiEnv is the environment deploy/compose/innsegl.yml gives the innsegl-api
// service, minus the DSN, which each case supplies.
//
// A repository is named because `innsegl api` refuses to start without one:
// "a proof BFF that serves no repository can answer nothing, and guessing is
// not one of the states doc 06 §4.6 allows". Nothing here asks it a proof
// question, so the path need only be named.
func apiEnv(dsn string) []string {
	return append(os.Environ(),
		"INNSEGL_API_DSN="+dsn,
		"INNSEGL_API_LISTEN=127.0.0.1:0",
		"INNSEGL_API_REPOS=github.com/innsegl-demo/scratch=/work/github.com/innsegl-demo/scratch",
		"INNSEGL_FULCIO_URL=http://127.0.0.1:1/fulcio",
		"INNSEGL_REKOR_URL=http://127.0.0.1:1/rekor",
		"INNSEGL_OIDC_ISSUER=",
	)
}

// startAPI runs `innsegl api` and returns the address it printed on stdout.
func startAPI(ctx context.Context, t *testing.T, bin, dsn string) (string, func()) {
	t.Helper()
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, bin, "api")
	cmd.Env = apiEnv(dsn)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("wiring the API's stdout: %v", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if startErr := cmd.Start(); startErr != nil {
		cancel()
		t.Fatalf("starting `innsegl api`: %v", startErr)
	}

	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		discardWait(cmd.Wait())
	}
	t.Cleanup(stop)

	// The bound address is one line on stdout and nothing else — `serve`'s
	// contract, and what makes `-listen 127.0.0.1:0` usable from a script.
	line := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 64)
		one := make([]byte, 1)
		for {
			n, rerr := stdout.Read(one)
			if n == 1 {
				if one[0] == '\n' {
					break
				}
				buf = append(buf, one[0])
				continue
			}
			if rerr != nil {
				break
			}
		}
		line <- string(buf)
	}()

	select {
	case addr := <-line:
		if addr == "" {
			stop()
			t.Fatalf("`innsegl api` published no address before exiting.\n%s", stderr.String())
		}
		return addr, stop
	case <-time.After(90 * time.Second):
		stop()
		t.Fatalf("`innsegl api` never published an address.\n%s", stderr.String())
	}
	return "", stop
}

// runAPIOnce runs the command to completion and returns its exit status.
func runAPIOnce(ctx context.Context, t *testing.T, bin, dsn string) (int, string) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, "api")
	cmd.Env = apiEnv(dsn)
	out, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		t.Fatalf("`innsegl api` did not run: %v\n%s", err, out)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

func fetchHealth(ctx context.Context, t *testing.T, addr string) healthBody {
	t.Helper()
	url := "http://" + addr + "/api/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building the health request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { discardRollback(resp.Body.Close()) }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d", url, resp.StatusCode)
	}
	var body healthBody
	if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr != nil {
		t.Fatalf("decoding the health body: %v", decErr)
	}
	return body
}

// composeServiceBlock returns one service's lines from a compose file, from its
// two-space key to the next one. The shipped files are hand written with that
// convention (topology_test.go's serviceLine relies on it too), which buys this
// package no YAML dependency.
func composeServiceBlock(t *testing.T, body, service string) string {
	t.Helper()
	lines := strings.Split(body, "\n")
	start := -1
	for i, line := range lines {
		if line == "  "+service+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no `%s:` service key in the compose file", service)
	}
	for i := start + 1; i < len(lines); i++ {
		if m := serviceLine.FindStringSubmatch(lines[i]); m != nil {
			return strings.Join(lines[start:i], "\n")
		}
		if lines[i] != "" && !strings.HasPrefix(lines[i], " ") &&
			!strings.HasPrefix(lines[i], "#") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// stripComments drops whole-line `#` comments, so an assertion about what a
// service is CONFIGURED to do cannot be satisfied — or defeated — by what the
// file says about it.
func stripComments(block string) string {
	var kept []string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func allowedWord(allowed bool) string {
	if allowed {
		return "ALLOWED"
	}
	return "REFUSED"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// discardWait swallows the exit error of a process this test killed on purpose.
// errcheck runs with check-blank here, so the discard is a named function
// (internal/api/readonly.go's idiom).
func discardWait(error) {}
