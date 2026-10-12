// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

// The enroller credential, and the proof that it is no more than that.
//
// RM-355 (#603): the core enrols, renews and revokes client machines. It did
// that as the auth-writer, the API's sign-in credential, which may read and
// write users, passkeys and sessions. A compromised core could mint itself a
// dashboard user. The enroller holds only the statements the core's own code
// paths issue (enroller.sql lists them), and AssertEnrollerScope asks the
// server, at every core start, both that it can enrol and that it reaches no
// further: the auth-writer handed to the core by a copied line is refused.

// EnrollerRole is the Postgres role the core's enrolment connects as. A
// default, not a protected string, exactly as AuthWriterRole is.
const EnrollerRole = "innsegl_enroller"

//go:embed enroller.sql
var enrollerGrants string

// ErrEnrollerCannotEnrol is an enroller credential that cannot make one of
// enrolment's own writes. Holding it would turn every enrolment into a 503.
var ErrEnrollerCannotEnrol = errors.New("api: the enroller credential cannot enrol a machine")

// The probes AssertEnrollerScope adds to AssertReadOnly's ledger probes. The
// enrol* ones must be allowed; every other one must be refused. Each touches
// no row: WHERE false, or INSERT ... SELECT ... WHERE false. They are probe
// names, not credentials.
//
//nolint:gosec // G101: "token" and "passkeys" name tables here, not secrets.
const (
	probeEnrolSpendToken        = "spend an enrolment token"
	probeEnrolInsertInstall     = "insert an installation"
	probeEnrolUpdateInstall     = "renew or revoke an installation"
	probeEnrolAudit             = "append an audit row"
	probeEnrollerReadUsers      = "read innsegl_auth.users"
	probeEnrollerReadPasskeys   = "read innsegl_auth.passkeys"
	probeEnrollerReadSessions   = "read innsegl_auth.sessions"
	probeEnrollerMintToken      = "insert into innsegl_auth.enrolment_tokens"
	probeEnrollerDeleteInstall  = "delete from innsegl_auth.installations"
	probeEnrollerRenameInstall  = "update an installation's name or repositories"
	probeEnrollerAddMember      = "insert into innsegl_auth.memberships"
	probeEnrollerCreateAccount  = "insert into innsegl_auth.accounts"
	probeEnrollerRewriteAudit   = "update innsegl_auth.audit"
	probeEnrollerEndGrant       = "update innsegl_auth.repo_grants"
	probeEnrollerReadEnrolCodes = "read innsegl_auth.enrolment_codes"
)

func enrollerProbes() (must, mustNot []Probe) {
	must = []Probe{
		{probeEnrolSpendToken, `UPDATE innsegl_auth.enrolment_tokens
			SET used_at = clock_timestamp(), installation_id = installation_id WHERE false`},
		{probeEnrolInsertInstall, `INSERT INTO innsegl_auth.installations
			(installation_id, account_id, created_by, name, kind, repos)
			SELECT installation_id, account_id, created_by, name, kind, repos
			  FROM innsegl_auth.installations WHERE false`},
		{probeEnrolUpdateInstall, `UPDATE innsegl_auth.installations
			SET last_renewed_at = clock_timestamp(), status = status, revoked_at = revoked_at WHERE false`},
		{probeEnrolAudit, `INSERT INTO innsegl_auth.audit (actor, account_id, action, subject, detail)
			SELECT NULL, NULL, 'probe', '', '{}'::jsonb WHERE false`},
	}
	mustNot = []Probe{
		{probeEnrollerReadUsers, `SELECT user_id FROM innsegl_auth.users WHERE false`},
		{probeEnrollerReadPasskeys, `SELECT 1 FROM innsegl_auth.passkeys WHERE false`},
		{probeEnrollerReadSessions, `SELECT 1 FROM innsegl_auth.sessions WHERE false`},
		{probeEnrollerReadEnrolCodes, `SELECT 1 FROM innsegl_auth.enrolment_codes WHERE false`},
		{probeEnrollerMintToken, `INSERT INTO innsegl_auth.enrolment_tokens
			SELECT * FROM innsegl_auth.enrolment_tokens WHERE false`},
		{probeEnrollerDeleteInstall, `DELETE FROM innsegl_auth.installations WHERE false`},
		{probeEnrollerRenameInstall, `UPDATE innsegl_auth.installations SET name = name, repos = repos WHERE false`},
		{probeEnrollerAddMember, `INSERT INTO innsegl_auth.memberships (user_id, account_id, role)
			SELECT NULL, NULL, NULL WHERE false`},
		{probeEnrollerCreateAccount, `INSERT INTO innsegl_auth.accounts (account_id, name)
			SELECT NULL, NULL WHERE false`},
		{probeEnrollerRewriteAudit, `UPDATE innsegl_auth.audit SET action = action WHERE false`},
		{probeEnrollerEndGrant, `UPDATE innsegl_auth.repo_grants SET until = clock_timestamp() WHERE false`},
	}
	return must, mustNot
}

// EnrollerReport is what AssertEnrollerScope established: the ledger probes
// AssertReadOnly runs, and the enroller's own.
type EnrollerReport struct {
	Ledger ReadOnlyReport `json:"ledger"`
	Probes []ProbeResult  `json:"probes"`
}

// EnsureEnrollerRole creates the role if it is absent and applies
// enroller.sql to it, using an ADMINISTRATIVE dsn — operator tooling, like
// EnsureAuthWriterRole.
func EnsureEnrollerRole(ctx context.Context, adminDSN, role, password string) error {
	return ensureRole(ctx, adminDSN, role, password, enrollerGrants, "enroller")
}

// AssertEnrollerScope asks the server what the enroller credential may do. It
// refuses, wrapping ErrWritable, a credential that can write the ledger or
// reach beyond enrolment (the auth-writer is one), and refuses, wrapping
// ErrEnrollerCannotEnrol, one that cannot make enrolment's own writes. Every
// probe is rolled back and touches no row.
func AssertEnrollerScope(ctx context.Context, c conn) (EnrollerReport, error) {
	var report EnrollerReport
	ledgerReport, err := AssertReadOnly(ctx, c)
	report.Ledger = ledgerReport
	if err != nil {
		return report, fmt.Errorf("api: the enroller credential can write the ledger schema: %w", err)
	}
	must, mustNot := enrollerProbes()
	var beyond, missing []string
	for _, p := range mustNot {
		r := probeOnce(ctx, c, p)
		report.Probes = append(report.Probes, r)
		if r.Allowed {
			beyond = append(beyond, p.Name)
		}
	}
	for _, p := range must {
		r := probeOnce(ctx, c, p)
		report.Probes = append(report.Probes, r)
		if !r.Allowed {
			missing = append(missing, p.Name)
		}
	}
	if len(beyond) > 0 {
		return report, fmt.Errorf("%w: the enroller role %q is allowed to: %s. It may enrol, renew and "+
			"revoke machines and nothing else; the core must not hold the auth-writer. Provision it "+
			"with EnsureEnrollerRole", ErrWritable, report.Ledger.Role, strings.Join(beyond, "; "))
	}
	if len(missing) > 0 {
		return report, fmt.Errorf("%w: the role %q may not: %s; provision it with EnsureEnrollerRole",
			ErrEnrollerCannotEnrol, report.Ledger.Role, strings.Join(missing, "; "))
	}
	return report, nil
}
