// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/spire"
)

// Enrolment and renewal on the gateway's listener (RM-284, #460; ADR-0063).
//
// # The contract
//
//	POST /_core/enrol   no client certificate
//	  {"token":"ie_<16hex>_<64hex>","csr":"<base64 DER PKCS#10>","name":"<display name>"}
//	  200 {"installation_id","certificate" (PEM chain, leaf first),"bundle" (PEM),"expires_at" (RFC3339)}
//	  401 {"error":"innsegl core: enrolment refused"} for every token problem
//	  400 for a malformed body or CSR
//	GET /_core/enrol    no client certificate
//	  200 {"trust_domain":"<td>"}: what a client needs to write its CSR
//	POST /_core/renew   client certificate required
//	  {"csr":"<base64 DER>"} -> the same 200 shape, for the same installation
//
// # The client chooses its installation id
//
// The identity authority takes the SPIFFE ID from the CSR's one URI SAN, and
// the CSR is signed by the client's key, so the core cannot add the SAN
// itself. The client therefore picks a random 32-hex id and names
// spiffe://<td>/client/<id> in its CSR; enrolment creates the installation
// under that id, and refuses an id already in use without spending the
// token.
//
// # Order: a failed mint burns nothing
//
// The CSR is checked first, before the token is looked at, so a malformed
// request costs the client nothing. Then the token is spent, the
// installation created and the certificate minted in ONE transaction
// (accounts.Store.Enrol): a failed mint rolls the transaction back, so the
// token is unspent and no installation exists. A commit that fails after a
// successful mint leaves a certificate for an installation that does not
// exist, which the guard refuses on every request.
//
// # The minter is the MCP's own admin client (MCP-096)
//
// IP §1: the MCP is the only holder of SPIRE admin credentials. `serve`
// publishes the admin client it already dialled (publishClientAuthority,
// servewiring.go), and the gateway companion running in the same process
// mints through it. The gateway dials no admin identity of its own; hosted
// mode refuses to start where none was published.

const (
	coreEnrolPath = "/_core/enrol"
	coreRenewPath = "/_core/renew"

	// enrolRefusal is the one answer for every token problem.
	enrolRefusal = "innsegl core: enrolment refused"
	// maxEnrolBody bounds an enrolment or renewal body: a token, a CSR and
	// a name.
	maxEnrolBody = 64 << 10
)

// clientAuthority is what enrolment and the guard need from the identity
// authority. *spire.Client is one.
type clientAuthority interface {
	TrustDomain() string
	MintClientX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) (chain, bundle []*x509.Certificate, err error)
	X509Bundle(ctx context.Context) ([]*x509.Certificate, error)
}

var _ clientAuthority = (*spire.Client)(nil)

var publishedAuthority struct {
	mu sync.Mutex
	a  clientAuthority
}

// publishClientAuthority makes a the authority the gateway companion mints
// through, and answers a function restoring the previous one. serve calls it
// with the MCP's own admin client.
func publishClientAuthority(a clientAuthority) (restore func()) {
	publishedAuthority.mu.Lock()
	defer publishedAuthority.mu.Unlock()
	prev := publishedAuthority.a
	publishedAuthority.a = a
	return func() {
		publishedAuthority.mu.Lock()
		defer publishedAuthority.mu.Unlock()
		publishedAuthority.a = prev
	}
}

func publishedClientAuthority() clientAuthority {
	publishedAuthority.mu.Lock()
	defer publishedAuthority.mu.Unlock()
	return publishedAuthority.a
}

// enrolStore is the accounts writer. *accounts.Store is one.
type enrolStore interface {
	Enrol(ctx context.Context, p accounts.EnrolParams, issue accounts.IssueFunc) (accounts.Installation, error)
	Renew(ctx context.Context, installationID string, issue accounts.IssueFunc) (accounts.Installation, error)
}

// issuedCertificate is the 200 answer of enrol and renew.
type issuedCertificate struct {
	InstallationID string `json:"installation_id"`
	Certificate    string `json:"certificate"`
	Bundle         string `json:"bundle"`
	ExpiresAt      string `json:"expires_at"`
}

func writeCoreJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// A failed write means the caller has gone; there is no one left to tell.
	discardCoreWrite(json.NewEncoder(w).Encode(v))
}

// discardCoreWrite is the named discard for a response write that failed.
func discardCoreWrite(error) {}

func writeCoreError(w http.ResponseWriter, status int, msg string) {
	writeCoreJSON(w, status, map[string]string{"error": msg})
}

// decodeCSR reads a base64 DER CSR and checks it names exactly one client
// identity in the trust domain. It answers the DER and the installation id.
func decodeCSR(raw, trustDomain string) ([]byte, string, bool) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(der) == 0 {
		return nil, "", false
	}
	id, err := spire.CheckClientCSR(der, trustDomain)
	if err != nil {
		return nil, "", false
	}
	return der, id, true
}

// mint has the authority mint for der and renders the answer.
func mint(ctx context.Context, authority clientAuthority, der []byte, id string) (issuedCertificate, error) {
	chain, bundle, err := authority.MintClientX509SVID(ctx, der, spire.ClientCertTTL)
	if err != nil {
		return issuedCertificate{}, err
	}
	if len(chain) == 0 || len(bundle) == 0 {
		return issuedCertificate{}, errors.New("the authority answered no certificate or no bundle")
	}
	return issuedCertificate{
		InstallationID: id,
		Certificate:    pemCerts(chain),
		Bundle:         pemCerts(bundle),
		ExpiresAt:      chain[0].NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func pemCerts(certs []*x509.Certificate) string {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return string(b)
}

// enrolHandler serves /_core/enrol, the one route reachable without a
// client certificate.
func enrolHandler(store enrolStore, authority clientAuthority, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeCoreJSON(w, http.StatusOK, map[string]string{"trust_domain": authority.TrustDomain()})
			return
		case http.MethodPost:
		default:
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: enrol: only GET and POST are accepted")
			return
		}
		var in struct {
			Token string `json:"token"`
			CSR   string `json:"csr"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrolBody)).Decode(&in); err != nil {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: enrol: a JSON body with token, csr and name is required")
			return
		}
		name := strings.TrimSpace(in.Name)
		if name == "" || len(name) > 256 {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: enrol: name must be 1 to 256 bytes")
			return
		}
		der, id, ok := decodeCSR(in.CSR, authority.TrustDomain())
		if !ok {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: enrol: csr must be a base64 DER certificate "+
				"request, signed by its key, naming exactly spiffe://"+authority.TrustDomain()+"/client/<32 lowercase hex>")
			return
		}

		var out issuedCertificate
		var mintErr error
		_, err := store.Enrol(r.Context(), accounts.EnrolParams{Token: in.Token, InstallationID: id, Name: name},
			func(ctx context.Context, _ accounts.Installation) error {
				out, mintErr = mint(ctx, authority, der, id)
				return mintErr
			})
		switch {
		case err == nil:
		case errors.Is(err, accounts.ErrTokenInvalid):
			log.info("enrolment refused")
			writeCoreError(w, http.StatusUnauthorized, enrolRefusal)
			return
		case errors.Is(err, accounts.ErrInvalid):
			writeCoreError(w, http.StatusBadRequest, "innsegl core: enrol: that installation id cannot be used; "+
				"choose another random id")
			return
		case mintErr != nil:
			log.warn("enrolment could not be issued; the token is unspent", "err", mintErr)
			writeCoreError(w, http.StatusServiceUnavailable,
				"innsegl core: the certificate could not be issued; nothing was enrolled and the token is unspent")
			return
		default:
			log.warn("enrolment failed", "err", err)
			writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: enrolment is unavailable; retry")
			return
		}
		log.info("installation enrolled", "installation_id", id)
		writeCoreJSON(w, http.StatusOK, out)
	}
}

// renewHandler serves /_core/renew, behind the client guard: the request
// carries the verified installation, and the CSR must name the same one.
func renewHandler(store enrolStore, authority clientAuthority, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: renew: only POST is accepted")
			return
		}
		inst, ok := gateway.InstallationFromContext(r.Context())
		if !ok {
			gateway.WriteClientRefusal(w)
			return
		}
		var in struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrolBody)).Decode(&in); err != nil {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: renew: a JSON body with csr is required")
			return
		}
		der, id, ok := decodeCSR(in.CSR, authority.TrustDomain())
		if !ok {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: renew: csr must be a base64 DER certificate "+
				"request naming this installation's own SPIFFE ID")
			return
		}
		if id != inst {
			gateway.WriteClientRefusal(w)
			return
		}
		var out issuedCertificate
		var mintErr error
		_, err := store.Renew(r.Context(), inst, func(ctx context.Context, _ accounts.Installation) error {
			out, mintErr = mint(ctx, authority, der, id)
			return mintErr
		})
		switch {
		case err == nil:
		case errors.Is(err, accounts.ErrNotFound):
			gateway.WriteClientRefusal(w)
			return
		default:
			log.warn("renewal failed", "installation_id", inst, "err", err)
			writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: renewal is unavailable; retry")
			return
		}
		log.info("installation renewed", "installation_id", inst)
		writeCoreJSON(w, http.StatusOK, out)
	}
}

// accountsInstallations adapts the accounts store to the guard's reader.
type accountsInstallations struct{ store *accounts.Store }

func (a accountsInstallations) InstallationActive(ctx context.Context, id string) (bool, error) {
	inst, err := a.store.GetInstallation(ctx, id)
	if errors.Is(err, accounts.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inst.Status == accounts.StatusActive, nil
}

func (a accountsInstallations) InScope(ctx context.Context, id, repo string) (bool, error) {
	return a.store.InScope(ctx, id, repo)
}

// repoClaimer is the accounts writer's first-use grant. *accounts.Store is
// one.
type repoClaimer interface {
	ClaimRepo(ctx context.Context, installationID, repo string) (bool, error)
}

// firstUseScope is hosted mode's one repository rule (ADR-0063, amended
// 2026-10-02), for the identity guard, the session statement, the commit
// path and the mirror push alike: an installation may act on a repository
// its organisation holds, and a repository no organisation holds becomes its
// organisation's on first use. The read is the gateway's own role, which may
// only SELECT; the grant goes through the accounts writer, audited with the
// installation as the actor. Another organisation's live grant, an explicit
// repos list that leaves the repository out, or an installation that is not
// active are out of scope.
type firstUseScope struct {
	reader gateway.ScopeChecker
	writer repoClaimer
}

func (s firstUseScope) InScope(ctx context.Context, installationID, repo string) (bool, error) {
	in, err := s.reader.InScope(ctx, installationID, repo)
	if err != nil || in {
		return in, err
	}
	return s.writer.ClaimRepo(ctx, installationID, repo)
}

// hostedCallers is the session endpoints' admission in hosted mode: the
// client guard has already verified the installation; a statement that names
// a repository must name one in its scope (claimed on first use), a statement
// that names none is a session outside any repository and is admitted, and a
// session belongs to the first installation that named it.
type hostedCallers struct {
	scope gateway.ScopeChecker
	pins  *gateway.SessionPins
}

func (h hostedCallers) admitRequest(r *http.Request) bool {
	_, ok := gateway.InstallationFromContext(r.Context())
	return ok
}

func (h hostedCallers) refuseCaller(w http.ResponseWriter, _ string) { gateway.WriteClientRefusal(w) }

func (h hostedCallers) rateKey(r *http.Request, base string) string {
	inst, _ := gateway.InstallationFromContext(r.Context())
	return base + ":" + inst
}

// admitStatement pins the session first: a session that is another
// installation's is refused whatever it states. A repository outside the
// installation's scope is out of scope: the session is the caller's, and
// runs unrecorded (RM-313).
func (h hostedCallers) admitStatement(ctx context.Context, sessionID string, st gateway.StatedWorkspace) (gateway.StatementVerdict, error) {
	inst, ok := gateway.InstallationFromContext(ctx)
	if !ok || !h.pins.Pin(sessionID, inst) {
		return gateway.StatementRefused, nil
	}
	if st.HasRepo() {
		in, err := h.scope.InScope(ctx, inst, st.Repo)
		if err != nil {
			return gateway.StatementRefused, err
		}
		if !in {
			return gateway.StatementOutOfScope, nil
		}
	}
	return gateway.StatementAdmitted, nil
}

func (h hostedCallers) admitSession(ctx context.Context, sessionID string) bool {
	inst, ok := gateway.InstallationFromContext(ctx)
	return ok && h.pins.Pin(sessionID, inst)
}
