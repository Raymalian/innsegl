// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

// Client identities (RM-300, #476).
//
// An enrolled installation holds a short-lived X509-SVID under
//
//	spiffe://{trust-domain}/client/{32 lowercase hex}
//
// minted by the deployment's SPIRE server through the MCP's admin credential.
// No client runs a SPIRE agent. A client identity never signs: SPIRE's
// authorization policy (deploy/compose/spire/authz-policy.rego) admits
// MintX509SVID from the admin identity only for this path, and keeps
// MintJWTSVID on the five-segment /agent/ run path.
//
// The refusals here run before any call, but they are not the control. A
// stolen admin credential does not run this code; the policy is what refuses
// it (SPI-022).

// ClientCertTTL is the longest a client certificate may live. The policy
// enforces the same bound on its side.
const ClientCertTTL = 24 * time.Hour

// clientPathPrefix is the subtree client identities live in.
const clientPathPrefix = "/client/"

var clientIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ClientSPIFFEID renders the client identity for one installation id.
func ClientSPIFFEID(trustDomain, installationID string) (string, error) {
	if !clientIDPattern.MatchString(installationID) {
		return "", newError(ClassInvariantViolation, "client_spiffe_id", "",
			fmt.Sprintf("installation id %q is not 32 lowercase hex characters", installationID), false, nil)
	}
	id := "spiffe://" + trustDomain + clientPathPrefix + installationID
	if _, err := ClientIDOf(id, trustDomain); err != nil {
		return "", err
	}
	return id, nil
}

// ClientIDOf returns the installation id named by a client SPIFFE ID in
// trustDomain, and refuses every other ID, an agent run's included.
func ClientIDOf(spiffeID, trustDomain string) (string, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return "", newError(ClassInvariantViolation, "client_spiffe_id", "",
			fmt.Sprintf("%q is not a URI: %v", spiffeID, err), false, err)
	}
	return clientIDOfURI(u, trustDomain)
}

func clientIDOfURI(u *url.URL, trustDomain string) (string, error) {
	fail := func(why string) (string, error) {
		return "", newError(ClassInvariantViolation, "client_spiffe_id", "",
			fmt.Sprintf("%q is not a client identity in %s: %s", u.String(), trustDomain, why), false, nil)
	}
	switch {
	case u.Scheme != "spiffe":
		return fail("scheme is not spiffe")
	case u.Host != trustDomain || trustDomain == "":
		return fail("wrong trust domain")
	case u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "":
		return fail("carries more than a path")
	}
	rest, ok := strings.CutPrefix(u.Path, clientPathPrefix)
	if !ok || !clientIDPattern.MatchString(rest) {
		return fail("path is not /client/{32 lowercase hex}")
	}
	return rest, nil
}

// CheckClientCSR parses a DER CSR and returns the installation id it asks for.
// It refuses a CSR whose signature does not verify, that names anything but
// exactly one URI, or whose URI is not a client identity in trustDomain.
func CheckClientCSR(csrDER []byte, trustDomain string) (string, error) {
	fail := func(why string, cause error) (string, error) {
		return "", newError(ClassInvariantViolation, "mint_client_svid", "", why, false, cause)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fail(fmt.Sprintf("not a certificate request: %v", err), err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fail(fmt.Sprintf("certificate request signature: %v", err), err)
	}
	if len(csr.DNSNames) > 0 || len(csr.EmailAddresses) > 0 || len(csr.IPAddresses) > 0 {
		return fail("certificate request names a DNS, email or IP subject; a client names only its SPIFFE ID", nil)
	}
	if len(csr.URIs) != 1 {
		return fail(fmt.Sprintf("certificate request names %d URIs, want exactly one", len(csr.URIs)), nil)
	}
	return clientIDOfURI(csr.URIs[0], trustDomain)
}

// MintClientX509SVID has SPIRE mint a client X509-SVID for csrDER, valid for
// ttl (at most ClientCertTTL). It returns the certificate chain, leaf first,
// and the deployment's X.509 bundle to verify it against.
//
// The CSR is checked before the call, and the answer after it: SPIRE must have
// minted exactly the identity asked for, and the chain must verify as a client
// certificate against the bundle.
func (c *Client) MintClientX509SVID(ctx context.Context, csrDER []byte, ttl time.Duration) (chain []*x509.Certificate, bundle []*x509.Certificate, err error) {
	const op = "mint_client_svid"
	if ttl <= 0 || ttl > ClientCertTTL {
		return nil, nil, newError(ClassInvariantViolation, op, "",
			fmt.Sprintf("ttl %v is outside (0, %v]", ttl, ClientCertTTL), false, nil)
	}
	want, err := CheckClientCSR(csrDER, c.trustDomain)
	if err != nil {
		return nil, nil, err
	}

	cctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := svidv1.NewSVIDClient(c.conn).MintX509SVID(cctx, &svidv1.MintX509SVIDRequest{
		Csr: csrDER,
		Ttl: int32(ttl / time.Second),
	})
	if err != nil {
		return nil, nil, classifyAdmin(op, "", err)
	}
	for _, der := range resp.GetSvid().GetCertChain() {
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			return nil, nil, newError(ClassInvariantViolation, op, "",
				fmt.Sprintf("SPIRE returned an unparseable certificate: %v", perr), false, perr)
		}
		chain = append(chain, cert)
	}

	bundle, err = c.x509Bundle(cctx, op)
	if err != nil {
		return nil, nil, err
	}

	got, err := VerifyClientCertificate(chain, bundle, c.trustDomain, time.Now())
	if err != nil {
		return nil, nil, newError(ClassInvariantViolation, op, "",
			fmt.Sprintf("SPIRE's answer is not a valid client certificate: %v", err), false, err)
	}
	if got != want {
		return nil, nil, newError(ClassInvariantViolation, op, "",
			fmt.Sprintf("SPIRE minted installation %s, asked for %s", got, want), false, nil)
	}
	return chain, bundle, nil
}

// X509Bundle reads the deployment's X.509 authorities: the roots a client
// certificate is verified against (VerifyClientCertificate). The gateway's
// client-certificate guard reads it through the MCP's own admin client
// (#460), so the gateway holds no admin identity of its own.
func (c *Client) X509Bundle(ctx context.Context) ([]*x509.Certificate, error) {
	cctx, cancel := c.call(ctx)
	defer cancel()
	return c.x509Bundle(cctx, "x509_bundle")
}

func (c *Client) x509Bundle(ctx context.Context, op string) ([]*x509.Certificate, error) {
	b, err := bundlev1.NewBundleClient(c.conn).GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, classifyAdmin(op, "", err)
	}
	var bundle []*x509.Certificate
	for _, a := range b.GetX509Authorities() {
		cert, perr := x509.ParseCertificate(a.GetAsn1())
		if perr != nil {
			return nil, newError(ClassInvariantViolation, op, "",
				fmt.Sprintf("SPIRE returned an unparseable bundle authority: %v", perr), false, perr)
		}
		bundle = append(bundle, cert)
	}
	return bundle, nil
}

// VerifyClientCertificate checks a presented chain (leaf first) against the
// deployment's X.509 bundle and returns the installation id it names.
//
// It refuses a chain that does not verify to roots at now, a leaf without the
// client-auth extended key usage, a CA leaf, and a leaf whose SANs are anything
// but exactly one client identity in trustDomain. An agent run's SVID is
// therefore refused even though the same authority issued it. A refusal is
// ATTESTATION_FAILED: the presenter is not what it claims.
func VerifyClientCertificate(chain, roots []*x509.Certificate, trustDomain string, now time.Time) (string, error) {
	const op = "verify_client_certificate"
	fail := func(why string, cause error) (string, error) {
		return "", newError(ClassAttestationFailed, op, "", why, false, cause)
	}
	if len(chain) == 0 {
		return fail("no certificate presented", nil)
	}
	if len(roots) == 0 {
		return fail("no trust bundle to verify against", nil)
	}
	leaf := chain[0]
	if leaf.IsCA {
		return fail("the leaf is a CA certificate", nil)
	}
	if len(leaf.DNSNames) > 0 || len(leaf.EmailAddresses) > 0 || len(leaf.IPAddresses) > 0 {
		return fail("the certificate names a DNS, email or IP subject", nil)
	}
	if len(leaf.URIs) != 1 {
		return fail(fmt.Sprintf("the certificate names %d URIs, want exactly one", len(leaf.URIs)), nil)
	}
	id, err := clientIDOfURI(leaf.URIs[0], trustDomain)
	if err != nil {
		return fail(err.Error(), err)
	}
	// x509 treats a leaf with no EKU at all as good for anything. A client
	// certificate has to say it is one.
	if !hasEKU(leaf, x509.ExtKeyUsageClientAuth) {
		return fail("the certificate lacks the client-auth extended key usage", nil)
	}

	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fail(fmt.Sprintf("certificate does not verify as a client certificate: %v", err), err)
	}
	return id, nil
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, u := range c.ExtKeyUsage {
		if u == want {
			return true
		}
	}
	return false
}
