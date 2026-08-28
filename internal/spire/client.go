// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Source supplies the client's own X509-SVID and the trust bundle it verifies
// the server with. In the deployment it is a *workloadapi.X509Source: the MCP
// is an attested workload like any other, and "holding the admin credential"
// means being the container SPIRE attests as innsegl-mcp — not holding a file.
type Source interface {
	x509svid.Source
	x509bundle.Source
}

// Config is what Dial needs.
type Config struct {
	// Address is the SPIRE server API, host:port. ADR-0011: the admin API is
	// not a separate listener, it is the same TCP endpoint separated by
	// authorization, reachable only from the innsegl-spire-admin network.
	Address string
	// TrustDomain is the SPIFFE trust domain name, e.g. "innsegl.dev".
	TrustDomain string
	// ServerID is the SPIFFE ID the server must present. Empty means
	// spiffe://{TrustDomain}/spire/server, which is what SPIRE issues itself.
	ServerID string
	// Source supplies this client's SVID and the trust bundle.
	Source Source
	// Timeout bounds each RPC. Zero means DefaultTimeout. IP §6.3 forbids
	// indefinite hangs; nothing here is allowed to block a caller forever.
	Timeout time.Duration
}

// DefaultTimeout bounds one admin RPC.
const DefaultTimeout = 15 * time.Second

// serverPath is the path SPIRE issues its own server SVID under.
const serverPath = "/spire/server"

// Client is an admin client for one SPIRE server.
type Client struct {
	conn    *grpc.ClientConn
	entries entryv1.EntryClient
	agents  agentv1.AgentClient

	trustDomain string
	timeout     time.Duration
}

// resolve fills in the defaults and rejects a configuration that cannot be
// safe. Every failure here is an INVARIANT_VIOLATION: a client pointed at the
// wrong trust domain, or willing to accept any server, is not a degraded
// client, it is a hole.
func (cfg Config) resolve() (td spiffeid.TrustDomain, serverID spiffeid.ID, err error) {
	fail := func(format string, args ...any) (spiffeid.TrustDomain, spiffeid.ID, error) {
		return spiffeid.TrustDomain{}, spiffeid.ID{},
			newError(ClassInvariantViolation, "dial", "", fmt.Sprintf(format, args...), false, nil)
	}

	if cfg.Address == "" {
		return fail("no server address")
	}
	if cfg.Source == nil {
		return fail("no SVID source: an admin client without a credential is not an admin client")
	}
	td, err = spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return fail("trust domain %q: %v", cfg.TrustDomain, err)
	}
	// TrustDomainFromString also accepts a whole SPIFFE ID and quietly keeps
	// its authority. Requiring the round trip means the caller has to have
	// meant a trust domain.
	if td.Name() != cfg.TrustDomain {
		return fail("trust domain %q is not a trust domain name (read as %q)", cfg.TrustDomain, td.Name())
	}

	want := cfg.ServerID
	if want == "" {
		want = "spiffe://" + td.Name() + serverPath
	}
	serverID, err = spiffeid.FromString(want)
	if err != nil {
		return fail("server id %q: %v", want, err)
	}
	if serverID.TrustDomain() != td {
		return fail("server id %q is not in trust domain %q", want, td.Name())
	}
	return td, serverID, nil
}

// Dial connects to the SPIRE server named by cfg and returns a client. It does
// not block on the connection: the first RPC reports an unreachable server as
// IDENTITY_UNAVAILABLE, retryable (IP §6.1).
func Dial(_ context.Context, cfg Config) (*Client, error) {
	td, serverID, err := cfg.resolve()
	if err != nil {
		return nil, err
	}

	// mTLS, both ways, over SPIFFE identities. The server is authorized by ID
	// rather than by hostname — which is also why a TCP proxy in front of it
	// changes nothing about what is being authenticated.
	tlsCfg := tlsconfig.MTLSClientConfig(cfg.Source, cfg.Source, tlsconfig.AuthorizeID(serverID))

	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, newError(ClassIdentityUnavailable, "dial", "",
			fmt.Sprintf("%s: %v", cfg.Address, err), true, err)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		conn:        conn,
		entries:     entryv1.NewEntryClient(conn),
		agents:      agentv1.NewAgentClient(conn),
		trustDomain: td.Name(),
		timeout:     timeout,
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// TrustDomain returns the trust domain this client is bound to.
func (c *Client) TrustDomain() string { return c.trustDomain }

// call derives the per-RPC deadline.
func (c *Client) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

// AttestedNodes returns the SPIFFE IDs of the nodes SPIRE has attested. A run
// entry is parented to one of them; an entry with no reachable parent is an
// entry no workload can ever match.
func (c *Client) AttestedNodes(ctx context.Context) ([]string, error) {
	rpcCtx, cancel := c.call(ctx)
	defer cancel()

	resp, err := c.agents.ListAgents(rpcCtx, &agentv1.ListAgentsRequest{})
	if err != nil {
		return nil, classifyAdmin("attested_nodes", "", err)
	}
	ids := make([]string, 0, len(resp.GetAgents()))
	for _, a := range resp.GetAgents() {
		ids = append(ids, idString(a.GetId()))
	}
	return ids, nil
}

// createEntries is the raw BatchCreateEntry call, without this package's own
// checks on the SPIFFE ID being created.
//
// RegisterRun refuses to build an out-of-subtree ID at all, which is right for
// production and useless as a test of SPI-005: a stolen admin credential does
// not run RegisterRun. This is the seam the SPI-005 case uses to ask SPIRE the
// question directly. It is unexported precisely so nothing outside this package
// can route around RegisterRun with it.
//
// The returned error is the RPC's own — an authorization denial arrives here.
// Per-entry statuses are handed back untouched for the caller to read: turning
// them into errors here would make "SPIRE refused the batch" and "SPIRE
// refused this one entry" indistinguishable, and SPI-005 is precisely about
// which of the two happened.
func (c *Client) createEntries(ctx context.Context, entries []*types.Entry) ([]*entryv1.BatchCreateEntryResponse_Result, error) {
	rpcCtx, cancel := c.call(ctx)
	defer cancel()

	resp, err := c.entries.BatchCreateEntry(rpcCtx, &entryv1.BatchCreateEntryRequest{Entries: entries})
	if err != nil {
		return nil, classifyAdmin("create_entry", "", err)
	}
	return resp.GetResults(), nil
}

// idString renders a types.SPIFFEID.
func idString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return "spiffe://" + id.GetTrustDomain() + id.GetPath()
}

// classifyAdmin maps an admin-API failure onto the error vocabulary of IP §4.
//
// The mapping is deliberate about what is retryable, because retryability is
// what a caller acts on:
//
//   - PermissionDenied is an INVARIANT_VIOLATION, not an attestation failure.
//     The admin credential either is not what it should be or was used for
//     something it must never do (SPI-005, AB-10). Both are alert-level and
//     neither improves on a retry.
//   - Unavailable, DeadlineExceeded, ResourceExhausted, Internal, Aborted and a
//     transport error with no gRPC status at all are IDENTITY_UNAVAILABLE and
//     retryable — IP §6.1's "spire-server down at register_agent".
//   - Anything else is IDENTITY_UNAVAILABLE and NOT retryable: we do not know
//     what happened, so we do not spin.
func classifyAdmin(op, runID string, err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		// No gRPC status: a transport or TLS failure before the server
		// answered. SPIRE is unreachable, which is retryable.
		return newError(ClassIdentityUnavailable, op, runID, err.Error(), true, err)
	}
	msg := st.Message()
	switch st.Code() {
	case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition:
		return newError(ClassInvariantViolation, op, runID, msg, false, err)
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Internal, codes.Aborted:
		return newError(ClassIdentityUnavailable, op, runID, msg, true, err)
	case codes.AlreadyExists:
		return newError(ClassDuplicateRequest, op, runID, msg, false, err)
	case codes.NotFound:
		return newError(ClassRunNotFound, op, runID, msg, false, err)
	default:
		return newError(ClassIdentityUnavailable, op, runID, msg, false, err)
	}
}

// statusError turns a per-entry status into a gRPC error classifyAdmin can read.
func statusError(s *types.Status) error {
	if s == nil {
		return errors.New("SPIRE returned no status for the entry")
	}
	return status.Error(codes.Code(s.GetCode()), s.GetMessage()) //nolint:gosec // a gRPC code from SPIRE's own response
}
