// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPI-005 (doc 07, layer I)
//
//	Admin credential scope: attempt entry creation outside /agent/ subtree
//	→ Refused by SPIRE authorization
//	→ proves IP §6.10, and closes abuse case AB-10
//
// AB-10 is "steal MCP admin credential, mint identities outside agent subtree".
// A stolen credential does not run our client, so a client-side check refuses
// nothing that matters. The refusal has to come from SPIRE, and this case
// therefore does not go through RegisterRun at all: it calls the entry API
// directly with the same admin SVID and asks SPIRE for an entry the MCP must
// never be able to create.
//
// # How this case is kept from passing vacuously
//
// "The thing was refused" passes when nothing was attempted. Four assertions
// close that, and they are the reason this test is longer than its one line of
// specification:
//
//  1. THE CONNECTION WORKS AND THE CREDENTIAL IS ADMIN. The same client, on the
//     same connection, creates an in-subtree entry immediately before — and it
//     succeeds. A broken channel or a rejected SVID would fail there.
//
//  2. THE REFUSAL IS SPIRE'S, AND IT IS AUTHORIZATION. The error carries gRPC
//     PermissionDenied and SPIRE's own "authorization denied for method
//     /spire.api.server.entry.v1.Entry/BatchCreateEntry" — not a transport
//     error, not an InvalidArgument about the ID's shape, not something this
//     package made up.
//
//  3. SPIRE HAS NO OTHER OBJECTION TO THE ID. The identical entry is created
//     successfully over the unauthenticated LOCAL socket, on the same server,
//     seconds later, and then deleted. So "/innsegl/rogue" is an entry this
//     SPIRE is perfectly willing to hold; what it will not do is let the admin
//     SPIFFE ID create it. That isolates the denial to the admin authorization
//     policy this issue added.
//
//  4. NOTHING WAS CREATED. After the refusal the server holds no entry for the
//     rogue ID, checked over the local socket rather than through the client
//     whose call was just denied.
//
// And the strongest evidence of all is in the git history rather than in an
// assertion: this test was first run against the stack *without*
// deploy/compose/spire/authz-policy.rego, and SPIRE created the entry and
// returned `status:{message:"OK"}`. The red is recorded in the commit that
// added the policy.
func TestSPI005AdminCredentialCannotMintOutsideTheAgentSubtree(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// (1) The positive control, on this connection, with this credential.
	okRun := newRun(t, "demo", "rm-015")
	okID, err := okRun.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("RunRef.SPIFFEID: %v", err)
	}
	registerForTest(t, c, s, okRun)
	t.Logf("positive control: the same admin credential created %s", okID)

	// Everything the MCP must never be able to mint. Each is a place an
	// attacker holding asset A2 would want to put an identity.
	for _, tc := range []struct {
		name string
		path string
	}{
		{"a sibling of the agent subtree", "/innsegl/rogue"},
		{"the MCP's own admin identity", "/innsegl/mcp"},
		{"a node identity", "/spire/agent/x509pop/deadbeef"},
		{"the trust domain root", "/"},
		{"the agent subtree itself", "/agent"},
		{"one level short of a run", "/agent/demo/rm-015"},
		{"one level past a run", "/agent/demo/rm-015/run-1/extra"},
		{"a path that only looks like the subtree", "/agentx/demo/rm-015/run-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &types.SPIFFEID{TrustDomain: testTrustDomain, Path: tc.path}

			results, err := c.createEntries(ctx, []*types.Entry{{
				ParentId:    &types.SPIFFEID{TrustDomain: testTrustDomain, Path: pathOf(t, s.parentID)},
				SpiffeId:    target,
				Selectors:   []*types.Selector{{Type: "unix", Value: "uid:10001"}},
				X509SvidTtl: int32(DefaultRunTTL.Seconds()),
				JwtSvidTtl:  int32(DefaultRunTTL.Seconds()),
			}})

			if err == nil {
				var created []string
				for _, r := range results {
					created = append(created, r.GetEntry().GetId())
				}
				t.Fatalf("SPIRE CREATED an entry for spiffe://%s%s (entries %v). "+
					"That is AB-10: a stolen admin credential can mint identities "+
					"outside the agent subtree.", testTrustDomain, tc.path, created)
			}

			// (2) The refusal is SPIRE's, and it is authorization.
			st, ok := status.FromError(unwrapAll(err))
			if !ok || st.Code() != codes.PermissionDenied {
				t.Fatalf("refusal was not a gRPC PermissionDenied: %v", err)
			}
			if !strings.Contains(st.Message(), "authorization denied") {
				t.Errorf("PermissionDenied message = %q, want SPIRE's authorization denial", st.Message())
			}
			if class, cok := ClassOf(err); !cok || class != ClassInvariantViolation {
				t.Errorf("class = %q (ok=%v), want %s", class, cok, ClassInvariantViolation)
			}
			if IsRetryable(err) {
				t.Error("an authorization denial was marked retryable")
			}

			// (4) Nothing was created, checked away from the denied path —
			// over the local socket, listing every entry the server holds and
			// comparing IDs exactly. (`entry show -spiffeID` cannot be used
			// here: SPIRE refuses to build a filter for a reserved-namespace
			// path or a trailing slash, which is precisely what two of these
			// cases are.)
			if entryExists(ctx, t, s, "spiffe://"+testTrustDomain+tc.path) {
				t.Errorf("SPIRE holds an entry for %s after refusing to create it", tc.path)
			}
		})
	}

	// (3) SPIRE has no objection to an out-of-subtree ID itself — only to who
	// asked for it. A path of its own, so this control can never collide with
	// anything a denied create above might have left behind.
	t.Run("the same shape of entry is accepted on the local socket", func(t *testing.T) {
		const rogue = "spiffe://" + testTrustDomain + "/innsegl/rogue-local-control"
		out, err := s.spireLocal(ctx, "entry", "create",
			"-parentID", s.parentID,
			"-spiffeID", rogue,
			"-selector", "unix:uid:10001",
			"-x509SVIDTTL", "300",
			"-jwtSVIDTTL", "300")
		if err != nil {
			t.Fatalf("the local socket refused %s too, so the admin denial above "+
				"is not attributable to the authorization policy: %v", rogue, err)
		}
		entryID := fieldAfter(out, "Entry ID")
		if entryID == "" {
			t.Fatalf("local entry create returned no entry ID:\n%s", out)
		}
		t.Logf("control: the unauthenticated local socket created %s (entry %s) — "+
			"ADR-0011's residual, and the reason the denial above is the policy "+
			"and not the ID", rogue, entryID)

		if _, err := s.spireLocal(ctx, "entry", "delete", "-entryID", entryID); err != nil {
			t.Errorf("cleaning up the control entry %s: %v", entryID, err)
		}
	})
}

// TestSPI005AdminIsDeniedTheMintAndJoinTokenAPIs covers the rest of AB-10.
// Scoping BatchCreateEntry alone would leave three ways to obtain an identity
// outside the agent subtree without creating an entry at all: mint an SVID
// directly, or mint a join token and attest a node with it. The policy denies
// all of them to an admin SPIFFE ID; this asserts that rather than trusting the
// allowlist to be read correctly.
func TestSPI005AdminIsDeniedTheMintAndJoinTokenAPIs(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	t.Run("MintX509SVID", func(t *testing.T) {
		// A CSR SPIRE would never get as far as parsing.
		_, err := svidv1.NewSVIDClient(c.conn).MintX509SVID(ctx,
			&svidv1.MintX509SVIDRequest{Csr: []byte{0x30, 0x00}, Ttl: 300})
		requirePermissionDenied(t, classifyAdmin("MintX509SVID", "", err))
	})
	t.Run("MintJWTSVID", func(t *testing.T) {
		// In the agent subtree, so the denial is about the method and not the ID.
		_, err := svidv1.NewSVIDClient(c.conn).MintJWTSVID(ctx, &svidv1.MintJWTSVIDRequest{
			Id:       &types.SPIFFEID{TrustDomain: testTrustDomain, Path: "/agent/demo/rm-015/run-1"},
			Audience: []string{"sigstore"},
		})
		requirePermissionDenied(t, classifyAdmin("MintJWTSVID", "", err))
	})
	t.Run("CreateJoinToken", func(t *testing.T) {
		// A join token attests a node, whose SVID is /spire/agent/... — an
		// identity outside the agent subtree obtained without any entry.
		_, err := agentv1.NewAgentClient(c.conn).CreateJoinToken(ctx,
			&agentv1.CreateJoinTokenRequest{Ttl: 600})
		requirePermissionDenied(t, classifyAdmin("CreateJoinToken", "", err))
	})
	t.Run("ListEntries is still allowed", func(t *testing.T) {
		// The allowlist has to still allow what the MCP needs, or "denied" is
		// just a broken credential.
		if _, err := c.AttestedNodes(ctx); err != nil {
			t.Fatalf("AttestedNodes: %v", err)
		}
		if _, _, err := c.LookupRun(ctx, newRun(t, "demo", "rm-015")); err != nil {
			t.Fatalf("LookupRun: %v", err)
		}
	})
}

// TestSPI005NonAdminSVIDIsNotAdmin checks the other end of admin_ids: an SVID
// for some other ID in the same trust domain, minted by the same server, gets
// no admin at all. Without this, "the admin ID is scoped" would be consistent
// with "every ID is admin".
func TestSPI005NonAdminSVIDIsNotAdmin(t *testing.T) {
	s := requireStack(t)
	c := s.clientAs(t, "spiffe://"+testTrustDomain+"/innsegl/not-the-mcp")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	run := newRun(t, "demo", "rm-015")
	_, err := c.RegisterRun(ctx, Registration{
		Run:       run,
		ParentID:  s.parentID,
		Selectors: runSelectors(run),
	})
	if err == nil {
		t.Fatal("a non-admin SVID created a registration entry")
	}
	requirePermissionDenied(t, err)
}

func requirePermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("the call succeeded; SPIRE was expected to refuse it")
	}
	st, ok := status.FromError(unwrapAll(err))
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("want gRPC PermissionDenied, got %v", err)
	}
	if class, cok := ClassOf(err); !cok || class != ClassInvariantViolation {
		t.Errorf("class = %q (ok=%v), want %s", class, cok, ClassInvariantViolation)
	}
	if IsRetryable(err) {
		t.Error("an authorization denial was marked retryable")
	}
}

// entryExists reports whether the server holds an entry with exactly this
// SPIFFE ID, read over the local socket.
func entryExists(ctx context.Context, t *testing.T, s *stack, id string) bool {
	t.Helper()
	out, err := s.spireLocal(ctx, "entry", "show")
	if err != nil {
		t.Fatalf("entry show: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "SPIFFE ID") {
			continue
		}
		_, v, ok := strings.Cut(trimmed, ":")
		if ok && strings.TrimSpace(v) == id {
			return true
		}
	}
	return false
}

// unwrapAll walks to the root cause. grpc-go's status.FromError unwraps on its
// own, but this makes the assertion independent of that.
func unwrapAll(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

// pathOf returns the path component of a SPIFFE ID string.
func pathOf(t *testing.T, id string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		t.Fatalf("%q is not a SPIFFE ID", id)
	}
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "/"
	}
	return rest[i:]
}

// fieldAfter reads "Name : value" out of SPIRE CLI output.
func fieldAfter(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, name) {
			continue
		}
		if _, v, ok := strings.Cut(trimmed, ":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
