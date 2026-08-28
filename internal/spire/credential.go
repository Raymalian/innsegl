// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultWorkloadAPIAddress is where deploy/compose/spire.yml mounts the
// Workload API socket for every attested workload.
const DefaultWorkloadAPIAddress = "unix:///run/spire/agent-sockets/api.sock"

// SVID is a workload's own identity as the Workload API handed it over. No
// private key crosses this boundary: E8 forbids the MCP from holding, caching
// or proxying agent keys, and nothing in this package ever sees one leave the
// workload it was minted for.
type SVID struct {
	SPIFFEID  string
	ExpiresAt time.Time
}

// FetchOutcome is the machine-readable result of one Workload API fetch: either
// an identity or a classified refusal. It is what the svidprobe helper prints
// and what an integration test reads back, so a refusal observed inside a
// container arrives with the class it was given rather than as loose text.
type FetchOutcome struct {
	SPIFFEID  string `json:"spiffe_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Class     Class  `json:"class,omitempty"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message,omitempty"`
}

// FetchWorkloadSVID fetches the calling workload's own X509-SVID from the SPIRE
// Workload API at addr.
//
// I1 lives here on the workload side: the caller does not say who it is, the
// agent attests what it is, and a workload SPIRE cannot place gets no identity
// at all. That refusal arrives as gRPC PermissionDenied "no identity issued"
// and becomes ATTESTATION_FAILED, not retryable (IP §6.1).
func FetchWorkloadSVID(ctx context.Context, addr string) (SVID, error) {
	if addr == "" {
		addr = DefaultWorkloadAPIAddress
	}
	svid, err := workloadapi.FetchX509SVID(ctx, workloadapi.WithAddr(addr))
	if err != nil {
		return SVID{}, classifyWorkload("get_credential", err)
	}
	if len(svid.Certificates) == 0 {
		return SVID{}, newError(ClassInvariantViolation, "get_credential", "",
			"the Workload API returned an SVID with no certificate", false, nil)
	}
	return SVID{
		SPIFFEID:  svid.ID.String(),
		ExpiresAt: svid.Certificates[0].NotAfter,
	}, nil
}

// FetchRunSVID fetches the calling workload's SVID and requires it to be the
// identity of run.
//
// The check is not decoration. A workload that holds a valid SVID for run A
// must not be able to act as run B: IP §6.2 makes cross-run use an
// INVARIANT_VIOLATION, and this is where a caller finds out before anything is
// signed with it.
func FetchRunSVID(ctx context.Context, addr, trustDomain string, run RunRef) (SVID, error) {
	want, err := run.SPIFFEID(trustDomain)
	if err != nil {
		return SVID{}, err
	}
	got, err := FetchWorkloadSVID(ctx, addr)
	if err != nil {
		return SVID{}, err
	}
	if got.SPIFFEID != want {
		return SVID{}, newError(ClassInvariantViolation, "get_credential", run.RunID,
			fmt.Sprintf("the Workload API issued %s; this run is %s", got.SPIFFEID, want), false, nil)
	}
	return got, nil
}

// Outcome renders a fetch result for transport.
func Outcome(svid SVID, err error) FetchOutcome {
	if err == nil {
		out := FetchOutcome{SPIFFEID: svid.SPIFFEID}
		if !svid.ExpiresAt.IsZero() {
			out.ExpiresAt = svid.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return out
	}
	out := FetchOutcome{Message: err.Error(), Retryable: IsRetryable(err)}
	if class, ok := ClassOf(err); ok {
		out.Class = class
	}
	return out
}

// classifyWorkload maps a Workload API failure onto the error vocabulary of
// IP §4.
//
// The one distinction that matters is between a refusal and an outage, because
// SPI-002 is only worth anything if the two are told apart:
//
//   - PermissionDenied is the agent saying "no identity issued" — the workload
//     did not attest. ATTESTATION_FAILED, and not retryable: retrying cannot
//     make a workload be something else (IP §6.1).
//   - Anything that means the agent could not be reached or did not answer —
//     a missing socket, a refused connection, a deadline, a transport error
//     with no gRPC status at all — is IDENTITY_UNAVAILABLE and retryable.
//     IP §6.1's "spire-agent socket lost mid-run at get_credential".
//   - Anything else is IDENTITY_UNAVAILABLE and not retryable: unrecognised is
//     not the same as transient.
func classifyWorkload(op string, err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.PermissionDenied:
			return newError(ClassAttestationFailed, op, "", st.Message(), false, err)
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled, codes.Unknown, codes.ResourceExhausted:
			return newError(ClassIdentityUnavailable, op, "", st.Message(), true, err)
		default:
			return newError(ClassIdentityUnavailable, op, "", st.Message(), false, err)
		}
	}
	// No gRPC status: the agent was never reached. A lost socket is the
	// commonest case and it is retryable.
	retryable := !errors.Is(err, context.Canceled)
	return newError(ClassIdentityUnavailable, op, "", err.Error(), retryable, err)
}
