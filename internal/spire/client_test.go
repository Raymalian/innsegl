// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Unit cases. These need no containers and are the ones that hold the error
// vocabulary in place: IP §4's classes and their retryability are a protected
// surface, and every one of them reaches a caller through the two classifiers
// below.

func TestRunRefSPIFFEID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  RunRef
		td   string
		want string
	}{
		{
			name: "the scheme of doc 01 §1",
			run:  RunRef{AgentType: "fix-ci", TaskID: "jira-118", RunID: "run-42"},
			td:   "innsegl.dev",
			want: "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		},
		{
			name: "another trust domain is not assumed away",
			run:  RunRef{AgentType: "demo", TaskID: "rm-015", RunID: "run-1"},
			td:   "example.test",
			want: "spiffe://example.test/agent/demo/rm-015/run-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.run.SPIFFEID(tc.td)
			if err != nil {
				t.Fatalf("SPIFFEID: %v", err)
			}
			if got != tc.want {
				t.Errorf("SPIFFEID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunRefSPIFFEIDRejectsAnythingOutsideTheGrammar(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  RunRef
		td   string
	}{
		{"empty agent type", RunRef{TaskID: "t", RunID: "r"}, "innsegl.dev"},
		{"empty task id", RunRef{AgentType: "a", RunID: "r"}, "innsegl.dev"},
		{"empty run id", RunRef{AgentType: "a", TaskID: "t"}, "innsegl.dev"},
		{"empty trust domain", RunRef{AgentType: "a", TaskID: "t", RunID: "r"}, ""},
		{"uppercase segment", RunRef{AgentType: "A", TaskID: "t", RunID: "r"}, "innsegl.dev"},
		{"path traversal", RunRef{AgentType: "..", TaskID: "t", RunID: "r"}, "innsegl.dev"},
		{"embedded slash", RunRef{AgentType: "a/b", TaskID: "t", RunID: "r"}, "innsegl.dev"},
		{"uppercase trust domain", RunRef{AgentType: "a", TaskID: "t", RunID: "r"}, "INNSEGL.DEV"},
		{"leading dash", RunRef{AgentType: "-a", TaskID: "t", RunID: "r"}, "innsegl.dev"},
		{
			"over-long segment",
			RunRef{AgentType: strings.Repeat("a", 64), TaskID: "t", RunID: "r"},
			"innsegl.dev",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.run.SPIFFEID(tc.td)
			if err == nil {
				t.Fatalf("SPIFFEID = %q, want an error", got)
			}
			if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
				t.Errorf("class = %q (ok=%v), want %s", class, ok, ClassInvariantViolation)
			}
			if IsRetryable(err) {
				t.Error("a malformed SPIFFE ID was marked retryable")
			}
		})
	}
}

func TestClassifyAdmin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		err       error
		want      Class
		retryable bool
	}{
		{"nil is not an error", nil, "", false},
		{
			"authorization denial is an invariant violation",
			status.Error(codes.PermissionDenied, "authorization denied for method X"),
			ClassInvariantViolation, false,
		},
		{
			"server unreachable is retryable",
			status.Error(codes.Unavailable, "connection refused"),
			ClassIdentityUnavailable, true,
		},
		{
			"deadline exceeded is retryable",
			status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			ClassIdentityUnavailable, true,
		},
		{
			"resource exhausted is retryable",
			status.Error(codes.ResourceExhausted, "too many requests"),
			ClassIdentityUnavailable, true,
		},
		{
			"internal is retryable",
			status.Error(codes.Internal, "datastore error"),
			ClassIdentityUnavailable, true,
		},
		{
			"already exists is a duplicate",
			status.Error(codes.AlreadyExists, "entry already exists"),
			ClassDuplicateRequest, false,
		},
		{
			"not found is a missing run",
			status.Error(codes.NotFound, "entry not found"),
			ClassRunNotFound, false,
		},
		{
			"invalid argument is our bug",
			status.Error(codes.InvalidArgument, "malformed spiffe id"),
			ClassInvariantViolation, false,
		},
		{
			"unauthenticated is not retryable",
			status.Error(codes.Unauthenticated, "no client certificate"),
			ClassInvariantViolation, false,
		},
		{
			"an unclassified transport error fails closed",
			errors.New("dial tcp: no route to host"),
			ClassIdentityUnavailable, true,
		},
		{
			"an unexpected code is not retryable",
			status.Error(codes.Unimplemented, "no such method"),
			ClassIdentityUnavailable, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyAdmin("op", "run-1", tc.err)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("classifyAdmin(nil) = %v, want nil", got)
				}
				return
			}
			class, ok := ClassOf(got)
			if !ok || class != tc.want {
				t.Errorf("class = %q (ok=%v), want %s", class, ok, tc.want)
			}
			if IsRetryable(got) != tc.retryable {
				t.Errorf("retryable = %v, want %v", IsRetryable(got), tc.retryable)
			}
			if !errors.Is(got, tc.err) {
				t.Error("the cause was not preserved for errors.Is")
			}
			var e *Error
			if errors.As(got, &e) && e.RunID != "run-1" {
				t.Errorf("run id = %q, want run-1", e.RunID)
			}
		})
	}
}

func TestClassifyWorkload(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		err       error
		want      Class
		retryable bool
	}{
		{"nil is not an error", nil, "", false},
		{
			// This is the exact status a SPIRE agent returns to a workload it
			// could not attest — SPI-002's refusal, verbatim.
			"no identity issued is ATTESTATION_FAILED and not retryable",
			status.Error(codes.PermissionDenied, "no identity issued"),
			ClassAttestationFailed, false,
		},
		{
			"an unreachable agent is retryable",
			status.Error(codes.Unavailable, "connection refused"),
			ClassIdentityUnavailable, true,
		},
		{
			"a lost socket mid-run is retryable",
			&net.OpError{Op: "dial", Err: errors.New("no such file or directory")},
			ClassIdentityUnavailable, true,
		},
		{
			"a deadline is retryable",
			context.DeadlineExceeded,
			ClassIdentityUnavailable, true,
		},
		{
			"an unexpected code is not retryable",
			status.Error(codes.InvalidArgument, "bad request"),
			ClassIdentityUnavailable, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyWorkload("fetch", tc.err)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("classifyWorkload(nil) = %v, want nil", got)
				}
				return
			}
			class, ok := ClassOf(got)
			if !ok || class != tc.want {
				t.Errorf("class = %q (ok=%v), want %s", class, ok, tc.want)
			}
			if IsRetryable(got) != tc.retryable {
				t.Errorf("retryable = %v, want %v", IsRetryable(got), tc.retryable)
			}
		})
	}
}

func TestErrorRendersClassAndRetryability(t *testing.T) {
	t.Parallel()
	e := newError(ClassAttestationFailed, "get_credential", "run-42", "no identity issued", false, nil)
	got := e.Error()
	for _, want := range []string{"get_credential", "ATTESTATION_FAILED", "run-42", "not retryable", "no identity issued"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, missing %q", got, want)
		}
	}
	retryable := newError(ClassIdentityUnavailable, "register", "", "spire-server is down", true, nil)
	if strings.Contains(retryable.Error(), "not retryable") {
		t.Errorf("a retryable error rendered as not retryable: %q", retryable.Error())
	}
}

func TestClassOfAndIsRetryableIgnoreForeignErrors(t *testing.T) {
	t.Parallel()
	plain := errors.New("something else")
	if class, ok := ClassOf(plain); ok {
		t.Errorf("ClassOf(plain) = %q, %v; want no class", class, ok)
	}
	if IsRetryable(plain) {
		t.Error("an unclassified error must not be retryable: fail closed rather than spin")
	}
	if class, ok := ClassOf(nil); ok {
		t.Errorf("ClassOf(nil) = %q, %v; want no class", class, ok)
	}
	wrapped := fmt.Errorf("outer: %w",
		newError(ClassRunNotFound, "op", "run-1", "gone", false, nil))
	if class, ok := ClassOf(wrapped); !ok || class != ClassRunNotFound {
		t.Errorf("ClassOf(wrapped) = %q, %v; want %s", class, ok, ClassRunNotFound)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	src := mintedSVID{}
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no address", Config{TrustDomain: "innsegl.dev", Source: src}},
		{"no trust domain", Config{Address: "127.0.0.1:8081", Source: src}},
		{"no source", Config{Address: "127.0.0.1:8081", TrustDomain: "innsegl.dev"}},
		{"malformed trust domain", Config{Address: "127.0.0.1:8081", TrustDomain: "spiffe://x/y", Source: src}},
		{
			"malformed server id",
			Config{Address: "127.0.0.1:8081", TrustDomain: "innsegl.dev", ServerID: "not-a-spiffe-id", Source: src},
		},
		{
			"server id in another trust domain",
			Config{
				Address: "127.0.0.1:8081", TrustDomain: "innsegl.dev",
				ServerID: "spiffe://elsewhere.test/spire/server", Source: src,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := Dial(ctx, tc.cfg); err == nil {
				t.Fatal("Dial succeeded on an invalid config")
			}
		})
	}
}

func TestRegistrationValidation(t *testing.T) {
	t.Parallel()
	c := &Client{trustDomain: "innsegl.dev", timeout: time.Second}
	run := RunRef{AgentType: "demo", TaskID: "rm-015", RunID: "run-1"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name string
		reg  Registration
	}{
		{"no parent", Registration{Run: run, Selectors: runSelectors(run)}},
		{
			"no selectors — an entry every workload matches",
			Registration{Run: run, ParentID: "spiffe://innsegl.dev/spire/agent/x509pop/abc"},
		},
		{
			"an empty selector",
			Registration{
				Run: run, ParentID: "spiffe://innsegl.dev/spire/agent/x509pop/abc",
				Selectors: []Selector{{Type: "", Value: ""}},
			},
		},
		{
			"a TTL longer than the deployment's own default is not short",
			Registration{
				Run: run, ParentID: "spiffe://innsegl.dev/spire/agent/x509pop/abc",
				Selectors: runSelectors(run), TTL: MaxRunTTL + time.Second,
			},
		},
		{
			"a negative TTL",
			Registration{
				Run: run, ParentID: "spiffe://innsegl.dev/spire/agent/x509pop/abc",
				Selectors: runSelectors(run), TTL: -time.Second,
			},
		},
		{
			"a parent that is not a SPIFFE ID",
			Registration{Run: run, ParentID: "not-a-spiffe-id", Selectors: runSelectors(run)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.RegisterRun(ctx, tc.reg)
			if err == nil {
				t.Fatal("RegisterRun accepted an invalid registration")
			}
			if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
				t.Errorf("class = %q (ok=%v), want %s", class, ok, ClassInvariantViolation)
			}
		})
	}
}

func TestSelectorString(t *testing.T) {
	t.Parallel()
	got := Selector{Type: "docker", Value: "label:dev.innsegl.run-id:run-42"}.String()
	const want = "docker:label:dev.innsegl.run-id:run-42"
	if got != want {
		t.Errorf("Selector.String() = %q, want %q", got, want)
	}
}

func TestOutcomeCarriesTheClassAcrossTheContainerBoundary(t *testing.T) {
	t.Parallel()
	refused := classifyWorkload("fetch", status.Error(codes.PermissionDenied, "no identity issued"))
	got := Outcome(SVID{}, refused)
	if got.Class != ClassAttestationFailed {
		t.Errorf("Outcome class = %q, want %s", got.Class, ClassAttestationFailed)
	}
	if got.Retryable {
		t.Error("Outcome marked an attestation failure retryable")
	}
	if got.SPIFFEID != "" {
		t.Errorf("a refused fetch carried a SPIFFE ID: %q", got.SPIFFEID)
	}
	if !strings.Contains(got.Message, "no identity issued") {
		t.Errorf("Outcome message = %q, want SPIRE's own text", got.Message)
	}

	expiry := time.Date(2026, 8, 28, 20, 23, 9, 0, time.UTC)
	ok := Outcome(SVID{SPIFFEID: "spiffe://innsegl.dev/agent/a/b/c", ExpiresAt: expiry}, nil)
	if ok.Class != "" || ok.Message != "" {
		t.Errorf("a successful Outcome carried a class or message: %+v", ok)
	}
	if ok.SPIFFEID != "spiffe://innsegl.dev/agent/a/b/c" {
		t.Errorf("Outcome SPIFFE ID = %q", ok.SPIFFEID)
	}
	if ok.ExpiresAt != expiry.Format(time.RFC3339) {
		t.Errorf("Outcome expiry = %q, want %q", ok.ExpiresAt, expiry.Format(time.RFC3339))
	}
}

// The small error paths. IP §2 asks for every error-return path of every MCP
// tool to be covered; these are the ones underneath those tools, and they are
// the ones a container-backed case cannot reach because they fire before any
// RPC is attempted.

func TestClientAccessorsAndNilPaths(t *testing.T) {
	t.Parallel()

	c := &Client{trustDomain: "innsegl.dev", timeout: DefaultTimeout}
	if c.TrustDomain() != "innsegl.dev" {
		t.Errorf("TrustDomain() = %q, want innsegl.dev", c.TrustDomain())
	}
	// A client that never dialled has nothing to close, and closing it is not
	// an error: the MCP's shutdown path must not care whether Dial got far.
	if err := (&Client{}).Close(); err != nil {
		t.Errorf("Close on an undialled client: %v", err)
	}
	var nilClient *Client
	if err := nilClient.Close(); err != nil {
		t.Errorf("Close on a nil client: %v", err)
	}
	if got := idString(nil); got != "" {
		t.Errorf("idString(nil) = %q, want empty", got)
	}
	if err := statusError(nil); err == nil {
		t.Error("statusError(nil) returned no error; a missing status is not a success")
	}
}

func TestSplitIDRejectsWhatIsNotASPIFFEID(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",
		"innsegl.dev/agent/a/b/c",
		"spiffe://",
		"spiffe://innsegl.dev",
		"spiffe:///agent/a/b/c",
	} {
		if got, err := splitID(bad); err == nil {
			t.Errorf("splitID(%q) = %+v, want an error", bad, got)
		}
	}
	got, err := splitID("spiffe://innsegl.dev/agent/a/b/c")
	if err != nil {
		t.Fatalf("splitID: %v", err)
	}
	if got.GetTrustDomain() != "innsegl.dev" || got.GetPath() != "/agent/a/b/c" {
		t.Errorf("splitID = %+v, want innsegl.dev + /agent/a/b/c", got)
	}
}

func TestWithRunStampsOnlyAnUnattributedError(t *testing.T) {
	t.Parallel()

	unattributed := newError(ClassIdentityUnavailable, "op", "", "spire is down", true, nil)
	stamped := withRun(unattributed, "run-42")
	var e *Error
	if !errors.As(stamped, &e) || e.RunID != "run-42" {
		t.Errorf("withRun did not stamp the run id: %v", stamped)
	}
	if unattributed.RunID != "" {
		t.Error("withRun mutated the original error instead of copying it")
	}

	already := newError(ClassRunNotFound, "op", "run-1", "gone", false, nil)
	// Identity comparison is the point: withRun must return the *same* error,
	// not a wrapped copy. errors.Is would pass on a wrapper and defeat the test.
	//nolint:errorlint // deliberate identity check, not an error-matching check
	if got := withRun(already, "run-42"); got != error(already) {
		t.Errorf("withRun overwrote an existing run id: %v", got)
	}

	plain := errors.New("not ours")
	//nolint:errorlint // deliberate identity check: a foreign error must pass through untouched
	if got := withRun(plain, "run-42"); got != plain {
		t.Errorf("withRun rewrote a foreign error: %v", got)
	}
}

func TestFetchWorkloadSVIDDefaultsToTheDeploymentSocket(t *testing.T) {
	t.Parallel()
	// The default address is the one deploy/compose/spire.yml mounts. Passing
	// "" must not mean "no address" and quietly succeed against something else.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := FetchWorkloadSVID(ctx, "")
	if err == nil {
		t.Skip("a Workload API socket exists at the deployment path on this machine")
	}
	if class, ok := ClassOf(err); !ok || class != ClassIdentityUnavailable {
		t.Errorf("class = %q (ok=%v), want %s: %v", class, ok, ClassIdentityUnavailable, err)
	}
}

func TestFetchRunSVIDRejectsAMalformedRunBeforeDialling(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No socket is contacted: an ID outside the scheme is refused first, so a
	// caller cannot smuggle a bad run past the Workload API by being offline.
	_, err := FetchRunSVID(ctx, "unix:///nonexistent/nope.sock", "innsegl.dev",
		RunRef{AgentType: "BAD", TaskID: "t", RunID: "r"})
	if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
		t.Errorf("class = %q (ok=%v), want %s: %v", class, ok, ClassInvariantViolation, err)
	}
}
