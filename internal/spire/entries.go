// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"

	"innsegl.dev/innsegl/internal/event"
)

// Run TTLs. IP §1: "short TTL, created at registration, deleted at retirement."
const (
	// DefaultRunTTL is the lifetime of the SVIDs a run entry issues when the
	// caller names none.
	DefaultRunTTL = 5 * time.Minute
	// MaxRunTTL is the longest this package will register. IP §6.2: "never
	// extend TTLs to 'help'." The bound is the server's own
	// default_x509_svid_ttl (deploy/compose/spire/server.conf): a per-run
	// identity that outlives the deployment-wide default is not short.
	MaxRunTTL = 30 * time.Minute
)

// agentPathPrefix is the one subtree this package will ever create an entry in.
// PROTECTED STRING (doc 01 §1).
const agentPathPrefix = "/agent/"

// RunRef names one agent run: the three path components of its SPIFFE ID.
type RunRef struct {
	AgentType string
	TaskID    string
	RunID     string
}

// SPIFFEID renders the run's SPIFFE ID under trustDomain.
//
// PROTECTED STRING (doc 01 §1, VERSIONING.md): the grammar is
// spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id} and it is
// validated, not merely formatted — event.ValidateSPIFFEID is the one
// definition of that grammar in this repository and this method defers to it
// rather than growing a second one that could drift.
func (r RunRef) SPIFFEID(trustDomain string) (string, error) {
	id := "spiffe://" + trustDomain + agentPathPrefix + r.AgentType + "/" + r.TaskID + "/" + r.RunID
	if err := event.ValidateSPIFFEID(id); err != nil {
		return "", newError(ClassInvariantViolation, "spiffe_id", r.RunID,
			fmt.Sprintf("%q is not a run identity: %v", id, err), false, err)
	}
	return id, nil
}

// RunRefOf reads a run's three path components back out of its SPIFFE ID.
//
// PROTECTED STRING (doc 01 §1): the grammar is
// spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}, and this
// defers to event.ValidateSPIFFEID for it rather than growing a second
// definition — the same reason RunRef.SPIFFEID does. It checks shape only;
// whether the trust domain is one this deployment owns is a policy question
// its callers answer (parseRunIdentity does, because the reaper deletes).
//
// It exists because since RM-079 (#116) the SPIFFE ID's {agent-type} and
// {task-id} may be PSEUDONYMS of the caller's agent type and task reference,
// generated under a deployment secret. SPIRE knows only the segments, so a
// caller holding a run's recorded SPIFFE ID and needing to look the entry up,
// or delete it, must read the segments off the ID. Deriving them any other way
// would need the secret on a read path, and then losing or rotating the secret
// would strand live runs — the exact failure the ledger-row mapping exists to
// avoid.
func RunRefOf(spiffeID string) (RunRef, error) {
	if err := event.ValidateSPIFFEID(spiffeID); err != nil {
		return RunRef{}, err
	}
	// ValidateSPIFFEID has already established five components, the second of
	// which is "agent"; nothing below can be out of range.
	parts := strings.Split(strings.TrimPrefix(spiffeID, "spiffe://"), "/")
	return RunRef{AgentType: parts[2], TaskID: parts[3], RunID: parts[4]}, nil
}

// Selector is one SPIRE selector, e.g. {Type: "docker", Value:
// "label:dev.innsegl.run-id:run-42"}.
type Selector struct {
	Type  string
	Value string
}

// String renders the selector the way the SPIRE CLI spells it.
func (s Selector) String() string { return s.Type + ":" + s.Value }

// RunSelectorType is the selector type a run's entry carries (ADR-0053). No
// workload attestor emits it: SPIRE stores it, and no workload can ever match
// it, so no workload is issued a run's identity by attestation. The only path
// to a run's credential is MintJWTSVID, which only the attested MCP may call.
// Adding an attestor that emits this type is a reviewed config change, which
// is the property ADR-0053 chose it for.
const RunSelectorType = "innsegl"

// runSelectorPrefix precedes the run id in a run selector's value.
const runSelectorPrefix = "run:"

// RunSelector is the one selector a run's entry carries: innsegl:run:<run_id>.
func RunSelector(runID string) Selector {
	return Selector{Type: RunSelectorType, Value: runSelectorPrefix + runID}
}

// Registration is one run's entry, as asked for.
type Registration struct {
	// Run is the run being registered.
	Run RunRef
	// ParentID is the attested node the entry hangs off.
	ParentID string
	// Selectors are what the workload must match. Doc 04: "Weak selectors are
	// the realistic failure" — this package requires at least one and refuses
	// none, but it cannot judge strength; that is review surface.
	Selectors []Selector
	// TTL is the SVID lifetime. Zero means DefaultRunTTL.
	TTL time.Duration
}

// Entry is a SPIRE registration entry as SPIRE holds it.
type Entry struct {
	ID        string
	SPIFFEID  string
	ParentID  string
	Selectors []Selector
	TTL       time.Duration
}

// Retirement is the outcome of RetireRun.
type Retirement struct {
	// EntryID is the entry that was deleted, empty when there was none.
	EntryID string
	// Deleted is false when the run already had no entry. Retirement is
	// idempotent (IP §4), so that is a success, not an error.
	Deleted bool
}

// resolve checks a registration and renders it as a SPIRE entry.
func (c *Client) resolve(reg Registration) (*types.Entry, string, error) {
	fail := func(format string, args ...any) (*types.Entry, string, error) {
		return nil, "", newError(ClassInvariantViolation, "register_agent", reg.Run.RunID,
			fmt.Sprintf(format, args...), false, nil)
	}

	spiffeID, err := reg.Run.SPIFFEID(c.trustDomain)
	if err != nil {
		return nil, "", err
	}
	parent, err := splitID(reg.ParentID)
	if err != nil {
		return fail("parent %q: %v", reg.ParentID, err)
	}
	if len(reg.Selectors) == 0 {
		return fail("no selectors: an entry with no selectors is an identity every " +
			"workload on the node matches (I1)")
	}
	selectors := make([]*types.Selector, 0, len(reg.Selectors))
	for _, s := range reg.Selectors {
		if s.Type == "" || s.Value == "" {
			return fail("selector %q is not type:value", s)
		}
		selectors = append(selectors, &types.Selector{Type: s.Type, Value: s.Value})
	}

	ttl := reg.TTL
	if ttl == 0 {
		ttl = DefaultRunTTL
	}
	if ttl < 0 || ttl > MaxRunTTL {
		return fail("TTL %s is outside (0, %s]; IP §6.2 forbids extending TTLs to help", ttl, MaxRunTTL)
	}

	target, err := splitID(spiffeID)
	if err != nil {
		return fail("%v", err)
	}
	seconds := int32(ttl.Seconds())
	return &types.Entry{
		ParentId:    parent,
		SpiffeId:    target,
		Selectors:   selectors,
		X509SvidTtl: seconds,
		JwtSvidTtl:  seconds,
	}, spiffeID, nil
}

// splitID parses a SPIFFE ID string into SPIRE's wire form.
func splitID(id string) (*types.SPIFFEID, error) {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return nil, fmt.Errorf("%q is not a SPIFFE ID", id)
	}
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return nil, fmt.Errorf("%q has no path", id)
	}
	return &types.SPIFFEID{TrustDomain: rest[:i], Path: rest[i:]}, nil
}

// RegisterRun creates exactly one registration entry for one run.
//
// IP §1: "One SPIRE registration entry per run, short TTL, created at
// registration, deleted at retirement. Identity ≡ single run ≡ single purpose."
// A second registration of the same run is a DUPLICATE_REQUEST, never a second
// identity.
func (c *Client) RegisterRun(ctx context.Context, reg Registration) (Entry, error) {
	wire, spiffeID, err := c.resolve(reg)
	if err != nil {
		return Entry{}, err
	}

	results, err := c.createEntries(ctx, []*types.Entry{wire})
	if err != nil {
		return Entry{}, withRun(err, reg.Run.RunID)
	}
	if len(results) != 1 {
		return Entry{}, newError(ClassInvariantViolation, "register_agent", reg.Run.RunID,
			fmt.Sprintf("SPIRE returned %d results for one entry", len(results)), false, nil)
	}
	r := results[0]
	if codes.Code(r.GetStatus().GetCode()) != codes.OK { //nolint:gosec // a gRPC code from SPIRE's own response
		return Entry{}, classifyAdmin("register_agent", reg.Run.RunID, statusError(r.GetStatus()))
	}

	created := fromWire(r.GetEntry())
	if created.SPIFFEID != spiffeID {
		return Entry{}, newError(ClassInvariantViolation, "register_agent", reg.Run.RunID,
			fmt.Sprintf("SPIRE created %q, this run is %q", created.SPIFFEID, spiffeID), false, nil)
	}
	return created, nil
}

// LookupRun returns the run's entry, and whether SPIRE holds one. It asks the
// server, whose datastore is authoritative the instant a create or delete
// returns — not an agent cache, which converges later.
func (c *Client) LookupRun(ctx context.Context, run RunRef) (Entry, bool, error) {
	spiffeID, err := run.SPIFFEID(c.trustDomain)
	if err != nil {
		return Entry{}, false, err
	}
	target, err := splitID(spiffeID)
	if err != nil {
		return Entry{}, false, newError(ClassInvariantViolation, "lookup_run", run.RunID, err.Error(), false, err)
	}

	rpcCtx, cancel := c.call(ctx)
	defer cancel()

	resp, err := c.entries.ListEntries(rpcCtx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{BySpiffeId: target},
	})
	if err != nil {
		return Entry{}, false, classifyAdmin("lookup_run", run.RunID, err)
	}
	switch found := resp.GetEntries(); len(found) {
	case 0:
		return Entry{}, false, nil
	case 1:
		return fromWire(found[0]), true, nil
	default:
		// One entry per run is the invariant; more than one is not something to
		// pick a favourite from.
		return Entry{}, false, newError(ClassInvariantViolation, "lookup_run", run.RunID,
			fmt.Sprintf("SPIRE holds %d entries for %s; IP §1 allows one", len(found), spiffeID),
			false, nil)
	}
}

// RetireRun deletes the run's registration entry. It never touches ledger
// content (I4): retirement removes the identity, not the record of what the
// identity did.
//
// Idempotent (IP §4): retiring a run SPIRE no longer holds an entry for is a
// success with nothing deleted.
func (c *Client) RetireRun(ctx context.Context, run RunRef) (Retirement, error) {
	entry, found, err := c.LookupRun(ctx, run)
	if err != nil {
		return Retirement{}, err
	}
	if !found {
		return Retirement{}, nil
	}

	rpcCtx, cancel := c.call(ctx)
	defer cancel()

	resp, err := c.entries.BatchDeleteEntry(rpcCtx, &entryv1.BatchDeleteEntryRequest{Ids: []string{entry.ID}})
	if err != nil {
		return Retirement{}, classifyAdmin("retire_agent", run.RunID, err)
	}
	results := resp.GetResults()
	if len(results) != 1 {
		return Retirement{}, newError(ClassInvariantViolation, "retire_agent", run.RunID,
			fmt.Sprintf("SPIRE returned %d results for one deletion", len(results)), false, nil)
	}
	switch code := codes.Code(results[0].GetStatus().GetCode()); code { //nolint:gosec // a gRPC code from SPIRE's own response
	case codes.OK:
		return Retirement{EntryID: entry.ID, Deleted: true}, nil
	case codes.NotFound:
		// Deleted between the lookup and here. Still retirement.
		return Retirement{}, nil
	default:
		return Retirement{}, classifyAdmin("retire_agent", run.RunID, statusError(results[0].GetStatus()))
	}
}

// RequireActiveRun returns nil when SPIRE still holds an entry for the run, and
// a RUN_NOT_FOUND error when it does not.
//
// This is where IP §6.2's "retirement is effective immediately (no
// cached-credential grace path through the MCP)" is discharged. SPIRE's own
// refusal is NOT immediate: a deleted entry has to fall out of the server's
// entry cache and then the agent's, which RM-014 measured at 3–7 seconds, and
// during that window the agent still serves an SVID it has already minted. The
// MCP does not get to inherit that window. It asks the server whether the entry
// exists — an answer that changes the instant the delete commits — and refuses
// on the answer, not on a cache.
//
// The class is RUN_NOT_FOUND rather than RUN_ALREADY_RETIRED because SPIRE
// cannot tell the two apart: a retired run and a run that never existed both
// have no entry. The ledger can, and the MCP holds the ledger; translating
// RUN_NOT_FOUND into RUN_ALREADY_RETIRED when a `run_retired` event exists is
// that layer's job (IP §4).
func (c *Client) RequireActiveRun(ctx context.Context, run RunRef) error {
	spiffeID, err := run.SPIFFEID(c.trustDomain)
	if err != nil {
		return err
	}
	_, found, err := c.LookupRun(ctx, run)
	if err != nil {
		return err
	}
	if !found {
		return newError(ClassRunNotFound, "require_active_run", run.RunID,
			fmt.Sprintf("SPIRE holds no registration entry for %s", spiffeID), false, nil)
	}
	return nil
}

// fromWire converts SPIRE's entry to ours.
func fromWire(e *types.Entry) Entry {
	selectors := make([]Selector, 0, len(e.GetSelectors()))
	for _, s := range e.GetSelectors() {
		selectors = append(selectors, Selector{Type: s.GetType(), Value: s.GetValue()})
	}
	return Entry{
		ID:        e.GetId(),
		SPIFFEID:  idString(e.GetSpiffeId()),
		ParentID:  idString(e.GetParentId()),
		Selectors: selectors,
		TTL:       time.Duration(e.GetX509SvidTtl()) * time.Second,
	}
}

// legacyLabelPrefix marks the docker label selectors run entries carried
// before ADR-0053: dev.innsegl.run-id, dev.innsegl.agent-type and
// dev.innsegl.task-id. A label is chosen by whoever starts a container, so an
// entry that still carries one can be matched by any container claiming it.
const legacyLabelPrefix = "label:dev.innsegl."

// RunSelectorMigration is the outcome of MigrateRunSelectors.
type RunSelectorMigration struct {
	// Rewritten names the runs whose entry was moved, by run id.
	Rewritten []string
	// Unchanged counts the run entries there was nothing to do for.
	Unchanged int
}

// needsRunSelectorMigration reports whether an entry holding `has` is one the
// start-up rewrite moves to `want`. Two conditions, both required:
//
//   - it carries at least one legacy label selector. An entry on selectors an
//     operator chose for themselves (RegisterAgentConfig.Selectors) is theirs
//     to review, as doc 04 says, and not this migration's to touch;
//   - it is not already `want`, compared as a set. SPIRE does not promise to
//     hand selectors back in the order they were sent, and an entry already
//     on the target is the idempotent case.
func needsRunSelectorMigration(has, want []Selector) bool {
	legacy := false
	for _, s := range has {
		if s.Type == "docker" && strings.HasPrefix(s.Value, legacyLabelPrefix) {
			legacy = true
			break
		}
	}
	if !legacy {
		return false
	}
	if len(has) != len(want) {
		return true
	}
	for _, w := range want {
		found := false
		for _, h := range has {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// MigrateRunSelectors moves every live run entry still on the legacy label
// selectors to want(run) — ADR-0053's start-up rewrite.
//
// "Live" is SPIRE's own answer: a run entry exists only between registration
// and retirement (IP §1), so a retired or reaped run has no entry, appears in
// no listing, and is never recreated here. The rewrite changes selectors ONLY
// (the input mask says so): the entry id, the SPIFFE ID, the parent and the
// TTL stay, so no ledger record changes meaning.
//
// Each entry is updated on its own. One refused update does not stop the
// others: every entry left on labels is a path still open, so closing as many
// as can be closed is the point. The first failure is returned after the
// pass, with what was rewritten before and after it.
func (c *Client) MigrateRunSelectors(ctx context.Context, want func(RunRef) []Selector) (RunSelectorMigration, error) {
	var out RunSelectorMigration
	entries, err := c.ListAgentEntries(ctx)
	if err != nil {
		return out, err
	}
	var first error
	for _, e := range entries {
		run, rerr := RunRefOf(e.SPIFFEID)
		if rerr != nil {
			// In the subtree but not a run: not this migration's shape. The
			// reconciler reports it (RM-019).
			out.Unchanged++
			continue
		}
		target := want(run)
		if !needsRunSelectorMigration(e.Selectors, target) {
			out.Unchanged++
			continue
		}
		if uerr := c.updateSelectors(ctx, e, run, target); uerr != nil {
			if first == nil {
				first = uerr
			}
			continue
		}
		out.Rewritten = append(out.Rewritten, run.RunID)
	}
	return out, first
}

// updateSelectors replaces one entry's selectors and nothing else.
//
// The request names the entry's SPIFFE ID even though the mask leaves it
// unchanged. deploy/compose/spire/authz-policy.rego scopes BatchUpdateEntry
// by the SPIFFE ID each entry in the batch names, so an update without one is
// refused before SPIRE reads it (measured: PermissionDenied).
func (c *Client) updateSelectors(ctx context.Context, e Entry, run RunRef, sels []Selector) error {
	if len(sels) == 0 {
		return newError(ClassInvariantViolation, "migrate_selectors", run.RunID,
			"no selectors: an entry with no selectors is an identity every workload on the node matches (I1)",
			false, nil)
	}
	target, err := splitID(e.SPIFFEID)
	if err != nil {
		return newError(ClassInvariantViolation, "migrate_selectors", run.RunID, err.Error(), false, err)
	}
	wire := make([]*types.Selector, 0, len(sels))
	for _, s := range sels {
		wire = append(wire, &types.Selector{Type: s.Type, Value: s.Value})
	}

	rpcCtx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.entries.BatchUpdateEntry(rpcCtx, &entryv1.BatchUpdateEntryRequest{
		Entries:   []*types.Entry{{Id: e.ID, SpiffeId: target, Selectors: wire}},
		InputMask: &types.EntryMask{Selectors: true},
	})
	if err != nil {
		return classifyAdmin("migrate_selectors", run.RunID, err)
	}
	results := resp.GetResults()
	if len(results) != 1 {
		return newError(ClassInvariantViolation, "migrate_selectors", run.RunID,
			fmt.Sprintf("SPIRE returned %d results for one update", len(results)), false, nil)
	}
	if codes.Code(results[0].GetStatus().GetCode()) != codes.OK { //nolint:gosec // a gRPC code from SPIRE's own response
		return classifyAdmin("migrate_selectors", run.RunID, statusError(results[0].GetStatus()))
	}
	return nil
}

// withRun stamps a run id onto a classified error that was raised before the
// run was known.
func withRun(err error, runID string) error {
	var e *Error
	if !errors.As(err, &e) || e.RunID != "" {
		return err
	}
	stamped := *e
	stamped.RunID = runID
	return &stamped
}
