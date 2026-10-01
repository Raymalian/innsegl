// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"time"
)

// guard.go is the one hook every request-time refusal in this package
// plugs into, from GW-011 (harness shape, this file's own HarnessGuard)
// through GW-013 (rate limiting, limit.go's SessionRateLimitGuard, #375)
// and whatever E15 (identity, ADR-0058 decision 11) adds next.
// Proxy.ServeHTTP (proxy.go) runs every configured Guard, in order, before
// building or sending the upstream request; the first refusal ends the
// request there.
//
// # For E15
//
// Add a Guard implementation here (or in a file of its own) and add it
// inside the Guards function below, at whatever position its own ordering
// requires -- that is the ONE place a guard chain is built; see Guards'
// own doc comment for why. A Guard that lets a request through can hand
// whatever a later Guard or an observer needs by returning
// r.WithContext(...) -- see WithIdentification in harness.go for the
// pattern HarnessGuard uses to carry its Identification forward, and
// SessionRateLimitGuard (limit.go) for a guard that consumes it. Nothing
// about the forwarding path in proxy.go needs to change again for a new
// Guard to plug in here.

// Refusal ends a request before Proxy.ServeHTTP forwards anything. Status
// is the HTTP status the caller receives: 400 for an unrecognised harness
// shape (HarnessGuard, GW-011), with 403 and 429 reserved for identity and
// rate-limit refusals respectively, so a caller can tell the three apart
// without parsing Reason. Reason is written into the JSON error body
// alongside "innsegl" (writeGatewayError, proxy.go) -- a plain-English
// explanation, never a code a caller has to look up elsewhere.
type Refusal struct {
	Status int
	Reason string
	// RetryAfter, when positive, is sent as the Retry-After header: the
	// refusal is for a missing input the harness will supply, and the same
	// request is expected to succeed once it has.
	RetryAfter time.Duration
}

// Guard inspects an incoming request before Proxy.ServeHTTP forwards it.
// Proxy.Guards runs in order; the first Guard to return a non-nil *Refusal
// ends the request there -- nothing after it runs, and the upstream never
// sees the request. A Guard that permits the request returns the
// *http.Request the rest of the chain should use from here on: r itself,
// unchanged, or r.WithContext(...) carrying something a later Guard or
// observer needs. Returning nil for that request is the same as returning r
// unchanged.
type Guard interface {
	Check(r *http.Request) (*http.Request, *Refusal)
}

// HarnessGuard is GW-011 and GW-012: the harness-shape guard installed by
// default (see defaultGuards and Proxy.ServeHTTP in proxy.go). It refuses
// any request whose shape it does not recognise, rather than guess at a
// session or agent id -- ADR-0058 decision 2's own caveat, applied at the
// point traffic arrives -- and attaches the Identification it found to the
// request's context for whatever Guard runs next.
type HarnessGuard struct {
	recognisers []harnessRecogniser
}

// NewHarnessGuard returns the harness-shape guard, recognising every
// harness version this build supports (harness.go's registeredRecognisers).
// Adding a harness version is adding a recogniser there and a
// testdata/harness/ fixture set (GW-012), never loosening an existing
// recogniser.
func NewHarnessGuard() *HarnessGuard {
	return &HarnessGuard{recognisers: registeredRecognisers}
}

// Check implements Guard.
func (g *HarnessGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	var reason string
	for _, recognise := range g.recognisers {
		id, ok, why := recognise(r)
		if ok {
			return r.WithContext(WithIdentification(r.Context(), id)), nil
		}
		reason = why
	}
	if reason == "" {
		reason = "the request shape did not match any supported harness version"
	}
	return nil, &Refusal{
		Status: http.StatusBadRequest,
		Reason: "innsegl gateway: unrecognised harness shape, refusing rather than guessing a session or agent id: " + reason,
	}
}

// Guards returns this package's own ordered guard chain: the harness-shape
// guard (GW-011, HarnessGuard) first, then -- when identity is non-nil --
// the identity guard (ADR-0058 decision 11, E15/#380's IdentityGuard), then
// the per-session rate-limit guard (GW-013, limit.go's
// SessionRateLimitGuard) built from limiter, then every witness in
// witnesses, in that order.
//
// The rate-limit guard reads the session id the harness guard attaches to
// the request's context, and finding none there is itself a refusal
// (SessionRateLimitGuard.Check) rather than a guess, and the identity guard
// sits ahead of it so a request with no issuable identity never consumes a
// place in the rate limit at all. The witnesses sit LAST, after the rate
// limit, so a request the rate limit itself refuses never reaches one --
// there is nothing to witness in a request that was never forwarded.
//
// identity is nilable because an IdentityGuard needs real dependencies
// (a Postgres-backed MappingStore, the MCP's own register_agent/retire_agent
// wired, a RunStateReader over a real chain) that cannot exist at package
// initialisation time (see defaultGuards, below) -- unlike the rate
// limiter, which has a workable in-memory default. Nil means "no identity
// guard in this chain", never a refuse-everything stand-in: a caller that
// wants ADR-0058 decision 11 enforced passes the guard it built
// (cmd/innsegl/gateway.go's openGateway does exactly this).
//
// witnesses is variadic and nil-tolerant: a nil entry among them is skipped
// rather than appended, so a caller with an optional witness (RM-236's
// ToolCallRecordGuard, RM-237's MessageRecorder, built only when their own
// dependencies are configured) passes whatever it built, unfiltered. Every
// witness this package ships never refuses a request (record.go's and
// messages.go's own doc comments, "witness, never a gate") -- Guards does
// not and cannot enforce that itself (a Guard is free to refuse; nothing
// about the interface stops one), but it is what every witness's own tests
// pin, and TestGuardsOrdersHarnessIdentityRateLimitThenWitnesses
// (guard_test.go) pins the ordering here plus that property for the two
// this codebase actually ships.
//
// THIS IS THE ONE LIST. defaultGuards (below) and cmd/innsegl/gateway.go's
// openGateway both build their guard chain by calling this function --
// the first with no identity guard, no witnesses and a limiter built from
// this package's own shipped defaults, the second with a fully-wired
// identity guard, its own witnesses and a limiter built from the command
// line ($INNSEGL_GATEWAY_RATE / $INNSEGL_GATEWAY_BURST). Before this
// function existed, those were two independently-written slices that had
// to be kept in the same order by hand; a guard added to one and not the
// other would silently ship a production gateway missing a protection the
// tests for the other slice still passed. RM-236 (#381) then grew a SECOND
// such hand-maintained list of its own (ChainGuards, composing the identity
// guard and its own witness OUTSIDE of this function, because this
// function had room for exactly one identity slot) -- exactly the drift
// this function exists to prevent, reintroduced one layer up. witnesses is
// this function's own fix for that: every future guard, witness or
// otherwise, is added HERE, inside this function, at whatever position its
// own ordering requires, and nowhere else: no other place in this codebase
// is allowed to grow its own, second, hand-maintained guard list.
func Guards(limiter *SessionRateLimiter, identity Guard, witnesses ...Guard) []Guard {
	guards := []Guard{NewHarnessGuard()}
	if identity != nil {
		guards = append(guards, identity)
	}
	guards = append(guards, NewSessionRateLimitGuard(limiter))
	for _, w := range witnesses {
		if w != nil {
			guards = append(guards, w)
		}
	}
	return guards
}

// defaultGuards is what Proxy.ServeHTTP uses when Guards is nil -- see
// proxy.go. Passing an explicit empty slice (Guards: []Guard{}) opts out of
// every default guard; this is the one place that default is set, so a
// Proxy refuses an unrecognised harness shape wherever one is constructed,
// with no wiring needed at each call site. Built from Guards, with no
// identity guard (see Guards' own doc comment for why one cannot exist at
// this point) and a limiter using this package's own shipped defaults
// (DefaultSessionRateLimitRate, DefaultSessionRateLimitBurst) -- a caller
// that needs the configured values from $INNSEGL_GATEWAY_RATE /
// $INNSEGL_GATEWAY_BURST, or ADR-0058 decision 11 enforced, calls Guards
// itself instead (cmd/innsegl/gateway.go's openGateway does exactly this).
var defaultGuards = Guards(defaultSessionRateLimiter(), nil)

// defaultSessionRateLimiter builds the limiter defaultGuards' rate-limit
// guard uses, from this package's own shipped defaults. Those defaults are
// constants this package's own tests hold fixed
// (TestDefaultSessionRateLimitSettingsAreValid, limit_test.go), so
// NewSessionRateLimiter refusing here can only mean that guarantee broke --
// and failing loudly at package initialisation is preferable to shipping a
// gateway whose default rate limit silently is not there.
func defaultSessionRateLimiter() *SessionRateLimiter {
	lim, err := NewSessionRateLimiter(SessionRateLimit{
		Rate:  DefaultSessionRateLimitRate,
		Burst: DefaultSessionRateLimitBurst,
	})
	if err != nil {
		panic("innsegl gateway: default session rate limit settings are invalid: " + err.Error())
	}
	return lim
}
