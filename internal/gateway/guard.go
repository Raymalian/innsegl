// SPDX-License-Identifier: Apache-2.0

package gateway

import "net/http"

// guard.go is the one hook every request-time refusal in this package
// plugs into, from GW-011 (harness shape, this file's own HarnessGuard)
// through whatever #375 (rate limiting, GW-013) and E15 (identity,
// ADR-0058 decision 11) add next. Proxy.ServeHTTP (proxy.go) runs every
// configured Guard, in order, before building or sending the upstream
// request; the first refusal ends the request there.
//
// # For #375 and E15
//
// Add a Guard implementation here (or in a file of its own) and either
// append it to a Proxy's own Guards, or add it to defaultGuards below if it
// should apply wherever a Proxy exists by default, the way HarnessGuard
// does. A Guard that lets a request through can hand whatever a later
// Guard or an observer needs by returning r.WithContext(...) -- see
// WithIdentification in harness.go for the pattern HarnessGuard uses to
// carry its Identification forward. Nothing about the forwarding path in
// proxy.go needs to change again for a new Guard to plug in here.

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

// defaultGuards is what Proxy.ServeHTTP uses when Guards is nil -- see
// proxy.go. Passing an explicit empty slice (Guards: []Guard{}) opts out of
// every default guard; this is the one place that default is set, so a
// Proxy refuses an unrecognised harness shape wherever one is constructed,
// with no wiring needed at each call site.
var defaultGuards = []Guard{NewHarnessGuard()}
