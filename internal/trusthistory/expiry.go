// SPDX-License-Identifier: Apache-2.0

package trusthistory

import "time"

// Warning is how close a CA is to expiring.
type Warning string

const (
	WarningNone    Warning = ""
	WarningYear    Warning = "expires within a year"
	Warning90Days  Warning = "expires within 90 days"
	WarningExpired Warning = "expired"
)

// WarningFor places notAfter against the two thresholds: one year and 90 days.
func WarningFor(notAfter, now time.Time) Warning {
	switch {
	case !notAfter.After(now):
		return WarningExpired
	case !notAfter.After(now.AddDate(0, 0, 90)):
		return Warning90Days
	case !notAfter.After(now.AddDate(1, 0, 0)):
		return WarningYear
	default:
		return WarningNone
	}
}

// Expiry is one CA in use and when it expires.
type Expiry struct {
	Name     string    `json:"name"`
	Kind     Kind      `json:"kind"`
	KeyID    string    `json:"key_id"`
	NotAfter time.Time `json:"not_after"`
	Warning  Warning   `json:"warning,omitempty"`
}

// caNames are the CAs whose expiry is watched, in the order they are shown.
var caNames = []struct {
	kind Kind
	name string
}{
	{KindFulcioRoot, "Fulcio root CA"},
	{KindSPIREUpstreamCA, "SPIRE upstream CA"},
	{KindGatewayCA, "gateway CA"},
}

// Expiries lists the current CA of each watched kind and how close it is to
// expiring. A log key has no expiry and is not listed.
func Expiries(h *History, now time.Time) []Expiry {
	if h == nil {
		return nil
	}
	out := []Expiry{}
	for _, c := range caNames {
		e, ok := h.Current(c.kind)
		if !ok {
			continue
		}
		cert, err := e.Certificate()
		if err != nil {
			continue
		}
		out = append(out, Expiry{Name: c.name, Kind: c.kind, KeyID: e.KeyID,
			NotAfter: cert.NotAfter.UTC(), Warning: WarningFor(cert.NotAfter, now)})
	}
	return out
}
