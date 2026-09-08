// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

// API-020 through API-022 (proposed for doc 07; doc 07 is not modified here).
//
// The runs table sorts oldest-first or newest-first, and the LEDGER does it.
//
// # Why this is not a client-side sort, which is the obvious cheap answer
//
// `web/src/views/runs/api.ts` states the rule and FE-051 asserts it: there is
// no client-side filter, sort or search in that directory. The browser holds
// ONE PAGE of runs. Sorting those would produce a table that looks sorted and
// is only sorted within the slice that happened to be fetched — a reader
// looking at "oldest first" would see the oldest of the newest fifty, which is
// not what the words say.
//
// # The part that breaks silently
//
// Paging is a keyset cursor: `chain_position < $7`, which is correct for
// DESC and wrong for ASC. Flip the order without flipping the comparison and
// the first page is right, the second page is empty or repeats, and nothing
// reports an error. API-021 is that case, and it is the reason this is a pair
// of complete statements rather than one statement with the direction pasted
// into it.

func TestAPI020OrderDefaultsToNewestFirst(t *testing.T) {
	got, err := runsOrder("")
	if err != nil {
		t.Fatalf("runsOrder(\"\"): %v", err)
	}
	if got != OrderDesc {
		t.Errorf("runsOrder(\"\") = %q, want %q — an unset order must not change what the table shows", got, OrderDesc)
	}
	for _, in := range []string{"desc", "DESC", "Desc"} {
		if o, err := runsOrder(in); err != nil || o != OrderDesc {
			t.Errorf("runsOrder(%q) = %q, %v; want %q, nil", in, o, err, OrderDesc)
		}
	}
	for _, in := range []string{"asc", "ASC", "Asc"} {
		if o, err := runsOrder(in); err != nil || o != OrderAsc {
			t.Errorf("runsOrder(%q) = %q, %v; want %q, nil", in, o, err, OrderAsc)
		}
	}
}

// TestAPI021TheCursorComparisonFollowsTheOrder. The one that breaks quietly:
// a keyset cursor written for DESC returns nothing on page two of an ASC
// listing, and no error is raised anywhere.
func TestAPI021TheCursorComparisonFollowsTheOrder(t *testing.T) {
	desc, asc := runsQuery(OrderDesc), runsQuery(OrderAsc)

	if !contains(desc, "chain_position < $7") {
		t.Error("the descending query does not page with `chain_position < $7`")
	}
	if !contains(desc, "ORDER BY chain_position DESC") {
		t.Error("the descending query does not order descending")
	}
	if !contains(asc, "chain_position > $7") {
		t.Error("the ascending query pages with the descending comparison; " +
			"page two would be empty and nothing would say so")
	}
	if !contains(asc, "ORDER BY chain_position ASC") {
		t.Error("the ascending query does not order ascending")
	}
	if desc == asc {
		t.Error("both orders produced the same statement")
	}
}

// TestAPI022AnUnknownOrderIsRefused. The direction reaches SQL, so it is a
// closed set checked at the edge rather than a string that gets pasted in.
func TestAPI022AnUnknownOrderIsRefused(t *testing.T) {
	for _, bad := range []string{"ascending", "up", "chain_position", "asc; drop table", "1"} {
		if _, err := runsOrder(bad); err == nil {
			t.Errorf("runsOrder(%q) was accepted; the direction reaches SQL and the set is closed", bad)
		}
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
