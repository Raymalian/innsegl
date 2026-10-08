// SPDX-License-Identifier: Apache-2.0

package deploy

import "testing"

// GH-007 (PROPOSED for doc 07) — the core receives the operator pairs its
// deployment pins, and pins none by default.
//
// A repository set to author agent commits as the operator (ENF-010) is
// signed only when the core's I6 policy pins that operator's
// `Name <address>`. The core reads the pairs from
// INNSEGL_SIGN_AUTHOR_OPERATORS, and compose has to hand it over from the
// deployment's .env; a variable compose never passes is a setting the
// operator writes and the core never sees.
func TestGH007TheCoreReceivesItsPinnedOperatorPairs(t *testing.T) {
	const pair = "Op Erator <1+op@users.noreply.github.com>"
	set := composeRender(t, []string{"INNSEGL_SIGN_AUTHOR_OPERATORS=" + pair}, coreBase).Services["innsegl-mcp"]
	if v := set.Environment["INNSEGL_SIGN_AUTHOR_OPERATORS"]; v == nil || *v != pair {
		t.Fatalf("innsegl-mcp INNSEGL_SIGN_AUTHOR_OPERATORS = %v, want %q", v, pair)
	}
	unset := composeRender(t, nil, coreBase).Services["innsegl-mcp"]
	if v := unset.Environment["INNSEGL_SIGN_AUTHOR_OPERATORS"]; v != nil && *v != "" {
		t.Fatalf("with nothing in .env the core pins %q; the default must pin no operator", *v)
	}
}
