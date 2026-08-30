// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Rendering a report.
//
// Doc 06 §4.1 describes a panel: three named checks, each with its own
// tri-state result, and the evidence behind each one adjacent to it. This is
// that panel in text, and it follows the same rules, because the CLI is the
// artifact a stranger screenshots into an audit report (doc 06 §3.6):
//
//   - the three checks never collapse into one line;
//   - a check's evidence is printed with it, not summarised;
//   - `unavailable` is spelled, never rounded to either neighbour;
//   - a commit that makes no attribution claim prints NO checks and the word
//     `unattributed`, and the word "failed" appears nowhere in it.

// Render writes the human-readable report.
func Render(r Report) string {
	var b strings.Builder

	b.WriteString("innsegl verify\n\n")
	field(&b, "commit", r.CommitSHA)
	field(&b, "tree", r.TreeHash)
	field(&b, "repository", r.Repo)
	if r.Certificate.SPIFFEID != "" {
		field(&b, "identity", r.Certificate.SPIFFEID)
	}
	fmt.Fprintf(&b, "\n  VERDICT: %s\n", strings.ToUpper(string(r.Verdict)))

	for i, c := range r.Checks {
		fmt.Fprintf(&b, "\n  %d. %s\n", i+1, c.Name)
		fmt.Fprintf(&b, "     result: %s\n", c.Result)
		fmt.Fprintf(&b, "     %s\n", wrap(c.Detail, "     "))
		for _, f := range c.Facts {
			fmt.Fprintf(&b, "       %-30s %s\n", f.Name, wrap(f.Value, strings.Repeat(" ", 39)))
		}
	}

	if len(r.Recovered) > 0 {
		b.WriteString("\n  original attribution, recovered through the tree hash:\n")
		for _, rec := range r.Recovered {
			fmt.Fprintf(&b, "       commit %s\n       signed by %s\n       log index %d at %s\n",
				rec.CommitSHA, rec.Identity, rec.LogIndex, rec.IntegratedAt.Format(rfc3339))
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n  note: %s\n", wrap(n, "        "))
	}
	return b.String()
}

const rfc3339 = "2006-01-02T15:04:05Z07:00"

// marshalIndent is json.MarshalIndent behind a seam. Report holds only
// strings, ints, bools and times, so the encoder cannot fail on it and the
// error path below is unreachable in production — which is exactly why it is
// reachable from a test rather than left as a branch nobody has taken. Never
// reassigned outside tests (internal/segment's validateDigest, same idiom).
var marshalIndent = json.MarshalIndent

func field(b *strings.Builder, name, value string) {
	fmt.Fprintf(b, "  %-12s %s\n", name, value)
}

// wrap folds a long line at 88 columns, indenting continuations, so a
// certificate identity and a Rekor error both stay readable in a terminal.
func wrap(s, indent string) string {
	const width = 88
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line == "" {
			line = word
			continue
		}
		if len(line)+1+len(word) > width {
			out = append(out, line)
			line = word
			continue
		}
		line += " " + word
	}
	out = append(out, line)
	return strings.Join(out, "\n"+indent)
}

// RenderJSON writes the machine-readable report — doc 06 P5: any verification
// the dashboard performs, a user must be able to reproduce without it, which
// needs the exact inputs and not a rendering of them.
func RenderJSON(r Report) ([]byte, error) {
	out, err := marshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
