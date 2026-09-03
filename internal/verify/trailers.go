// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"strings"
)

// The trailer reader, and the identity comparison IP §1's check 3 is.
//
// # Why this is not RM-031's parser
//
// internal/signing deliberately exported none. Its classifier is a WRITER's:
// isTrailerLine is narrower than git's on purpose, because a writer that
// mistakes prose for a trailer merges its claim into a paragraph git will not
// read, and "a trailer git cannot find is a claim nothing can check"
// (ADR-0028). Every one of its asymmetries points the same way — refuse, and
// place the claim somewhere unambiguous.
//
// A verifier's asymmetries point the other way. The commit is already written;
// nothing can be moved. If a claim is present in any form a reader could take
// as a claim, the verifier must SEE it and judge it, because the alternative
// is a commit that carries `Agent-Identity : spiffe://...` and is reported as
// making no claim at all — which is a forger's best outcome. So this reader is
// permissive in exactly the places the writer is strict: whitespace before the
// separator, case, position in the message, and lines past a `---` divider.
//
// It is strict in one place, and that strictness is also a verifier's: two
// Agent-Identity trailers are refused rather than resolved. A verifier that
// picked one would be choosing which claim to check (IP §6.9).

// The three trailer keys. PROTECTED STRINGS (doc 08 §3, VERSIONING.md surface
// 2): character-exact, and a reader that spelled one differently would quietly
// stop finding claims. They are duplicated from internal/signing rather than
// imported so that this package depends on nothing of ours;
// TestTheReaderReadsTheProtectedTrailerKeys holds the two spellings together.
const (
	trailerAgentIdentity = "Agent-Identity"
	trailerAgentRun      = "Agent-Run"
	trailerAgentTask     = "Agent-Task"
)

// Claim is what a commit's trailers assert. It is claimed, never established.
type Claim struct {
	Identity string `json:"identity,omitempty"`
	Run      string `json:"run,omitempty"`
	Task     string `json:"task,omitempty"`
}

// Present reports whether the commit makes any attribution claim at all. Any
// one of the three is a claim: a commit carrying only Agent-Run is malformed,
// but it is not unattributed, and VER-006's distinction turns on that.
func (c Claim) Present() bool {
	return c.Identity != "" || c.Run != "" || c.Task != ""
}

// disagreesWith reports how the claim's own three values fail to agree with
// the identity the certificate proves, or "".
//
// The three trailers are redundant by construction (RM-031 holds Agent-Run to
// the identity's run segment and Agent-Task to its task segment), and that
// redundancy is what lets check 3 settle all three from the certificate alone,
// with no access to this system's database — which is I5.
//
// An identity that does not parse into the six named segments is one this
// comparison cannot settle Agent-Run or Agent-Task against — it is not one
// that agrees with them (#137). This fails closed: whichever of the two
// trailers is present is reported as unconfirmable, in those words, rather
// than as a disagreement that was never established. ADR-0042 records why
// this matters and why it is not, by itself, support for non-SPIFFE
// identities: a public Fulcio root issuing such a SAN remains refused.
func (c Claim) disagreesWith(san string) string {
	parts, err := splitSPIFFEID(san)
	if err != nil {
		return c.unconfirmable(san, err)
	}
	if c.Run != "" && c.Run != parts[runSegment] {
		return fmt.Sprintf("the %s trailer is %q; the certificate's identity names the run %q",
			trailerAgentRun, c.Run, parts[runSegment])
	}
	if c.Task != "" && strings.ToLower(c.Task) != parts[taskSegment] {
		return fmt.Sprintf("the %s trailer is %q, which does not lowercase to the task %q "+
			"in the certificate's identity", trailerAgentTask, c.Task, parts[taskSegment])
	}
	return ""
}

// unconfirmable names the redundant trailers this claim carries that
// disagreesWith could not check against san, because san does not parse as a
// SPIFFE ID, or "" when the claim carries neither — nothing was owed a
// verdict, so nothing is reported.
func (c Claim) unconfirmable(san string, parseErr error) string {
	var trailers []string
	if c.Run != "" {
		trailers = append(trailers, trailerAgentRun)
	}
	if c.Task != "" {
		trailers = append(trailers, trailerAgentTask)
	}
	if len(trailers) == 0 {
		return ""
	}
	noun := "trailer"
	if len(trailers) > 1 {
		noun = "trailers"
	}
	return fmt.Sprintf("the certificate's identity %q could not be read as a SPIFFE ID (%v), "+
		"so the %s %s could not be checked against it",
		san, parseErr, strings.Join(trailers, " and "), noun)
}

// ReadClaim reads the three trailers out of a commit message.
//
// Every line of the message is considered, wherever it sits: a verifier that
// only looked where git looks would report a commit whose trailer block was
// mangled as making no claim.
func ReadClaim(message string) (Claim, error) {
	found := map[string][]string{}
	for _, line := range strings.Split(message, "\n") {
		key, value, ok := trailerOf(line)
		if !ok {
			continue
		}
		found[key] = append(found[key], value)
	}
	var c Claim
	for _, key := range []string{trailerAgentIdentity, trailerAgentRun, trailerAgentTask} {
		values := found[key]
		if len(values) > 1 {
			return Claim{}, fmt.Errorf("the commit message carries %d %s trailers "+
				"(%s); a verifier that picked one of them would be choosing which "+
				"claim to check (IP §6.9)",
				len(values), key, strings.Join(quoteAll(values), ", "))
		}
		if len(values) == 1 {
			switch key {
			case trailerAgentIdentity:
				c.Identity = values[0]
			case trailerAgentRun:
				c.Run = values[0]
			default:
				c.Task = values[0]
			}
		}
	}
	return c, nil
}

func quoteAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprintf("%q", v)
	}
	return out
}

// trailerOf reads one line as a trailer of one of the three protected keys.
//
// Permissive by design: leading whitespace, any case, and any amount of
// whitespace before the colon — every spelling a reader might take as the key.
// hasTrailerToken in internal/signing matches the same set, and for the same
// reason: it is the WRITER's refusal test, which must also be wider than its
// acceptance test.
func trailerOf(line string) (key, value string, ok bool) {
	trimmed := strings.TrimLeft(line, " \t")
	for _, k := range []string{trailerAgentIdentity, trailerAgentRun, trailerAgentTask} {
		if len(trimmed) < len(k) || !strings.EqualFold(trimmed[:len(k)], k) {
			continue
		}
		rest := strings.TrimLeft(trimmed[len(k):], " \t")
		if !strings.HasPrefix(rest, ":") {
			continue
		}
		return k, strings.TrimSpace(rest[1:]), true
	}
	return "", "", false
}

// ---------------------------------------------------------------------------
// The identity comparison, and the segment that differs.
// ---------------------------------------------------------------------------

// The SPIFFE ID grammar of IP §1 and doc 02 §5, as named positions:
//
//	spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}
//
// PROTECTED SURFACE (VERSIONING.md surface 3). The names are what a reader
// sees when a comparison fails, and "the identities differ" is not a finding
// anybody can act on — WHICH segment differs is.
const (
	schemeSegment = iota
	trustDomainSegment
	agentSegment
	agentTypeSegment
	taskSegment
	runSegment
	spiffeSegments
)

var spiffeSegmentNames = [spiffeSegments]string{
	"scheme", "trust-domain", "agent", "agent-type", "task-id", "run-id",
}

// splitSPIFFEID breaks an identity into its six named segments.
func splitSPIFFEID(id string) ([spiffeSegments]string, error) {
	var out [spiffeSegments]string
	scheme, rest, ok := strings.Cut(id, "://")
	if !ok {
		return out, fmt.Errorf("%q has no scheme", id)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != spiffeSegments-1 {
		return out, fmt.Errorf("%q has %d path segments after the trust domain, "+
			"the grammar has %d", id, len(parts)-1, spiffeSegments-2)
	}
	out[schemeSegment] = scheme
	copy(out[trustDomainSegment:], parts)
	return out, nil
}

// DiffIdentity names the first segment in which two SPIFFE IDs differ, or ""
// when they are the same.
//
// This is what makes VER-002 readable. A forged trailer usually differs in one
// segment — a run id, a task — and a report that said only "mismatch" would
// leave the reader diffing two 60-character URIs by eye.
func DiffIdentity(trailer, certificate string) string {
	if trailer == certificate {
		return ""
	}
	claimed, cerr := splitSPIFFEID(trailer)
	proven, perr := splitSPIFFEID(certificate)
	if cerr != nil || perr != nil {
		return fmt.Sprintf("the two identities cannot be compared segment by segment: "+
			"the trailer is %q and the certificate's URI SAN is %q", trailer, certificate)
	}
	for i := range spiffeSegments {
		if claimed[i] != proven[i] {
			return fmt.Sprintf("%s: the trailer says %q, the certificate says %q",
				spiffeSegmentNames[i], claimed[i], proven[i])
		}
	}
	// Same six segments, different strings: only a separator can differ.
	return fmt.Sprintf("the identities differ outside the six named segments: "+
		"the trailer is %q and the certificate's URI SAN is %q", trailer, certificate)
}
