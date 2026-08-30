// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git's object name is SHA-1; this recomputes it, it does not choose it
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/verify"
)

// Re-deriving a proof response from its own material — the check that convicts
// a lying server.
//
// #48's headline criterion: "a tampered BFF must be detectable by re-derivation
// from the returned material. A response whose 'proof' cannot convict a lying
// server is not a proof."
//
// # WHAT THIS IS, AND EMPHATICALLY WHAT IT IS NOT
//
// This is NOT a second verifier. It performs no network call, validates no
// certificate chain, checks no signature and proves no inclusion. Every one of
// those is internal/verify's, there is one of it, and running a second one here
// would be exactly the duplication #48 forbids.
//
// What this does is narrower and it is the thing the criterion actually asks
// for: it recomputes, FROM THE MATERIAL THE RESPONSE CARRIES, every assertion
// the response makes that the material can settle, and reports where the two
// disagree. It cannot tell you the commit is genuinely attributed — for that,
// run `innsegl verify` against Fulcio and Rekor yourself, which is the whole
// point of being given the material. It can tell you that this server's answer
// contradicts its own evidence, and a server whose answer survives that is a
// server whose remaining claims are worth checking upstream.
//
// The two checks it reuses rather than reimplements are internal/verify's own
// exported ones: ReadClaim reads the trailers out of the commit object, and
// DiffIdentity compares a claimed SPIFFE ID with a proven one. One reader, one
// comparison, used by the verifier and by the re-derivation both.
//
// # THREE STATES HERE TOO
//
// A finding agrees, contradicts, or could not be derived. The third is not
// tidiness: a response degraded by an unreachable Rekor carries no entry, and a
// checker that read absent material as agreement would be FD anti-pattern 1 —
// a verdict rendered from nothing — with the badge moved one level down.

// Agreement is one re-derivation's outcome.
type Agreement string

const (
	// Agrees: the material settles this and the response is right about it.
	Agrees Agreement = "agrees"
	// Contradicts: the material settles this and the response is wrong.
	Contradicts Agreement = "contradicts"
	// Underivable: the material does not settle this. NEVER read as either
	// of the other two.
	Underivable Agreement = "underivable"
)

// Finding is one re-derived claim.
type Finding struct {
	Name   string    `json:"name"`
	Result Agreement `json:"result"`
	Detail string    `json:"detail,omitempty"`
}

// The findings, named so a caller can address one.
const (
	FindingCommitObject  = "the commit object is the commit that was asked about"
	FindingTrailerClaim  = "the Agent-Identity trailer is the one the response reports"
	FindingCertificate   = "the certificate is the one the transparency log recorded"
	FindingArtifact      = "the log entry is this commit's artifact"
	FindingLogIndex      = "the log index is the one the response reports"
	FindingIdentityCheck = "check 3 re-derives to the result the response reports"
	FindingRollup        = "the verdict is the rollup of the reported checks"
)

// Rederive recomputes what a proof response asserts, from that response's own
// material, and reports where the two disagree.
func Rederive(p Proof) []Finding {
	object := []byte(p.Material.CommitObject)
	entry, entryErr := entryBody(p.Material.RekorEntry, p.Entry.UUID)

	return []Finding{
		rederiveCommitObject(p, object),
		rederiveTrailer(p, object),
		rederiveCertificate(p, entry, entryErr),
		rederiveArtifact(p, entry, entryErr),
		rederiveLogIndex(p, entry, entryErr),
		rederiveIdentityCheck(p, object, entry, entryErr),
		rederiveRollup(p),
	}
}

// Contradictions is the subset of findings that convict the responder.
func Contradictions(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Result == Contradicts {
			out = append(out, f)
		}
	}
	return out
}

func agrees(name, detail string) Finding {
	return Finding{Name: name, Result: Agrees, Detail: detail}
}

func contradicts(name, detail string) Finding {
	return Finding{Name: name, Result: Contradicts, Detail: detail}
}

func underivable(name, detail string) Finding {
	return Finding{Name: name, Result: Underivable, Detail: detail}
}

// rederiveCommitObject is the binding that makes everything else evidence: the
// bytes hash to the object name the caller asked about, so the response is not
// about some other commit.
func rederiveCommitObject(p Proof, object []byte) Finding {
	if len(object) == 0 {
		return underivable(FindingCommitObject,
			"the response carries no commit object, so nothing binds its material "+
				"to the commit it names")
	}
	if p.CommitSHA == "" {
		return underivable(FindingCommitObject, "the response names no commit")
	}
	got := gitObjectName(object, p.CommitSHA)
	if got != p.CommitSHA {
		return contradicts(FindingCommitObject, fmt.Sprintf(
			"the object in this response hashes to %s; the response is about %s. "+
				"Whatever else it says, it is not about the commit it names.",
			got, p.CommitSHA))
	}
	return agrees(FindingCommitObject,
		"re-hashing the object reproduces "+p.CommitSHA)
}

// rederiveTrailer reads the claim out of the commit object with the verifier's
// own reader, and holds the response's rendering of it to account.
func rederiveTrailer(p Proof, object []byte) Finding {
	if len(object) == 0 {
		return underivable(FindingTrailerClaim, "the response carries no commit object")
	}
	claim, err := verify.ReadClaim(commitMessage(object))
	if err != nil {
		if !p.Claim.Present() {
			return agrees(FindingTrailerClaim,
				"the object's trailers do not resolve, and the response claims no identity: "+
					err.Error())
		}
		return contradicts(FindingTrailerClaim, fmt.Sprintf(
			"the response reports the identity %q, but the object's own trailers do "+
				"not resolve to one: %v", p.Claim.Identity, err))
	}
	for _, f := range []struct {
		what          string
		derived, said string
	}{
		{"Agent-Identity", claim.Identity, p.Claim.Identity},
		{"Agent-Run", claim.Run, p.Claim.Run},
		{"Agent-Task", claim.Task, p.Claim.Task},
	} {
		if f.derived != f.said {
			return contradicts(FindingTrailerClaim, fmt.Sprintf(
				"the commit object's %s trailer is %q; the response reports %q",
				f.what, f.derived, f.said))
		}
	}
	return agrees(FindingTrailerClaim,
		"the object's trailers are the claim the response reports")
}

// rederiveCertificate holds the reported certificate to the one the log
// recorded. The log's copy is the one bound to the entry, and the entry is
// bound to the commit, so this is where a swapped certificate is caught.
func rederiveCertificate(p Proof, entry *logEntryBody, entryErr error) Finding {
	if entryErr != nil {
		return underivable(FindingCertificate,
			"the certificate cannot be checked against the log's record: "+entryErr.Error())
	}
	logged, err := parseCertificatePEM(entry.certificatePEM)
	if err != nil {
		return underivable(FindingCertificate,
			"the entry's certificate does not parse: "+err.Error())
	}

	if served := p.Material.CertificatePEM; served != "" {
		servedCert, serr := parseCertificatePEM([]byte(served))
		switch {
		case serr != nil:
			return contradicts(FindingCertificate,
				"the certificate served as material does not parse: "+serr.Error())
		case !bytes.Equal(servedCert.Raw, logged.Raw):
			return contradicts(FindingCertificate, fmt.Sprintf(
				"the certificate served as material (sha256:%s) is not the one the "+
					"log recorded for this entry (sha256:%s)",
				fingerprint(servedCert), fingerprint(logged)))
		}
	}
	if want := p.Certificate.Fingerprint; want != "" && want != fingerprint(logged) {
		return contradicts(FindingCertificate, fmt.Sprintf(
			"the response reports the certificate fingerprint %s; the certificate "+
				"the log recorded is %s", want, fingerprint(logged)))
	}
	if san := uriSAN(logged); p.Certificate.SPIFFEID != "" && san != p.Certificate.SPIFFEID {
		return contradicts(FindingCertificate, fmt.Sprintf(
			"the response reports the identity %q; the certificate the log recorded "+
				"names %q in its URI SAN", p.Certificate.SPIFFEID, san))
	}
	return agrees(FindingCertificate,
		"the reported certificate is the one the log holds for this entry, sha256:"+
			fingerprint(logged))
}

// rederiveArtifact is arithmetic: the log entry is keyed on sha256 of the
// commit SHA (ADR-0031 decision 6), so anyone can recompute it.
func rederiveArtifact(p Proof, entry *logEntryBody, entryErr error) Finding {
	if entryErr != nil {
		return underivable(FindingArtifact,
			"there is no log entry in this response to check: "+entryErr.Error())
	}
	digest := sha256.Sum256([]byte(p.CommitSHA))
	want := hex.EncodeToString(digest[:])
	if entry.algorithm != "sha256" || entry.artifact != want {
		return contradicts(FindingArtifact, fmt.Sprintf(
			"the entry's artifact is %s:%s; sha256 of this commit's SHA is sha256:%s. "+
				"The entry is not about this commit.",
			entry.algorithm, entry.artifact, want))
	}
	return agrees(FindingArtifact,
		"the entry's artifact is sha256:"+want+", which is sha256 of "+p.CommitSHA)
}

func rederiveLogIndex(p Proof, entry *logEntryBody, entryErr error) Finding {
	if entryErr != nil {
		return underivable(FindingLogIndex,
			"there is no log entry in this response to read an index from: "+entryErr.Error())
	}
	if entry.logIndex != p.Entry.LogIndex {
		return contradicts(FindingLogIndex, fmt.Sprintf(
			"the response reports log index %d; the entry it served carries %d",
			p.Entry.LogIndex, entry.logIndex))
	}
	return agrees(FindingLogIndex,
		"the entry carries log index "+strconv.FormatInt(entry.logIndex, 10))
}

// rederiveIdentityCheck is the one check of the three that is fully derivable
// offline: the trailer against the certificate's URI SAN, compared with
// internal/verify's own DiffIdentity.
//
// It convicts in one direction only, and deliberately. A response claiming
// VERIFIED over material that says the two identities differ is a lie, and
// this catches it. A response claiming FAILED where the identities match may
// be resting on the redundant Agent-Run/Agent-Task rule, which internal/verify
// keeps unexported and this re-derivation therefore cannot settle — so that
// case is underivable rather than a conviction. A checker that guessed there
// would produce false accusations, and a false accusation from a proof surface
// is worse than a missing one.
func rederiveIdentityCheck(p Proof, object []byte, entry *logEntryBody, entryErr error) Finding {
	var reported *verify.Check
	for i := range p.Checks {
		if p.Checks[i].Name == verify.CheckTrailerIdentity {
			reported = &p.Checks[i]
		}
	}
	if reported == nil {
		return underivable(FindingIdentityCheck,
			"the response reports no "+verify.CheckTrailerIdentity+" check")
	}
	if len(object) == 0 {
		return underivable(FindingIdentityCheck, "the response carries no commit object")
	}
	if entryErr != nil {
		return underivable(FindingIdentityCheck,
			"there is no logged certificate to compare the trailer against: "+entryErr.Error())
	}
	logged, err := parseCertificatePEM(entry.certificatePEM)
	if err != nil {
		return underivable(FindingIdentityCheck, "the entry's certificate does not parse: "+err.Error())
	}
	claim, err := verify.ReadClaim(commitMessage(object))
	if err != nil {
		return underivable(FindingIdentityCheck, "the object's trailers do not resolve: "+err.Error())
	}
	san := uriSAN(logged)
	diff := verify.DiffIdentity(claim.Identity, san)

	switch {
	case reported.Result == verify.Verified && claim.Identity == "":
		return contradicts(FindingIdentityCheck,
			"the response reports this check verified, and the commit object carries "+
				"no Agent-Identity trailer at all: there is no claim for the "+
				"certificate to match")
	case reported.Result == verify.Verified && diff != "":
		return contradicts(FindingIdentityCheck,
			"the response reports this check verified, and the material says otherwise — "+diff)
	case reported.Result == verify.Verified:
		return agrees(FindingIdentityCheck,
			"the trailer and the certificate's URI SAN are both "+san)
	case reported.Result == verify.Failed && diff != "":
		return agrees(FindingIdentityCheck,
			"the response reports this check failed, and the material agrees — "+diff)
	case reported.Result == verify.Failed:
		return underivable(FindingIdentityCheck,
			"the response reports this check failed while the Agent-Identity trailer "+
				"and the certificate's URI SAN are identical. That can be honest — the "+
				"redundant Agent-Run and Agent-Task trailers are also compared — but "+
				"internal/verify does not expose that rule, so this re-derivation "+
				"cannot settle it. Run `innsegl verify` to.")
	default:
		return underivable(FindingIdentityCheck,
			"the response reports this check as "+string(reported.Result))
	}
}

// rederiveRollup reapplies FD §4.1's rule to the checks the response reported:
// "Any single check failing makes the rollup failed. Any check erroring (not
// failing) makes it verification unavailable, never verified."
//
// This is the cheapest tamper to catch and the most valuable, because it is
// the one a server would reach for first: leave the checks honest, change the
// badge.
func rederiveRollup(p Proof) Finding {
	if len(p.Checks) == 0 {
		return underivable(FindingRollup,
			"the response reports no checks, so there is no rollup to re-derive. A "+
				"commit that makes no attribution claim is reported as "+
				string(verify.VerdictUnattributed)+" with no checks, which is a state "+
				"about the commit rather than a verification result.")
	}
	want := verify.VerdictVerified
	for _, c := range p.Checks {
		if c.Result == verify.Failed {
			want = verify.VerdictFailed
			break
		}
		if c.Result == verify.Unavailable {
			want = verify.VerdictUnavailable
		}
	}
	if string(want) != p.Verdict {
		var spelled []string
		for _, c := range p.Checks {
			spelled = append(spelled, fmt.Sprintf("%s=%s", c.Name, c.Result))
		}
		return contradicts(FindingRollup, fmt.Sprintf(
			"the response reports the verdict %q; FD §4.1's rule over the checks it "+
				"reported (%s) gives %q",
			p.Verdict, strings.Join(spelled, ", "), want))
	}
	return agrees(FindingRollup,
		"FD §4.1's rule over the reported checks gives "+p.Verdict)
}

// ---------------------------------------------------------------------------
// Reading the material. Field reads, no decisions.
// ---------------------------------------------------------------------------

// logEntryBody is the part of a Rekor entry this package reads, flattened.
type logEntryBody struct {
	logIndex       int64
	algorithm      string
	artifact       string
	certificatePEM []byte
}

// entryBody pulls the fields out of a served log entry.
//
// The served document is Rekor's `{"<uuid>": {...}}` map. uuid names which
// entry to read when the response says; with an empty uuid the map must hold
// exactly one, because picking one of several would be choosing which entry to
// believe.
func entryBody(raw json.RawMessage, uuid string) (*logEntryBody, error) {
	if len(raw) == 0 {
		return nil, errors.New("the response carries no log entry")
	}
	var entries map[string]struct {
		Body     string `json:"body"`
		LogIndex int64  `json:"logIndex"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("the served log entry is not a Rekor entry map: %w", err)
	}
	key := uuid
	if key == "" {
		if len(entries) != 1 {
			return nil, fmt.Errorf("the served document holds %d entries and the "+
				"response names none", len(entries))
		}
		for k := range entries {
			key = k
		}
	}
	entry, ok := entries[key]
	if !ok {
		return nil, fmt.Errorf("the served document holds no entry %s", key)
	}
	body, err := base64Decode(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("the entry body is not base64: %w", err)
	}
	var decoded struct {
		Kind string `json:"kind"`
		Spec struct {
			Data struct {
				Hash struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"`
				} `json:"hash"`
			} `json:"data"`
			Signature struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("the entry body is not JSON: %w", err)
	}
	certPEM, err := base64Decode(decoded.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, fmt.Errorf("the entry's public key is not base64: %w", err)
	}
	return &logEntryBody{
		logIndex:       entry.LogIndex,
		algorithm:      decoded.Spec.Data.Hash.Algorithm,
		artifact:       decoded.Spec.Data.Hash.Value,
		certificatePEM: certPEM,
	}, nil
}

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func parseCertificatePEM(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func uriSAN(cert *x509.Certificate) string {
	if len(cert.URIs) == 0 {
		return ""
	}
	return cert.URIs[0].String()
}

// commitMessage is everything after the commit object's header block, which
// ends at the first empty line. That is git's own rule about its own object
// format, and it is the only thing this file interprets about the bytes.
func commitMessage(object []byte) string {
	if i := bytes.Index(object, []byte("\n\n")); i >= 0 {
		return string(object[i+2:])
	}
	return string(object)
}

// gitObjectName recomputes a commit's object name from its bytes:
// sha1("commit " + length + NUL + content), or SHA-256 in a repository using
// that object format, chosen by the width of the name being checked against.
//
// This is the one piece of arithmetic that makes the rest of the material
// evidence rather than assertion, and it is deliberately something a reader
// can redo with `git hash-object -t commit` or four lines of any language.
func gitObjectName(object []byte, like string) string {
	header := []byte("commit " + strconv.Itoa(len(object)) + "\x00")
	if len(like) == sha256.Size*2 {
		sum := sha256.Sum256(append(header, object...))
		return hex.EncodeToString(sum[:])
	}
	sum := sha1.Sum(append(header, object...)) //nolint:gosec // see the import comment
	return hex.EncodeToString(sum[:])
}
