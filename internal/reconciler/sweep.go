// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The LOG-SIDE reader (RM-036, #44). rekor.go asks the log one question —
// "what is the entry for this commit?" — because RM-035's join runs from the
// intent. Drift detection has two questions that join cannot express, and both
// are answered here, on the same *RekorLog, through the same transport, so
// there is exactly one Rekor client in this package.
//
//	EntriesFrom   what has the log accepted lately, whoever asked for it?
//	              REC-003's question. It cannot be asked by artifact hash,
//	              because the whole subject is entries no intent named and
//	              therefore no tree hash can reach.
//	EntryByUUID   is the entry this `commit_recorded` names really there, and
//	              does it attest what the record says? REC-004's question, and
//	              the one a compromised MCP cannot make come out its way.
//
// # Why the batch endpoint and not one GET per index
//
// Measured against the shipped rekor-server v1.3.10:
//
//	POST /api/v1/log/entries/retrieve {"logIndexes":[0,1,5]}   -> HTTP 200, a
//	    JSON ARRAY of single-member {uuid: entry} objects. Indexes the log does
//	    not hold are OMITTED, not errors: asking for 0, 1 and 5 of a three-entry
//	    log returns two objects. Eleven indexes -> HTTP 422, "logIndexes in body
//	    should have at most 10 items", so the batch is ten.
//	GET  /api/v1/log/entries?logIndex=0 on an empty log -> HTTP 404.
//
// The 404 is why the single-index GET is not used: `do` treats every unexpected
// status as an OUTAGE, which is the right default for a reader whose caller may
// write a permanent `commit_intent_expired` on an absence, and teaching it that
// one 404 on one path is really an answer would put that distinction in the
// transport. The retrieve endpoint answers an absence with an empty array,
// which needs no exception.
//
// # A uuid the log will not even be asked about
//
//	POST .../retrieve {"entryUUIDs":["not-hex"]} -> HTTP 422, "should match
//	    '^([0-9a-fA-F]{64}|[0-9a-fA-F]{80})$'"
//
// A `commit_recorded` written by a compromised MCP can name anything at all in
// `rekor_entry_uuid` — the schema bounds it as a reference and no more. Sending
// such a value to Rekor would come back as an HTTP 422 that this reader would
// have to call an outage, and the fabrication would go unreported for as long
// as the attacker kept the value malformed. So the shape is checked HERE, and a
// value that cannot name any entry is answered with ErrNoEntry: the log holds
// no such entry, which is true, and is a finding rather than a failure.

const (
	rekorLogInfoPath  = "/api/v1/log"
	rekorRetrievePath = "/api/v1/log/entries/retrieve"

	// rekorRetrieveBatch is Rekor's own maxItems on both `logIndexes` and
	// `entryUUIDs`, measured above. Sending eleven is an HTTP 422.
	rekorRetrieveBatch = 10

	// maxSweepEntries bounds how many entries one EntriesFrom call will ask
	// for, whatever it is passed. The sweep window is a policy in drift.go;
	// this is the reader refusing to be told to make ten thousand requests.
	maxSweepEntries = 4096
)

var _ LogSweeper = (*RekorLog)(nil)

// TreeSize is how many entries the log holds — the top of the sweep range.
func (l *RekorLog) TreeSize(ctx context.Context) (int64, error) {
	raw, err := l.get(ctx, rekorLogInfoPath)
	if err != nil {
		return 0, err
	}
	var info struct {
		TreeSize int64 `json:"treeSize"`
	}
	if jerr := json.Unmarshal(raw, &info); jerr != nil {
		return 0, fmt.Errorf("reconciler: the rekor log info answered %s: %w", truncate(raw), jerr)
	}
	if info.TreeSize < 0 {
		return 0, fmt.Errorf("reconciler: the rekor log reports a tree size of %d", info.TreeSize)
	}
	return info.TreeSize, nil
}

// EntriesFrom returns the entries at log indexes [from, from+count), in index
// order, as far as the log holds them.
//
// Every failure is an outage: an entry the log declines to show is not the
// same as an entry that is not there, and the caller may not turn one into the
// other. An index the log does not hold is simply absent from the result,
// which is the log answering.
func (l *RekorLog) EntriesFrom(ctx context.Context, from, count int64) ([]SweptEntry, error) {
	switch {
	case from < 0:
		return nil, fmt.Errorf("reconciler: sweeping from log index %d; indexes are 0-based", from)
	case count <= 0:
		return nil, fmt.Errorf("reconciler: sweeping %d entries; the range must be positive", count)
	case count > maxSweepEntries:
		return nil, fmt.Errorf("reconciler: sweeping %d entries at once, over the %d bound",
			count, maxSweepEntries)
	}

	var out []SweptEntry
	for start := from; start < from+count; start += rekorRetrieveBatch {
		indexes := make([]int64, 0, rekorRetrieveBatch)
		for i := start; i < start+rekorRetrieveBatch && i < from+count; i++ {
			indexes = append(indexes, i)
		}
		// Written rather than marshalled, for rekor.go's reason: these are
		// int64s, so there is nothing in them to escape, and a marshal error
		// would be an error branch no test could ever reach.
		var body strings.Builder
		body.WriteString(`{"logIndexes":[`)
		for i, index := range indexes {
			if i > 0 {
				body.WriteByte(',')
			}
			body.WriteString(strconv.FormatInt(index, 10))
		}
		body.WriteString(`]}`)

		raw, perr := l.post(ctx, rekorRetrievePath, []byte(body.String()))
		if perr != nil {
			return nil, perr
		}
		batch, derr := decodeSweptEntries(raw)
		if derr != nil {
			return nil, derr
		}
		out = append(out, batch...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LogIndex < out[j].LogIndex })
	return out, nil
}

// EntryByUUID returns the entry the log holds under uuid, or ErrNoEntry.
//
// ErrNoEntry is the log ANSWERING — including for a uuid no Rekor entry could
// ever carry, which the log is not asked about at all. Every other error means
// the log could not be asked, and REC-004's caller must leave the record
// unjudged rather than record a permanent accusation on a timeout.
func (l *RekorLog) EntryByUUID(ctx context.Context, uuid string) (SweptEntry, error) {
	if !IsRekorEntryUUID(uuid) {
		return SweptEntry{}, fmt.Errorf(
			"%w: %q is not a rekor entry uuid (64 or 80 hex characters), so no entry can carry it",
			ErrNoEntry, uuid)
	}
	// Written rather than marshalled: the guard above has already established
	// that uuid is nothing but hex, so there is nothing in it to escape.
	raw, err := l.post(ctx, rekorRetrievePath, []byte(`{"entryUUIDs":["`+uuid+`"]}`))
	if err != nil {
		return SweptEntry{}, err
	}
	entries, err := decodeSweptEntries(raw)
	if err != nil {
		return SweptEntry{}, err
	}
	for _, entry := range entries {
		if entry.UUID == uuid {
			return entry, nil
		}
	}
	return SweptEntry{}, fmt.Errorf("%w: the log holds no entry %s", ErrNoEntry, uuid)
}

// IsRekorEntryUUID reports whether s can name a Rekor entry: 64 hex characters,
// or 80 when the log's tree id is prefixed. It is the pattern rekor-server
// itself enforces, quoted in the header comment.
func IsRekorEntryUUID(s string) bool {
	if len(s) != 64 && len(s) != 80 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// retrievedEntry is one element of a retrieve response, keyed by uuid.
type retrievedEntry struct {
	Body           string `json:"body"`
	LogIndex       int64  `json:"logIndex"`
	IntegratedTime int64  `json:"integratedTime"`
}

// decodeSweptEntries turns a retrieve response into entries.
//
// An entry whose body cannot be read as a certificate-bearing hashedrekord is
// KEPT, with an empty CertificateIdentity or ArtifactHash, rather than dropped.
// The two callers want opposite things from it — the sweep skips it, because a
// segment anchor (ADR-0009, a raw P-256 key and no certificate) attributes
// nothing to anybody; REC-004 reports it, because a `commit_recorded` naming an
// entry that attributes nothing is a claim with no proof. Deciding here would
// take that choice away from both.
func decodeSweptEntries(raw []byte) ([]SweptEntry, error) {
	var response []map[string]retrievedEntry
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("reconciler: the rekor retrieve endpoint answered %s: %w",
			truncate(raw), err)
	}
	var out []SweptEntry
	for _, object := range response {
		for uuid, got := range object {
			identity, artifact := attributionAndArtifact(got.Body)
			out = append(out, SweptEntry{
				UUID:                uuid,
				LogIndex:            got.LogIndex,
				IntegratedAt:        time.Unix(got.IntegratedTime, 0).UTC(),
				CertificateIdentity: identity,
				ArtifactHash:        artifact,
			})
		}
	}
	return out, nil
}

// attributionAndArtifact reads what an entry attributes and to what.
//
// It is rekor.go's `attributionOf` asked the other way round. That one is given
// the artifact hash and answers "is this the entry for it?"; this one is given
// nothing and answers "what is this entry, and whose?". They read the same five
// members of the same body and neither can be expressed as the other: a sweep
// has no hash to pass in, and a lookup that returned the hash would have to be
// told to ignore it. Both are here rather than one, and both are tested.
//
// Either value comes back empty when it could not be read, and empty is
// unambiguous: doc 02 §1 admits no empty string as a value anywhere.
func attributionAndArtifact(bodyBase64 string) (identity, artifact string) {
	body, err := base64.StdEncoding.DecodeString(bodyBase64)
	if err != nil {
		return "", ""
	}
	var got rekorBody
	if jerr := json.Unmarshal(body, &got); jerr != nil {
		return "", ""
	}
	if got.Kind != rekorHashedRekord {
		return "", ""
	}
	if got.Spec.Data.Hash.Algorithm == rekorSHA256 {
		artifact = got.Spec.Data.Hash.Value
	}
	pemBytes, err := base64.StdEncoding.DecodeString(got.Spec.Signature.PublicKey.Content)
	if err != nil {
		return "", artifact
	}
	return uriSANOf(pemBytes), artifact
}

// uriSANOf returns the first URI SAN of a PEM certificate, or "".
//
// gitsign's Fulcio certificates carry the SPIFFE ID there and it is the only
// member of a certificate this package reads. A block that is not a
// certificate — a segment anchor's raw `PUBLIC KEY` (ADR-0009), an entry from
// some other producer — attributes nothing and comes back empty.
func uriSANOf(pemBytes []byte) string {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.URIs) == 0 {
		return ""
	}
	return cert.URIs[0].String()
}
