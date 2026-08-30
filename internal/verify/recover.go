// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// VER-003's "where possible", made precise.
//
// A squash or a rebase produces a NEW commit object. Its SHA is different, so
// the transparency log holds nothing for it and check 2 fails — that is the
// required verdict and it is correct: the signature does not cover the new
// object. The question doc 07 then asks is whether the ORIGINAL attribution is
// still resolvable, "via Rekor + tree hash where possible".
//
// WHERE IT IS POSSIBLE. Git rewrites commits, not trees. A squash keeps the
// tree of the last commit in the squashed range; an amend of a message keeps
// the tree entirely. So if the original commit object is still IN THIS
// REPOSITORY — as it is after any local rewrite, unreferenced but present
// until gc runs — it can be found by its tree hash, and its SHA can then be
// looked up in Rekor exactly as a live commit's would be.
//
// WHERE IT STOPS, and this is the honest half. Rekor's index is keyed on the
// hash of a COMMIT SHA (ADR-0031 decision 6). A tree hash is not one, and
// there is no query that turns a tree into an entry. So the moment the
// original object is gone — a fresh clone of the rewritten branch, a pushed
// force, a `git gc --prune=now` — there is nothing left to ask. The tree hash
// is a way of finding a candidate SHA locally; it is not an index into the
// log. This function reports that outcome as an absence it established, not as
// an answer.
//
// It is also NOT a way to rescue a verdict. The rewritten commit stays FAILED
// whatever is recovered here; what is recovered is history, for a human.

// recover looks for other commits in the repository that carry the same tree
// and are known to the log.
func (v *Verifier) recover(ctx context.Context, repo string, c commit, notes []string) ([]Recovered, []string) {
	shas, err := commitObjects(ctx, v.cfg.GitPath, repo)
	if err != nil {
		return nil, append(notes, fmt.Sprintf(
			"the repository's object database could not be walked, so the original "+
				"attribution was not looked for: %v", err))
	}
	var candidates []string
	for _, sha := range shas {
		if sha == c.SHA {
			continue
		}
		other, oerr := readCommit(ctx, v.cfg.GitPath, repo, sha)
		if oerr != nil {
			continue
		}
		if other.Tree == c.Tree {
			candidates = append(candidates, sha)
		}
	}
	if len(candidates) == 0 {
		return nil, append(notes, "the original attribution could not be recovered: "+
			"no other commit in this repository holds tree "+c.Tree+
			", and Rekor is indexed by the hash of a commit SHA, not by a tree hash, "+
			"so there is no query left to make")
	}

	var out []Recovered
	for _, sha := range candidates {
		rec, ok := v.attributionOf(ctx, sha)
		if !ok {
			continue
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, append(notes, fmt.Sprintf("commit(s) %s in this repository hold the "+
			"same tree, and the transparency log holds no entry for any of them",
			strings.Join(candidates, ", ")))
	}
	return out, append(notes, fmt.Sprintf("the original attribution was recovered from the "+
		"tree hash: %d commit(s) in this repository carry tree %s and are in the "+
		"transparency log", len(out), c.Tree))
}

// attributionOf asks the log what identity signed one commit SHA. It reads the
// certificate out of the log entry rather than out of the repository, because
// the point of the exercise is what a third party recorded.
func (v *Verifier) attributionOf(ctx context.Context, sha string) (Recovered, bool) {
	uuids, err := v.searchLog(ctx, sha256Hex(sha))
	if err != nil || len(uuids) == 0 {
		return Recovered{}, false
	}
	for _, id := range uuids {
		raw, gerr := v.get(ctx, v.rekorEntries+"/"+id)
		if gerr != nil {
			continue
		}
		var entries map[string]logEntry
		if uerr := json.Unmarshal(raw, &entries); uerr != nil {
			continue
		}
		entry, ok := entries[id]
		if !ok {
			continue
		}
		identity, ierr := identityOfEntry(entry)
		if ierr != nil {
			continue
		}
		return Recovered{
			CommitSHA:    sha,
			Identity:     identity,
			LogIndex:     entry.LogIndex,
			IntegratedAt: unixUTC(entry.IntegratedTime),
		}, true
	}
	return Recovered{}, false
}

// identityOfEntry reads the URI SAN out of the certificate a log entry was
// accepted under.
func identityOfEntry(entry logEntry) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return "", err
	}
	var body hashedRekordBody
	if uerr := json.Unmarshal(raw, &body); uerr != nil {
		return "", uerr
	}
	certPEM, err := base64.StdEncoding.DecodeString(body.Spec.Signature.PublicKey.Content)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("the entry's public key is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	san := uriSANOf(cert)
	if san == "" {
		return "", fmt.Errorf("the entry's certificate carries no URI SAN")
	}
	return san, nil
}

// commitObjects lists every commit object in the repository, referenced or
// not — the unreferenced ones are the point, because that is what a rewritten
// original becomes.
func commitObjects(ctx context.Context, gitPath, repo string) ([]string, error) {
	out, err := runGit(ctx, gitPath, repo, "cat-file", "--batch-all-objects",
		"--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		return nil, err
	}
	var shas []string
	for _, line := range strings.Split(out, "\n") {
		name, kind, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || kind != "commit" {
			continue
		}
		shas = append(shas, name)
		if len(shas) == maxTreeScan {
			break
		}
	}
	return shas, nil
}

func unixUTC(sec int64) time.Time { return time.Unix(sec, 0).UTC() }
