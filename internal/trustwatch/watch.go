// SPDX-License-Identifier: Apache-2.0

// Package trustwatch is the core's daily look at its own trust roots
// (ADR-0073).
//
// One pass does three things:
//
//  1. RECORD. It reads the material the deployment uses now (the Fulcio root,
//     the log key, the SPIRE upstream CA, the gateway CA) and appends anything
//     new to the trust history. The first pass on an existing deployment is
//     its seed: no step for the operator.
//  2. CANARY. It verifies a pinned set of sentinel commits, at least one per
//     trust era, against that history, and alerts on any whose verdict is not
//     the one pinned for it. On 2026-09-16 a rotation made every older commit
//     unverifiable and nothing noticed for three weeks; a sentinel from the
//     old era would have failed the same day.
//  3. EXPIRY. It warns a year and 90 days before any CA in use expires.
//
// An alert is a line for the operator's log. The ledger's only alert type for
// this kind of thing, ledger_drift_detected, needs a subject event on the
// chain, and a sentinel from an era the ledger also lost has none. The same
// rule the telemetry witness follows applies: no honest subject, no append.
package trustwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
	"innsegl.dev/innsegl/internal/verify"
)

// SentinelsFileName is the operator's sentinel list, beside the history. It
// is optional: the pass selects one sentinel per era on its own.
const SentinelsFileName = "trust-sentinels.json"

// AutoSentinelsFileName is the sentinels the pass selected itself, one per
// era, append-only.
const AutoSentinelsFileName = "trust-sentinels-auto.json"

// StatusFileName is the last pass's problems, for /_core/status and the
// query API's health response to show.
const StatusFileName = "trust-status.json"

// DefaultInterval is how often a pass runs: daily.
const DefaultInterval = 24 * time.Hour

// maxCandidates bounds how many commits one pass verifies while looking for
// sentinels. Each is a live verification against Fulcio and Rekor.
const maxCandidates = 20

// Source reads one kind of material the deployment uses now. It may return
// several PEM documents (a published chain); each is recorded.
type Source func(context.Context) ([][]byte, error)

// Outcome is one verification as the watch needs it: the verdict, and the key
// id of the history root the certificate chained to, when it did.
type Outcome struct {
	Verdict   verify.Verdict
	RootKeyID string
}

// VerifyFunc verifies one commit against a trust history. The production one
// is internal/verify's, given the history.
type VerifyFunc func(ctx context.Context, h *trusthistory.History, repoDir, sha string) (Outcome, error)

// Candidate is a recent commit the pass may select as an era's sentinel.
type Candidate struct {
	Repo   string
	Commit string
}

// Config is one watch.
type Config struct {
	// HistoryFile is the trust history. Required.
	HistoryFile string
	// SentinelsFile is the operator's sentinel list. Optional.
	SentinelsFile string
	// AutoSentinelsFile is where selected sentinels are kept. Empty turns
	// selection off.
	AutoSentinelsFile string
	// LostRootsFile is the operator's seed of roots lost before the history
	// existed (trusthistory.LostRootsFileName). Optional; imported into the
	// history on every pass, which changes nothing after the first.
	LostRootsFile string
	// StatusFile is where the pass writes its problems. Empty writes none.
	StatusFile string
	// Sources read the material in use, by kind. Recorded in the order of
	// recordOrder, so a seed records the Fulcio root before the log key.
	Sources map[trusthistory.Kind]Source
	// Candidates lists recent commits, newest first, to select sentinels
	// from. Nil turns selection off.
	Candidates func(context.Context) ([]Candidate, error)
	// RepoDir finds a repository in the core's mirror.
	RepoDir func(repo string) (string, error)
	Verify  VerifyFunc
	// Interval between passes; zero is DefaultInterval.
	Interval time.Duration
	Now      func() time.Time
}

// recordOrder is the order sources are recorded in. The Fulcio root goes
// first: a seeded log key takes the root's first use as its own.
var recordOrder = []trusthistory.Kind{
	trusthistory.KindFulcioRoot,
	trusthistory.KindTransparencyLog,
	trusthistory.KindSPIREUpstreamCA,
	trusthistory.KindGatewayCA,
}

// Watch runs passes and remembers when the last one ran.
type Watch struct {
	cfg  Config
	last time.Time
}

// New builds a watch.
func New(cfg Config) *Watch {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Watch{cfg: cfg}
}

// Due reports whether a pass should run now: on the first call, then once
// per interval.
func (w *Watch) Due() bool {
	if w == nil {
		return false
	}
	return w.last.IsZero() || !w.cfg.Now().Before(w.last.Add(w.cfg.Interval))
}

// SentinelResult is one sentinel and what it verified as.
type SentinelResult struct {
	Sentinel
	Got    verify.Verdict `json:"got,omitempty"`
	OK     bool           `json:"ok"`
	Detail string         `json:"detail,omitempty"`
}

// Result is one pass.
type Result struct {
	Recorded     []trusthistory.Entry
	SourceErrors []string
	// Err is a history that could not be read or written. Nothing was
	// written over it.
	Err          error
	SentinelsErr []string
	Sentinels    []SentinelResult
	// Selected are the sentinels this pass chose for eras that had none.
	Selected []Sentinel
	// Info is what an operator may read and need not act on: an era with no
	// sentinel yet, and why none was found.
	Info      []string
	Expiries  []trusthistory.Expiry
	StatusErr error
}

// Pass runs one pass.
func (w *Watch) Pass(ctx context.Context) (res Result) {
	now := w.cfg.Now().UTC()
	w.last = now
	// The status is written however the pass ends, and its own failure is
	// part of the result.
	defer func() { w.writeStatus(now, &res) }()

	h, err := w.record(ctx, now, &res)
	if err != nil {
		res.Err = err
		return res
	}
	res.Expiries = trusthistory.Expiries(h, now)

	configured := w.loadSentinels(w.cfg.SentinelsFile, &res)
	auto := w.loadSentinels(w.cfg.AutoSentinelsFile, &res)
	covered := map[string]bool{}
	for _, s := range auto {
		covered[s.Era] = true
	}
	for _, s := range append(configured, auto...) {
		r, root := w.check(ctx, h, s)
		if r.OK && root != "" {
			covered[root] = true
		}
		res.Sentinels = append(res.Sentinels, r)
	}
	w.selectSentinels(ctx, h, covered, auto, &res)
	return res
}

// loadSentinels reads one sentinel list. Absent is an empty list; a damaged
// one is reported and never written over.
func (w *Watch) loadSentinels(path string, res *Result) []Sentinel {
	if path == "" {
		return nil
	}
	s, err := LoadSentinels(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		res.SentinelsErr = append(res.SentinelsErr, err.Error())
		return nil
	}
	return s.Sentinels
}

// selectSentinels picks a sentinel for each era that has none: the first recent
// commit that verifies under that era's root.
func (w *Watch) selectSentinels(ctx context.Context, h *trusthistory.History, covered map[string]bool,
	auto []Sentinel, res *Result) {

	var open []trusthistory.Entry
	for _, e := range h.OfKind(trusthistory.KindFulcioRoot) {
		if !covered[e.KeyID] && e.RevokedAt == nil {
			open = append(open, e)
		}
	}
	if len(open) == 0 {
		return
	}
	why := ""
	if w.cfg.Candidates != nil && w.cfg.AutoSentinelsFile != "" && len(res.SentinelsErr) == 0 {
		why = w.selectFrom(ctx, h, covered, auto, res)
	}
	for _, e := range open {
		if covered[e.KeyID] {
			continue
		}
		line := fmt.Sprintf("no sentinel yet for era %s (first used %s)", e.KeyID,
			e.FirstUsed.Format(time.DateOnly))
		if why != "" {
			line += ": " + why
		}
		res.Info = append(res.Info, line)
	}
}

func (w *Watch) selectFrom(ctx context.Context, h *trusthistory.History, covered map[string]bool,
	auto []Sentinel, res *Result) string {

	candidates, err := w.cfg.Candidates(ctx)
	if err != nil {
		return "recent commits could not be listed: " + err.Error()
	}
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}
	for _, c := range candidates {
		dir, err := w.cfg.RepoDir(c.Repo)
		if err != nil {
			continue
		}
		out, err := w.cfg.Verify(ctx, h, dir, c.Commit)
		if err != nil || out.Verdict != verify.VerdictVerified || out.RootKeyID == "" || covered[out.RootKeyID] {
			continue
		}
		s := Sentinel{Era: out.RootKeyID, Repo: c.Repo, Commit: c.Commit, Expect: verify.VerdictVerified}
		auto = append(auto, s)
		if err := saveSentinels(w.cfg.AutoSentinelsFile, auto); err != nil {
			return "the selected sentinel could not be kept: " + err.Error()
		}
		covered[out.RootKeyID] = true
		res.Selected = append(res.Selected, s)
	}
	return ""
}

// saveSentinels writes a sentinel list beside the history, atomically.
func saveSentinels(path string, list []Sentinel) error {
	out, err := json.MarshalIndent(Sentinels{Version: 1, Sentinels: list}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, out)
}

func writeAtomic(path string, out []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil { //nolint:gosec // G306: public material, read by the services that report it
		return err
	}
	return os.Rename(tmp, path)
}

// record reads the history, appends what is in use now and any lost roots
// the operator seeded, and saves it if anything was added. A history that
// cannot be read is never written over.
func (w *Watch) record(ctx context.Context, now time.Time, res *Result) (*trusthistory.History, error) {
	h, err := trusthistory.Load(w.cfg.HistoryFile)
	if errors.Is(err, os.ErrNotExist) {
		h = trusthistory.New()
	} else if err != nil {
		return nil, fmt.Errorf("the trust history could not be read, and is left as it is: %w", err)
	}
	before := len(h.Entries)
	for _, kind := range recordOrder {
		src, ok := w.cfg.Sources[kind]
		if !ok {
			continue
		}
		docs, err := src(ctx)
		if err != nil {
			res.SourceErrors = append(res.SourceErrors, fmt.Sprintf("%s: %v", kind, err))
			continue
		}
		for _, doc := range docs {
			if _, err := h.Record(kind, doc, now); err != nil {
				res.SourceErrors = append(res.SourceErrors, fmt.Sprintf("%s: %v", kind, err))
			}
		}
	}
	w.importLost(h, res)
	if len(h.Entries) == before {
		return h, nil
	}
	if err := trusthistory.Save(w.cfg.HistoryFile, h); err != nil {
		return nil, fmt.Errorf("the trust history could not be written: %w", err)
	}
	res.Recorded = append(res.Recorded, h.Entries[before:]...)
	return h, nil
}

// importLost records the operator's lost-root seed. Absent is a fresh
// deployment's state and says nothing.
func (w *Watch) importLost(h *trusthistory.History, res *Result) {
	if w.cfg.LostRootsFile == "" {
		return
	}
	seed, err := trusthistory.LoadLostRoots(w.cfg.LostRootsFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		res.SourceErrors = append(res.SourceErrors, "lost roots: "+err.Error())
		return
	}
	for _, s := range seed {
		if _, err := h.RecordLost(s.KeyID, s.LostAt, s.Reason); err != nil {
			res.SourceErrors = append(res.SourceErrors, "lost roots: "+err.Error())
		}
	}
}

func (w *Watch) check(ctx context.Context, h *trusthistory.History, s Sentinel) (SentinelResult, string) {
	r := SentinelResult{Sentinel: s}
	dir, err := w.cfg.RepoDir(s.Repo)
	if err != nil {
		r.Detail = "the core's mirror does not hold it: " + err.Error()
		return r, ""
	}
	out, err := w.cfg.Verify(ctx, h, dir, s.Commit)
	if err != nil {
		r.Detail = "it could not be verified: " + err.Error()
		return r, ""
	}
	r.Got = out.Verdict
	r.OK = out.Verdict == s.Expect
	return r, out.RootKeyID
}

// Problems are the lines an operator must act on, apart from expiry: every
// sentinel that is not what it was pinned as, and anything that kept the pass
// from looking. These are what /_core/status and the dashboard show.
func (r Result) Problems() []string {
	var out []string
	if r.Err != nil {
		out = append(out, "trust history: "+r.Err.Error())
	}
	for _, e := range r.SourceErrors {
		out = append(out, "trust material in use could not be recorded: "+e)
	}
	for _, e := range r.SentinelsErr {
		out = append(out, "a sentinel list could not be read: "+e)
	}
	for _, s := range r.Sentinels {
		if s.OK {
			continue
		}
		what := s.Detail
		if what == "" {
			what = fmt.Sprintf("it verified as %s", s.Got)
		}
		out = append(out, fmt.Sprintf("sentinel %s in %s (era %q) should verify as %s: %s",
			s.Commit, s.Repo, s.Era, s.Expect, what))
	}
	return out
}

// Alerts are the problems, every CA near expiry, and a status file that could
// not be written. An empty list is a healthy deployment.
func (r Result) Alerts() []string {
	out := r.Problems()
	for _, e := range r.Expiries {
		if e.Warning != trusthistory.WarningNone {
			out = append(out, fmt.Sprintf("the %s %s on %s", e.Name, e.Warning,
				e.NotAfter.Format(time.DateOnly)))
		}
	}
	if r.StatusErr != nil {
		out = append(out, "the trust status could not be written: "+r.StatusErr.Error())
	}
	return out
}

// Status is the last pass's problems, each with when it was first seen.
type Status struct {
	CheckedAt time.Time `json:"checked_at"`
	Problems  []Problem `json:"problems"`
	Info      []string  `json:"info,omitempty"`
}

// Problem is one problem and the first pass that saw it.
type Problem struct {
	Text  string    `json:"text"`
	Since time.Time `json:"since"`
}

// LoadStatus reads the status file.
func LoadStatus(path string) (Status, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return Status{}, fmt.Errorf("%s: %w", path, err)
	}
	return st, nil
}

// writeStatus writes this pass's problems, keeping the first-seen time of any
// the previous pass already reported. A damaged previous file is replaced.
func (w *Watch) writeStatus(now time.Time, res *Result) {
	if w.cfg.StatusFile == "" {
		return
	}
	since := map[string]time.Time{}
	if prev, err := LoadStatus(w.cfg.StatusFile); err == nil {
		for _, p := range prev.Problems {
			since[p.Text] = p.Since
		}
	}
	st := Status{CheckedAt: now, Problems: []Problem{}, Info: res.Info}
	for _, text := range res.Problems() {
		at, ok := since[text]
		if !ok {
			at = now
		}
		st.Problems = append(st.Problems, Problem{Text: text, Since: at})
	}
	out, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = writeAtomic(w.cfg.StatusFile, out)
	}
	res.StatusErr = err
}

// Sentinel is one pinned commit and the verdict it must keep.
type Sentinel struct {
	Era    string         `json:"era"`
	Repo   string         `json:"repo"`
	Commit string         `json:"commit"`
	Expect verify.Verdict `json:"expect"`
}

// Sentinels is the sentinel file.
type Sentinels struct {
	Version   int        `json:"version"`
	Sentinels []Sentinel `json:"sentinels"`
}

var commitSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// expectable are the verdicts a sentinel may be pinned to. A sentinel pinned
// to fail would make a failure the healthy state.
var expectable = map[verify.Verdict]bool{
	verify.VerdictVerified:        true,
	verify.VerdictContentVerified: true,
	verify.VerdictPreHistory:      true,
}

// LoadSentinels reads and checks the sentinel file, strictly.
func LoadSentinels(path string) (*Sentinels, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Sentinels
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: trailing data", path)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("%s: version %d, this reader knows 1", path, s.Version)
	}
	for i, x := range s.Sentinels {
		switch {
		case x.Repo == "":
			return nil, fmt.Errorf("%s: sentinel %d names no repository", path, i)
		case !commitSHA.MatchString(x.Commit):
			return nil, fmt.Errorf("%s: sentinel %d: %q is not a full commit SHA", path, i, x.Commit)
		case !expectable[x.Expect]:
			return nil, fmt.Errorf("%s: sentinel %d expects %q; a sentinel is pinned to "+
				"verified, content-verified or pre-history", path, i, x.Expect)
		}
	}
	return &s, nil
}
